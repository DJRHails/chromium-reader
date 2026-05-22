"""Chromium localStorage reader, sitting on top of :mod:`chromium_reader.leveldb`.

Chromium serialises localStorage into a single LevelDB directory per profile,
at ``<profile>/Local Storage/leveldb``. Each record has one of two shapes:

- ``META:<storage_key>``                — small protobuf with timestamp + size
- ``_<storage_key>\\x00<script_key>``   — the actual stored value

The value bytes carry a 1-byte type prefix:

- ``0x00`` — UTF-16 little-endian
- ``0x01`` — Latin-1 (ISO-8859-1)

Reassembling a long string written across multiple LevelDB entries is handled
by LevelDB itself; the per-value framing artefacts that show up in raw byte
scans (e.g. ``\\r\\x0f\\xf0O``) disappear once the leveldb block protocol is
respected.

Derived in spirit from
``ccl_chromium_reader/ccl_chromium_localstorage.py`` by CCL Forensics
(MIT, Copyright 2020-2024). Reimplemented from scratch for Python 3.11+ with
dataclasses, ``pathlib``, type hints and ``logging``.

References:
- https://source.chromium.org/chromium/chromium/src/+/main:components/services/storage/dom_storage/local_storage_impl.cc
"""

from __future__ import annotations

import bisect
import dataclasses
import datetime as dt
import io
import logging
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from chromium_reader.common import KeySearch, matches
from chromium_reader.leveldb import KeyState, RawLevelDb, Record, _read_le_varint

logger = logging.getLogger(__name__)

_META_PREFIX = b"META:"
_RECORD_PREFIX = b"_"
_LATIN1 = "iso-8859-1"
_CHROME_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)


def chrome_timestamp(microseconds: int) -> dt.datetime:
    """Convert a Chrome/Windows epoch microsecond timestamp to a tz-aware datetime."""
    return _CHROME_EPOCH + dt.timedelta(microseconds=microseconds)


def decode_value(raw: bytes) -> str:
    """Decode a Chromium type-prefixed string.

    Args:
        raw: leveldb value bytes, with a leading type byte.

    Returns:
        Decoded Python string.

    Raises:
        ValueError: if the type prefix is not 0 (UTF-16 LE) or 1 (Latin-1).
    """
    if not raw:
        raise ValueError("Empty value")
    prefix = raw[0]
    if prefix == 0:
        return raw[1:].decode("utf-16-le")
    if prefix == 1:
        return raw[1:].decode(_LATIN1)
    raise ValueError(f"Unexpected string-type prefix: {prefix:#x}")


@dataclasses.dataclass(frozen=True, slots=True)
class StorageMetadata:
    """Per-origin metadata: timestamp and total bytes written."""

    storage_key: str
    timestamp: dt.datetime
    size_in_bytes: int
    leveldb_seq_number: int

    @classmethod
    def from_protobuf(cls, storage_key: str, data: bytes, seq: int) -> Self:
        """Parse the 2-field protobuf produced by Chromium's localStorage."""
        with io.BytesIO(data) as buf:
            ts_tag = _read_le_varint(buf)
            if ts_tag is None or (ts_tag & 0x07) != 0 or (ts_tag >> 3) != 1:
                raise ValueError(f"Bad timestamp tag for {storage_key!r}")
            ts_value = _read_le_varint(buf)
            if ts_value is None:
                raise ValueError(f"Truncated timestamp for {storage_key!r}")

            size_tag = _read_le_varint(buf)
            if size_tag is None or (size_tag & 0x07) != 0 or (size_tag >> 3) != 2:
                raise ValueError(f"Bad size tag for {storage_key!r}")
            size = _read_le_varint(buf)
            if size is None:
                raise ValueError(f"Truncated size for {storage_key!r}")

        return cls(storage_key, chrome_timestamp(ts_value), size, seq)


@dataclasses.dataclass(frozen=True, slots=True)
class LocalStorageRecord:
    """A single ``window.localStorage`` entry, possibly historical."""

    storage_key: str
    script_key: str
    value: str | None
    leveldb_seq_number: int
    is_live: bool

    @property
    def host(self) -> str:
        """Alias for storage_key — the origin/host owning the record."""
        return self.storage_key


@dataclasses.dataclass(frozen=True, slots=True)
class LocalStorageBatch:
    """A contiguous run of (META + records) attributable to one write batch."""

    storage_key: str
    timestamp: dt.datetime
    start: int
    end: int


class LocalStorageReader:
    """Reader for a Chromium localStorage leveldb directory.

    Use as a context manager:

        >>> from chromium_reader.localstorage import LocalStorageReader
        >>> with LocalStorageReader(path) as reader:
        ...     for record in reader.records():
        ...         ...
    """

    def __init__(self, in_dir: Path | str) -> None:
        path = Path(in_dir)
        if not path.is_dir():
            raise NotADirectoryError(path)
        self._path = path
        self._ldb = RawLevelDb(path)

        self._meta_by_key: dict[str, dict[int, StorageMetadata]] = {}
        self._rec_by_key: dict[str, dict[str, dict[int, LocalStorageRecord]]] = {}
        self._flat: list[StorageMetadata | LocalStorageRecord] = []

        for raw in self._ldb.iterate_records_raw():
            self._ingest(raw)

        self._flat.sort(key=lambda x: x.leveldb_seq_number)
        self._all_keys: frozenset[str] = frozenset(
            self._meta_by_key.keys() | self._rec_by_key.keys()
        )
        self._batches: dict[int, LocalStorageBatch] = self._build_batches()
        self._batch_starts: tuple[int, ...] = tuple(sorted(self._batches.keys()))

    def _ingest(self, record: Record) -> None:
        key = record.user_key
        if key.startswith(_META_PREFIX) and record.state == KeyState.LIVE:
            self._ingest_meta(record)
        elif key.startswith(_RECORD_PREFIX):
            self._ingest_record(record)

    def _ingest_meta(self, record: Record) -> None:
        storage_key = record.user_key.removeprefix(_META_PREFIX).decode(_LATIN1)
        try:
            meta = StorageMetadata.from_protobuf(storage_key, record.value, record.seq)
        except ValueError:
            logger.debug("Skipping malformed META for %s", storage_key)
            return
        self._meta_by_key.setdefault(storage_key, {})[meta.leveldb_seq_number] = meta
        self._flat.append(meta)

    def _ingest_record(self, record: Record) -> None:
        body = record.user_key.removeprefix(_RECORD_PREFIX)
        if b"\x00" not in body:
            logger.debug("Record key without separator: %r", record.user_key)
            return
        storage_raw, script_raw = body.split(b"\x00", 1)
        storage_key = storage_raw.decode(_LATIN1)
        try:
            script_key = decode_value(script_raw)
        except (ValueError, UnicodeDecodeError):
            logger.debug("Undecodable script key under %s", storage_key)
            return

        is_live = record.state == KeyState.LIVE
        value: str | None = None
        if is_live:
            try:
                value = decode_value(record.value)
            except (ValueError, UnicodeDecodeError):
                logger.debug(
                    "Undecodable value for %s / %s at seq %s",
                    storage_key,
                    script_key,
                    record.seq,
                )
                return

        rec = LocalStorageRecord(
            storage_key=storage_key,
            script_key=script_key,
            value=value,
            leveldb_seq_number=record.seq,
            is_live=is_live,
        )
        bucket = self._rec_by_key.setdefault(storage_key, {}).setdefault(script_key, {})
        bucket[rec.leveldb_seq_number] = rec
        self._flat.append(rec)

    def _build_batches(self) -> dict[int, LocalStorageBatch]:
        batches: dict[int, LocalStorageBatch] = {}
        current: StorageMetadata | None = None
        current_end = 0
        for item in self._flat:
            if isinstance(item, StorageMetadata):
                if current is not None:
                    batches[current.leveldb_seq_number] = LocalStorageBatch(
                        current.storage_key,
                        current.timestamp,
                        current.leveldb_seq_number,
                        current_end,
                    )
                current = item
                current_end = item.leveldb_seq_number
                continue
            if current is None:
                continue
            if (
                item.leveldb_seq_number - current_end != 1
                or item.storage_key != current.storage_key
            ):
                batches[current.leveldb_seq_number] = LocalStorageBatch(
                    current.storage_key, current.timestamp, current.leveldb_seq_number, current_end
                )
                current = None
                current_end = 0
            else:
                current_end = item.leveldb_seq_number
        if current is not None:
            batches[current.leveldb_seq_number] = LocalStorageBatch(
                current.storage_key, current.timestamp, current.leveldb_seq_number, current_end
            )
        return batches

    @property
    def path(self) -> Path:
        return self._path

    @property
    def storage_keys(self) -> frozenset[str]:
        return self._all_keys

    def metadata(self) -> Iterator[StorageMetadata]:
        for per_key in self._meta_by_key.values():
            yield from per_key.values()

    def find_batch(self, seq: int) -> LocalStorageBatch | None:
        """Return the batch (if any) covering the given sequence number."""
        if not self._batch_starts:
            return None
        i = bisect.bisect_left(self._batch_starts, seq) - 1
        if i < 0:
            return None
        batch = self._batches[self._batch_starts[i]]
        if batch.start <= seq <= batch.end:
            return batch
        return None

    def records(
        self,
        *,
        host: KeySearch | None = None,
        script_key: KeySearch | None = None,
        include_deletions: bool = False,
    ) -> Iterator[LocalStorageRecord]:
        """Iterate records, optionally filtered by host and/or script key.

        Args:
            host: storage-key filter (str, regex, collection, or callable).
            script_key: script-key filter (same forms).
            include_deletions: when True, yield records for deleted entries too.
        """
        for storage_key, scripts in self._rec_by_key.items():
            if host is not None and not matches(host, storage_key):
                continue
            for script, seq_map in scripts.items():
                if script_key is not None and not matches(script_key, script):
                    continue
                for rec in seq_map.values():
                    if rec.is_live or include_deletions:
                        yield rec

    def __contains__(self, item: object) -> bool:
        if isinstance(item, str):
            return item in self._all_keys
        if isinstance(item, tuple) and len(item) == 2:
            host, script = item
            return (
                isinstance(host, str)
                and isinstance(script, str)
                and host in self._rec_by_key
                and script in self._rec_by_key[host]
            )
        return False

    def __iter__(self) -> Iterator[str]:
        return iter(self._all_keys)

    def close(self) -> None:
        self._ldb.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = [
    "LocalStorageBatch",
    "LocalStorageReader",
    "LocalStorageRecord",
    "StorageMetadata",
    "chrome_timestamp",
    "decode_value",
]
