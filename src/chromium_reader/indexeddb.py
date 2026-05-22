"""Chromium IndexedDB reader.

Chromium stores IndexedDB databases as a single LevelDB instance per origin at
``<profile>/IndexedDB/<origin>.leveldb/``. Inside that store, keys are
namespaced into:

- *Global metadata* (key prefix ``\\x00\\x00\\x00\\x00``) — schema version,
  next-available-id, the name→id mapping for databases.
- *Database metadata* (key prefix ``\\x00<db_id>\\x00\\x00``) — name/version
  of each database and the next-available object-store id.
- *Object-store metadata* (key prefix ``\\x00<db_id>\\x00\\x32<store_id>``) —
  the object-store name, key path, auto-increment flag, etc.
- *Records* (key prefix ``\\x00<db_id>\\x01<store_id>\\x00<idb_key>``) —
  the actual stored values, Blink-wrapped V8 payloads.

This module yields :class:`IndexedDbRecord` instances with their decoded
Python value, leaving the IDB key as raw bytes (callers that care about
sortable IDB keys typically know the key path used by the store).

Derived in spirit from ``ccl_chromium_reader/ccl_chromium_indexeddb.py``
by CCL Forensics (MIT, Copyright 2020-2024). Reimplemented from scratch
for Python 3.11+ with dataclasses, ``pathlib`` and stdlib-only deps.

References:
- https://source.chromium.org/chromium/chromium/src/+/main:content/browser/indexed_db/indexed_db_backing_store.cc
- https://source.chromium.org/chromium/chromium/src/+/main:content/browser/indexed_db/indexed_db_leveldb_coding.cc
"""

from __future__ import annotations

import dataclasses
import io
import logging
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from chromium_reader._blink_deserializer import BlinkError, deserialize
from chromium_reader._v8_deserializer import V8Error
from chromium_reader.common import KeySearch, matches
from chromium_reader.leveldb import KeyState, RawLevelDb, Record, _read_le_varint

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True, slots=True)
class DatabaseInfo:
    """Per-database metadata recovered from the global section."""

    db_id: int
    name: str
    origin: str


@dataclasses.dataclass(frozen=True, slots=True)
class ObjectStoreInfo:
    """Per-object-store metadata recovered from the database section."""

    db_id: int
    store_id: int
    name: str


@dataclasses.dataclass(frozen=True, slots=True)
class IndexedDbRecord:
    """A single IndexedDB record materialised from a Blink/V8 payload."""

    database_name: str
    object_store_name: str
    raw_key: bytes
    value: Any
    leveldb_seq_number: int
    is_live: bool


class IndexedDbReader:
    """Reader for one Chromium ``IndexedDB/*.leveldb`` directory.

    Use as a context manager:

        >>> from chromium_reader.indexeddb import IndexedDbReader
        >>> with IndexedDbReader(path) as db:
        ...     for record in db.records():
        ...         ...
    """

    def __init__(self, in_dir: Path | str) -> None:
        path = Path(in_dir)
        if not path.is_dir():
            raise NotADirectoryError(path)
        self._path = path
        self._ldb = RawLevelDb(path)

        self._databases: dict[int, DatabaseInfo] = {}
        self._object_stores: dict[tuple[int, int], ObjectStoreInfo] = {}
        self._raw_records: list[_RawIdbRecord] = []

        for raw in self._ldb.iterate_records_raw():
            self._classify(raw)

    def _classify(self, record: Record) -> None:
        key = record.user_key
        if len(key) < 4 or key[0] != 0:
            return
        # The first byte after 0x00 is the database-id length nibble pack;
        # in the global section it is 0x00 0x00. See indexed_db_leveldb_coding.cc.
        if key[1:4] == b"\x00\x00\x00":
            self._classify_global(record)
            return
        # Otherwise: 0x00 <db_id_varint> <section> ...
        try:
            db_id, rest = _read_short_id(key[1:])
        except ValueError:
            return
        if len(rest) < 1:
            return
        section = rest[0]
        body = rest[1:]
        if section == 0x00:
            self._classify_database_meta(db_id, body, record)
        elif section == 0x01:
            self._classify_record(db_id, body, record)

    def _classify_global(self, record: Record) -> None:
        if record.state != KeyState.LIVE:
            return
        # Database name entry: 0x00 0x00 0x00 0xC9 <origin_string> 0x00 <db_name>
        # We parse origin + name + db_id (in value) loosely.
        if len(record.user_key) < 5 or record.user_key[4] != 0xC9:
            return
        body = record.user_key[5:]
        origin, sep, name_part = body.partition(b"\x00")
        if not sep:
            return
        try:
            origin_str = _decode_string_with_length(origin)
            name_str = _decode_string_with_length(name_part)
        except ValueError:
            return
        try:
            db_id = int.from_bytes(record.value, "little", signed=False)
        except ValueError:
            return
        self._databases[db_id] = DatabaseInfo(db_id=db_id, name=name_str, origin=origin_str)

    def _classify_database_meta(self, db_id: int, body: bytes, record: Record) -> None:
        # Object store metadata key: <0x32 = '2'> <store_id_varint> <meta_type>
        if record.state != KeyState.LIVE or not body or body[0] != 0x32:
            return
        try:
            store_id, rest = _read_short_id(body[1:])
        except ValueError:
            return
        if len(rest) != 1 or rest[0] != 0x00:
            # 0x00 = object store name; other meta types are skipped.
            return
        try:
            name = _decode_string_with_length(record.value)
        except ValueError:
            return
        self._object_stores[(db_id, store_id)] = ObjectStoreInfo(
            db_id=db_id, store_id=store_id, name=name
        )

    def _classify_record(self, db_id: int, body: bytes, record: Record) -> None:
        # Record key: <store_id_varint> 0x00 <idb_key_bytes>
        try:
            store_id, rest = _read_short_id(body)
        except ValueError:
            return
        if not rest or rest[0] != 0x00:
            return
        idb_key = rest[1:]
        self._raw_records.append(
            _RawIdbRecord(
                db_id=db_id,
                store_id=store_id,
                idb_key=idb_key,
                value=record.value,
                seq=record.seq,
                is_live=record.state == KeyState.LIVE,
            )
        )

    @property
    def path(self) -> Path:
        return self._path

    @property
    def databases(self) -> tuple[DatabaseInfo, ...]:
        return tuple(self._databases.values())

    def object_stores(self, database_name: str | None = None) -> Iterator[ObjectStoreInfo]:
        for info in self._object_stores.values():
            db = self._databases.get(info.db_id)
            if database_name is not None and (db is None or db.name != database_name):
                continue
            yield info

    def records(
        self,
        *,
        database: KeySearch | None = None,
        object_store: KeySearch | None = None,
        include_deletions: bool = False,
        skip_undecodable: bool = True,
    ) -> Iterator[IndexedDbRecord]:
        """Iterate IndexedDB records, optionally filtered.

        Args:
            database: database-name filter (str, regex, collection, or callable).
            object_store: object-store-name filter (same forms).
            include_deletions: when True, yield records for deleted entries too.
            skip_undecodable: when True, silently drop records whose value isn't
                a valid Blink/V8 payload; otherwise surface them with ``value=None``.
        """
        for raw in self._raw_records:
            db_info = self._databases.get(raw.db_id)
            store_info = self._object_stores.get((raw.db_id, raw.store_id))
            if db_info is None or store_info is None:
                continue
            if database is not None and not matches(database, db_info.name):
                continue
            if object_store is not None and not matches(object_store, store_info.name):
                continue
            if not raw.is_live and not include_deletions:
                continue
            value = self._decode_value(raw.value, skip_undecodable)
            if value is _UNDECODABLE:
                continue
            yield IndexedDbRecord(
                database_name=db_info.name,
                object_store_name=store_info.name,
                raw_key=raw.idb_key,
                value=value,
                leveldb_seq_number=raw.seq,
                is_live=raw.is_live,
            )

    @staticmethod
    def _decode_value(raw: bytes, skip_undecodable: bool) -> Any:
        # IDB record values are prefixed with: <var_int = wrapper_version>
        # <var_int = blob_size> <blink payload>. We need to skip both varints.
        stream = io.BytesIO(raw)
        first = _read_le_varint(stream)
        if first is None:
            return _UNDECODABLE if skip_undecodable else None
        # If the first byte was the Blink envelope (0xFF), we already consumed
        # part of the payload — fall back to treating the whole buffer as Blink.
        if first == 0xFF or (first & 0x80) == 0 and first < 0x10:
            try:
                value, _envelope = deserialize(raw[stream.tell() :])
                return value
            except (BlinkError, V8Error) as exc:
                logger.debug("IDB value decode failed: %s", exc)
                return _UNDECODABLE if skip_undecodable else None
        try:
            value, _envelope = deserialize(raw)
            return value
        except (BlinkError, V8Error) as exc:
            logger.debug("IDB value decode failed: %s", exc)
            return _UNDECODABLE if skip_undecodable else None

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


@dataclasses.dataclass(frozen=True, slots=True)
class _RawIdbRecord:
    db_id: int
    store_id: int
    idb_key: bytes
    value: bytes
    seq: int
    is_live: bool


_UNDECODABLE: object = object()


def _read_short_id(buf: bytes) -> tuple[int, bytes]:
    """Read a leveldb varint and return (value, remaining_bytes)."""
    stream = io.BytesIO(buf)
    value = _read_le_varint(stream, is_32bit=True)
    if value is None:
        raise ValueError("Truncated short id")
    return value, buf[stream.tell() :]


def _decode_string_with_length(buf: bytes) -> str:
    """Decode a length-prefixed UTF-16BE string used in IDB metadata keys.

    The format is ``<varint length_in_uint16s><UTF-16BE bytes>``.
    """
    stream = io.BytesIO(buf)
    length = _read_le_varint(stream, is_32bit=True)
    if length is None:
        raise ValueError("Missing string length")
    chunk = stream.read(length * 2)
    if len(chunk) != length * 2:
        raise ValueError("Truncated string")
    return chunk.decode("utf-16-be")


__all__ = [
    "DatabaseInfo",
    "IndexedDbReader",
    "IndexedDbRecord",
    "ObjectStoreInfo",
]
