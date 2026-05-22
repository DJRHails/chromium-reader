"""Chromium SessionStorage reader, sitting on top of :mod:`chromium_reader.leveldb`.

SessionStorage lives in ``<profile>/Session Storage`` and uses a two-stage
mapping: each (host, namespace) pair gets a short *map id*, and the actual
script-side keys hang off that map id. The on-disk layout is:

- ``namespace-<namespace_id>-<storage_key>`` → ``<map_id>`` (ASCII bytes)
- ``map-<map_id>-<script_key>``              → ``<value>``  (Chromium string)

Both ``<storage_key>``, ``<script_key>`` and ``<value>`` use the same 1-byte
type prefix convention as localStorage (see
:func:`chromium_reader.localstorage.decode_value`).

Derived in spirit from
``ccl_chromium_reader/ccl_chromium_sessionstorage.py`` by CCL Forensics
(MIT, Copyright 2020-2024). Reimplemented from scratch for Python 3.11+.

References:
- https://source.chromium.org/chromium/chromium/src/+/main:components/services/storage/dom_storage/session_storage_impl.cc
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from chromium_reader.common import KeySearch, matches
from chromium_reader.leveldb import KeyState, RawLevelDb, Record
from chromium_reader.localstorage import decode_value

logger = logging.getLogger(__name__)

_NAMESPACE_PREFIX = b"namespace-"
_MAP_PREFIX = b"map-"
_LATIN1 = "iso-8859-1"


@dataclasses.dataclass(frozen=True, slots=True)
class SessionStorageRecord:
    """A single ``window.sessionStorage`` entry, possibly historical."""

    namespace_id: str
    storage_key: str
    script_key: str
    value: str | None
    map_id: str
    leveldb_seq_number: int
    is_live: bool

    @property
    def host(self) -> str:
        """Alias for ``storage_key`` — the origin/host owning the record."""
        return self.storage_key


class SessionStorageReader:
    """Reader for a Chromium Session Storage leveldb directory.

    Use as a context manager:

        >>> from chromium_reader.sessionstorage import SessionStorageReader
        >>> with SessionStorageReader(path) as reader:
        ...     for record in reader.records():
        ...         ...
    """

    def __init__(self, in_dir: Path | str) -> None:
        path = Path(in_dir)
        if not path.is_dir():
            raise NotADirectoryError(path)
        self._path = path
        self._ldb = RawLevelDb(path)

        # map_id -> (storage_key, namespace_id) — keyed on the latest live binding.
        self._map_to_host: dict[str, tuple[str, str]] = {}
        # Raw (state, value, seq) entries to materialise after we know the host.
        self._pending_maps: list[_PendingMapEntry] = []

        for raw in self._ldb.iterate_records_raw():
            self._ingest(raw)

    def _ingest(self, record: Record) -> None:
        key = record.user_key
        if key.startswith(_NAMESPACE_PREFIX):
            self._ingest_namespace(record)
        elif key.startswith(_MAP_PREFIX):
            self._ingest_map(record)

    def _ingest_namespace(self, record: Record) -> None:
        if record.state != KeyState.LIVE:
            return
        body = record.user_key.removeprefix(_NAMESPACE_PREFIX)
        # Layout: <namespace_id>-<storage_key>; namespace_id is fixed-width
        # but we use the last dash before the protocol prefix to split.
        try:
            namespace_id, storage_key = body.decode(_LATIN1).split("-", 1)
        except ValueError:
            logger.debug("Malformed namespace key: %r", body)
            return
        map_id = record.value.decode(_LATIN1)
        self._map_to_host[map_id] = (storage_key, namespace_id)

    def _ingest_map(self, record: Record) -> None:
        body = record.user_key.removeprefix(_MAP_PREFIX)
        try:
            map_id, script_raw = body.decode(_LATIN1).split("-", 1)
        except ValueError:
            logger.debug("Malformed map key: %r", body)
            return
        self._pending_maps.append(
            _PendingMapEntry(
                map_id=map_id,
                script_raw=script_raw.encode(_LATIN1),
                value_raw=record.value,
                state=record.state,
                seq=record.seq,
            )
        )

    def _materialise(self) -> Iterator[SessionStorageRecord]:
        for pending in self._pending_maps:
            host_pair = self._map_to_host.get(pending.map_id)
            if host_pair is None:
                logger.debug("Map %s has no live namespace binding", pending.map_id)
                continue
            storage_key, namespace_id = host_pair
            try:
                script_key = decode_value(pending.script_raw)
            except (ValueError, UnicodeDecodeError):
                logger.debug("Undecodable script key under map %s", pending.map_id)
                continue
            is_live = pending.state == KeyState.LIVE
            value: str | None = None
            if is_live:
                try:
                    value = decode_value(pending.value_raw)
                except (ValueError, UnicodeDecodeError):
                    logger.debug(
                        "Undecodable value for map=%s script=%s",
                        pending.map_id,
                        script_key,
                    )
                    continue
            yield SessionStorageRecord(
                namespace_id=namespace_id,
                storage_key=storage_key,
                script_key=script_key,
                value=value,
                map_id=pending.map_id,
                leveldb_seq_number=pending.seq,
                is_live=is_live,
            )

    @property
    def path(self) -> Path:
        return self._path

    @property
    def storage_keys(self) -> frozenset[str]:
        return frozenset(host for host, _ns in self._map_to_host.values())

    def records(
        self,
        *,
        host: KeySearch | None = None,
        script_key: KeySearch | None = None,
        include_deletions: bool = False,
    ) -> Iterator[SessionStorageRecord]:
        """Iterate records, optionally filtered by host and/or script key.

        Args:
            host: storage-key filter (str, regex, collection, or callable).
            script_key: script-key filter (same forms).
            include_deletions: when True, yield records for deleted entries too.
        """
        for rec in self._materialise():
            if host is not None and not matches(host, rec.storage_key):
                continue
            if script_key is not None and not matches(script_key, rec.script_key):
                continue
            if not rec.is_live and not include_deletions:
                continue
            yield rec

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
class _PendingMapEntry:
    map_id: str
    script_raw: bytes
    value_raw: bytes
    state: KeyState
    seq: int


__all__ = ["SessionStorageReader", "SessionStorageRecord"]
