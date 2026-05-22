"""chromium-reader — pure-Python reader for Chromium on-disk storage formats.

This package reimplements the parts of CCL Forensics' ``ccl_chromium_reader``
that are needed to read browser LevelDB, localStorage, SessionStorage,
IndexedDB and serialized V8 values without native dependencies.

Public modules:
- :mod:`chromium_reader.leveldb` — low-level LevelDB reader
- :mod:`chromium_reader.localstorage` — Chromium localStorage on top of LevelDB
- :mod:`chromium_reader.sessionstorage` — Chromium SessionStorage on top of LevelDB
- :mod:`chromium_reader.indexeddb` — Chromium IndexedDB reader (V8/Blink-aware)
"""

from chromium_reader.common import KeySearch
from chromium_reader.indexeddb import IndexedDbReader, IndexedDbRecord
from chromium_reader.leveldb import RawLevelDb, Record
from chromium_reader.localstorage import LocalStorageReader, LocalStorageRecord
from chromium_reader.sessionstorage import SessionStorageReader, SessionStorageRecord

__version__ = "0.1.0"

__all__ = [
    "IndexedDbReader",
    "IndexedDbRecord",
    "KeySearch",
    "LocalStorageReader",
    "LocalStorageRecord",
    "RawLevelDb",
    "Record",
    "SessionStorageReader",
    "SessionStorageRecord",
    "__version__",
]
