# chromium-reader

Pure-Python reader for Chromium/Chrome on-disk storage formats. Reads LevelDB,
localStorage, SessionStorage, IndexedDB and serialized V8 values **without**
native dependencies — no `plyvel`, no `snappy` C extension, no Node.

Reimplements the parts of CCL Forensics'
[`ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chrome_indexeddb)
needed for read-only forensics / data recovery, in idiomatic Python 3.11+
with dataclasses, `pathlib`, type hints and stdlib-only deps.

## Install

```bash
pip install chromium-reader
```

Requires Python 3.11+. Zero runtime dependencies.

## Usage

### localStorage

```python
from chromium_reader.localstorage import LocalStorageReader

profile = "~/Library/Application Support/Arc/User Data/Default/Local Storage/leveldb"
with LocalStorageReader(profile) as reader:
    for record in reader.records(host="https://app.slack.com"):
        print(record.script_key, record.value[:80])
```

`records()` accepts string, regex, collection or callable filters via the
`host=` and `script_key=` keyword arguments.

### SessionStorage

```python
from chromium_reader.sessionstorage import SessionStorageReader

with SessionStorageReader(profile_session_storage) as reader:
    for record in reader.records(host="https://example.com"):
        print(record.namespace_id, record.script_key, record.value)
```

### IndexedDB

```python
from chromium_reader.indexeddb import IndexedDbReader

with IndexedDbReader("~/.../IndexedDB/https_example.com_0.indexeddb.leveldb") as db:
    for info in db.databases:
        print(info.name)
    for record in db.records(database="MyDB", object_store="kv"):
        print(record.raw_key, record.value)
```

IndexedDB values are automatically decoded through the Blink + V8 envelopes,
recovering plain objects, arrays, Maps, Sets, Dates, BigInts and typed arrays.
Host objects (Blob, File, etc.) are surfaced as opaque `HostObject`
placeholders.

### Raw LevelDB

For other Chromium leveldb stores (Cookies, Site Characteristics, etc.):

```python
from chromium_reader.leveldb import RawLevelDb

with RawLevelDb(path) as db:
    for record in db.iterate_records_raw():
        if record.is_live:
            print(record.user_key, record.value[:32])
```

## What's supported

- **LevelDB**: `.ldb`/`.sst` table reader (Snappy-decompressing), `.log`
  write-ahead reader, MANIFEST parser for level lookup.
- **Snappy**: pure-Python block decompression.
- **localStorage**: META-prefixed protobufs + 1-byte type-tagged values
  (UTF-16 LE and Latin-1). Write-batch reconstruction.
- **SessionStorage**: namespace→map_id resolution, value decoding.
- **V8 ValueDeserializer**: format versions 13-15, primitives, BigInts, Date,
  RegExp, ArrayBuffer/typed-array views, plain objects, Maps, Sets, sparse
  and dense arrays.
- **Blink envelope**: Blink versions ≥ 17 around the V8 payload; gracefully
  rewinds when the payload is V8-only.
- **IndexedDB**: walks every database / object store, decodes values, exposes
  `(database_name, object_store_name, raw_key, value)`.

## What's not (yet)

- IndexedDB **index** entries (we only read the primary object-store records).
- IndexedDB external `.blob` resolution.
- Cookies database schema (the underlying LevelDB is readable via `RawLevelDb`,
  but no high-level wrapper).
- Session Storage history/batching like the localStorage version.

## Credits

The parsers are derived in spirit from
[`ccl_chromium_reader`](https://github.com/cclgroupltd/ccl_chrome_indexeddb)
by CCL Forensics (MIT, Copyright 2020-2024). This is a clean-room
reimplementation; correctness bugs are mine, not theirs.

## License

MIT.
