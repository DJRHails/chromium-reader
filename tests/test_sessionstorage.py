"""End-to-end test for the SessionStorageReader against a synthetic log."""

from __future__ import annotations

import struct
from pathlib import Path

from chromium_reader.leveldb import KeyState
from chromium_reader.sessionstorage import SessionStorageReader


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _entry(state: int, key: bytes, value: bytes) -> bytes:
    body = bytearray([state]) + _varint(len(key)) + key
    if state == KeyState.LIVE.value:
        body += _varint(len(value)) + value
    return bytes(body)


def _log_block(entries: list[bytes], start_seq: int = 1) -> bytes:
    body = b"".join(entries)
    header = struct.pack("<QI", start_seq, len(entries))
    payload = header + body
    record = struct.pack("<IHB", 0, len(payload), 1) + payload
    return record.ljust(32768, b"\x00")


def _value(text: str) -> bytes:
    return b"\x01" + text.encode("iso-8859-1")


def test_sessionstorage_roundtrip(tmp_path: Path) -> None:
    (tmp_path / "CURRENT").write_text("MANIFEST-000001\n")
    (tmp_path / "MANIFEST-000001").write_bytes(b"")
    log_path = tmp_path / "000002.log"

    ns_id = "AAAAAAAA"
    map_id = "01"
    ns_entry = _entry(
        KeyState.LIVE.value,
        f"namespace-{ns_id}-https://example.com".encode("iso-8859-1"),
        map_id.encode("iso-8859-1"),
    )
    map_entry = _entry(
        KeyState.LIVE.value,
        f"map-{map_id}-".encode("iso-8859-1") + _value("greeting"),
        _value("hello"),
    )
    log_path.write_bytes(_log_block([ns_entry, map_entry]))

    with SessionStorageReader(tmp_path) as reader:
        assert "https://example.com" in reader.storage_keys
        records = list(reader.records())
        assert len(records) == 1
        rec = records[0]
        assert rec.storage_key == "https://example.com"
        assert rec.namespace_id == ns_id
        assert rec.script_key == "greeting"
        assert rec.value == "hello"
