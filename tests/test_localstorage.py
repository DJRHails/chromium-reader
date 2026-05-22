"""End-to-end tests for the LocalStorageReader against synthetic leveldb logs."""

from __future__ import annotations

import io
import struct
from pathlib import Path

from chromium_reader.leveldb import KeyState
from chromium_reader.localstorage import (
    LocalStorageReader,
    chrome_timestamp,
    decode_value,
)


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


def _build_value(text: str) -> bytes:
    return b"\x01" + text.encode("iso-8859-1")


def _build_meta_protobuf(timestamp_us: int, size: int) -> bytes:
    # Field 1 varint = timestamp, field 2 varint = size.
    return b"\x08" + _varint(timestamp_us) + b"\x10" + _varint(size)


def test_localstorage_roundtrip(tmp_path: Path) -> None:
    (tmp_path / "CURRENT").write_text("MANIFEST-000001\n")
    (tmp_path / "MANIFEST-000001").write_bytes(b"")  # empty manifest is OK
    log_path = tmp_path / "000002.log"

    meta = _entry(
        KeyState.LIVE.value,
        b"META:https://example.com",
        _build_meta_protobuf(13000000000000000, 42),
    )
    rec_alpha = _entry(
        KeyState.LIVE.value,
        b"_https://example.com\x00" + _build_value("alpha"),
        _build_value("xoxc-secret-token-pretend"),
    )
    rec_beta = _entry(
        KeyState.LIVE.value,
        b"_https://example.com\x00" + _build_value("beta"),
        _build_value("plain"),
    )
    log_path.write_bytes(_log_block([meta, rec_alpha, rec_beta]))

    with LocalStorageReader(tmp_path) as reader:
        assert "https://example.com" in reader.storage_keys
        records = list(reader.records())
        assert {r.script_key for r in records} == {"alpha", "beta"}
        alpha = next(r for r in records if r.script_key == "alpha")
        assert alpha.value == "xoxc-secret-token-pretend"
        assert alpha.host == "https://example.com"
        metas = list(reader.metadata())
        assert metas[0].size_in_bytes == 42


def test_decode_value_utf16() -> None:
    raw = b"\x00" + "hé".encode("utf-16-le")
    assert decode_value(raw) == "hé"


def test_decode_value_latin1() -> None:
    raw = b"\x01" + "hé".encode("iso-8859-1")
    assert decode_value(raw) == "hé"


def test_chrome_timestamp_epoch() -> None:
    base = chrome_timestamp(0)
    assert base.year == 1601


def test_decode_value_empty_raises() -> None:
    import pytest

    with pytest.raises(ValueError):
        decode_value(b"")


def test_read_le_varint_smoke() -> None:
    from chromium_reader.leveldb import _read_le_varint

    assert _read_le_varint(io.BytesIO(b"\x00")) == 0
    assert _read_le_varint(io.BytesIO(b"\xff\x01")) == 255
