"""Tests for the leveldb log-file reader using synthetic byte sequences."""

from __future__ import annotations

import io
import struct
from pathlib import Path

from chromium_reader.leveldb import (
    KeyState,
    LogFile,
    _read_le_varint,
)


def _varint32(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def test_read_le_varint_basic() -> None:
    stream = io.BytesIO(b"\x96\x01")  # 150
    assert _read_le_varint(stream, is_32bit=True) == 150


def _build_log_batch(entries: list[tuple[int, bytes, bytes]]) -> bytes:
    """Build a single leveldb log batch: header + entries."""
    seq = 100
    body = bytearray()
    for state, key, value in entries:
        body.append(state)
        body += _varint32(len(key))
        body += key
        if state == KeyState.LIVE.value:
            body += _varint32(len(value))
            body += value
    header = struct.pack("<QI", seq, len(entries))
    return header + bytes(body)


def _wrap_in_log_block(batch: bytes) -> bytes:
    """Wrap a batch as a single FULL log record (32 KiB block)."""
    btype = 1  # FULL
    record = struct.pack("<IHB", 0, len(batch), btype) + batch
    return record.ljust(32768, b"\x00")


def test_log_file_roundtrip(tmp_path: Path) -> None:
    batch = _build_log_batch(
        [
            (KeyState.LIVE.value, b"alpha", b"first"),
            (KeyState.LIVE.value, b"beta", b"second"),
            (KeyState.DELETED.value, b"gamma", b""),
        ]
    )
    path = tmp_path / "000001.log"
    path.write_bytes(_wrap_in_log_block(batch))

    log = LogFile(path)
    try:
        records = list(log)
    finally:
        log.close()

    assert [r.key for r in records] == [b"alpha", b"beta", b"gamma"]
    assert records[0].value == b"first"
    assert records[1].value == b"second"
    assert records[2].state == KeyState.DELETED
    assert {r.seq for r in records} == {100, 101, 102}
