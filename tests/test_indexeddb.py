"""Unit tests for IndexedDB key-coding helpers and the public surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from chromium_reader.indexeddb import (
    IndexedDbReader,
    _decode_string_with_length,
    _read_short_id,
)


def test_read_short_id_basic() -> None:
    value, rest = _read_short_id(b"\x05\xff\x00")
    assert value == 5
    assert rest == b"\xff\x00"


def test_read_short_id_multi_byte_varint() -> None:
    # 300 = 0xAC 0x02 in varint LE.
    value, rest = _read_short_id(b"\xac\x02xyz")
    assert value == 300
    assert rest == b"xyz"


def test_read_short_id_truncated() -> None:
    with pytest.raises(ValueError):
        _read_short_id(b"")


def test_decode_string_with_length_utf16be() -> None:
    text = "hi"
    body = bytes([len(text)]) + text.encode("utf-16-be")
    assert _decode_string_with_length(body) == text


def test_decode_string_with_length_truncated() -> None:
    with pytest.raises(ValueError):
        _decode_string_with_length(bytes([5]) + b"ab")


def test_reader_rejects_non_directory(tmp_path: Path) -> None:
    bogus = tmp_path / "nope"
    with pytest.raises(NotADirectoryError):
        IndexedDbReader(bogus)
