"""Tests for the pure-Python V8 ValueDeserializer."""

from __future__ import annotations

import io
import struct

import pytest

from chromium_reader._v8_deserializer import Deserializer, RegExpValue, V8Error


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


def _zigzag(value: int) -> bytes:
    return _varint(
        (value << 1) ^ (value >> 63 if value < 0 else 0) if value >= 0 else _zigzag_neg(value)
    )


def _zigzag_neg(value: int) -> bytes:
    # zigzag for negative: ((v << 1) ^ -1) for negative v, but we precompute.
    encoded = (value << 1) ^ ((1 << 64) - 1)
    encoded &= (1 << 64) - 1
    return _varint(encoded)


def _v8_header(version: int = 13) -> bytes:
    return bytes([0xFF]) + _varint(version)


def _make(version: int, body: bytes) -> Deserializer:
    return Deserializer(io.BytesIO(_v8_header(version) + body))


def test_read_header_rejects_old_version() -> None:
    d = Deserializer(io.BytesIO(bytes([0xFF]) + _varint(12)))
    with pytest.raises(V8Error):
        d.read_header()


def test_read_undefined() -> None:
    d = _make(13, bytes([0x5F]))
    d.read_header()
    assert d.read_value() is None


def test_read_int32_zigzag() -> None:
    d = _make(13, bytes([0x49]) + _varint(0))
    d.read_header()
    assert d.read_value() == 0

    d = _make(13, bytes([0x49]) + _varint(1))  # zigzag(1) = -1
    d.read_header()
    assert d.read_value() == -1

    d = _make(13, bytes([0x49]) + _varint(2))  # zigzag(2) = 1
    d.read_header()
    assert d.read_value() == 1


def test_read_double() -> None:
    d = _make(13, bytes([0x4E]) + struct.pack("<d", 3.14))
    d.read_header()
    assert d.read_value() == pytest.approx(3.14)


def test_read_utf8_string() -> None:
    body = bytes([0x53]) + _varint(5) + b"hello"
    d = _make(13, body)
    d.read_header()
    assert d.read_value() == "hello"


def test_read_two_byte_string() -> None:
    text = "héllo"
    encoded = text.encode("utf-16-le")
    body = bytes([0x63]) + _varint(len(encoded)) + encoded
    d = _make(13, body)
    d.read_header()
    assert d.read_value() == text


def test_read_object() -> None:
    # { "a": 1 } — BEGIN_OBJECT, UTF8 "a", INT32 1, END_OBJECT, count=1
    key = bytes([0x53]) + _varint(1) + b"a"
    val = bytes([0x49]) + _varint(2)  # zigzag(2) = 1
    body = bytes([0x6F]) + key + val + bytes([0x7B]) + _varint(1)
    d = _make(13, body)
    d.read_header()
    assert d.read_value() == {"a": 1}


def test_read_dense_array() -> None:
    # [10, 20] — BEGIN_DENSE_ARRAY len=2, INT32 10, INT32 20, then 0 trailing props,
    # written-props=0, declared length=2.
    body = (
        bytes([0x41])
        + _varint(2)
        + bytes([0x49])
        + _varint(20)  # zigzag(20)=10? zigzag inverse: u=20 -> -10
    )

    # Compute correct zigzag for 10 and 20.
    def z(n: int) -> bytes:
        return _varint((n << 1) ^ (n >> 31))

    body = (
        bytes([0x41])
        + _varint(2)
        + bytes([0x49])
        + z(10)
        + bytes([0x49])
        + z(20)
        + _varint(0)  # properties written
        + _varint(2)  # declared length
    )
    d = _make(13, body)
    d.read_header()
    assert d.read_value() == [10, 20]


def test_read_map() -> None:
    body = (
        bytes([0x3B])
        + bytes([0x53])
        + _varint(1)
        + b"k"
        + bytes([0x49])
        + _varint(0)  # 0
        + bytes([0x3A])
        + _varint(2)
    )
    d = _make(13, body)
    d.read_header()
    assert d.read_value() == {"k": 0}


def test_read_set() -> None:
    body = (
        bytes([0x27])
        + bytes([0x49])
        + _varint(0)
        + bytes([0x49])
        + _varint(2)
        + bytes([0x2C])
        + _varint(2)
    )
    d = _make(13, body)
    d.read_header()
    assert d.read_value() == {0, 1}


def test_read_regexp() -> None:
    pattern = bytes([0x53]) + _varint(3) + b".*?"
    body = bytes([0x52]) + pattern + _varint(2)
    d = _make(13, body)
    d.read_header()
    val = d.read_value()
    assert isinstance(val, RegExpValue)
    assert val.pattern == ".*?"
    assert val.flags == 2


def test_unsupported_tag_raises() -> None:
    d = _make(13, bytes([0xAA]))
    d.read_header()
    with pytest.raises(V8Error):
        d.read_value()
