"""Tests for the Blink envelope around the V8 deserializer."""

from __future__ import annotations

import pytest

from chromium_reader._blink_deserializer import (
    BlinkError,
    deserialize,
    has_blink_envelope,
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


def _v8_int32(zigzag_encoded: int) -> bytes:
    return bytes([0x49]) + _varint(zigzag_encoded)


def _blink_payload(blink_version: int, v8_payload: bytes) -> bytes:
    return bytes([0xFF]) + _varint(blink_version) + v8_payload


def _v8_string_hello() -> bytes:
    return bytes([0xFF]) + _varint(13) + bytes([0x53]) + _varint(5) + b"hello"


def test_deserialize_blink_wrapped_string() -> None:
    payload = _blink_payload(17, _v8_string_hello())
    value, envelope = deserialize(payload)
    assert value == "hello"
    assert envelope.blink_version == 17
    assert envelope.v8_version == 13


def test_deserialize_without_blink_envelope() -> None:
    value, envelope = deserialize(_v8_string_hello())
    assert value == "hello"
    assert envelope.blink_version == 0


def test_has_blink_envelope_detects() -> None:
    assert has_blink_envelope(bytes([0xFF, 17]))
    assert not has_blink_envelope(bytes([0xFF, 5]))
    assert not has_blink_envelope(b"")


def test_empty_payload_raises() -> None:
    with pytest.raises(BlinkError):
        deserialize(b"")


def test_blink_version_below_threshold_falls_through() -> None:
    # A "Blink version" below 17 looks identical to a V8 header — we should
    # rewind and let V8 handle it.
    value, envelope = deserialize(_v8_string_hello())
    assert value == "hello"
    assert envelope.blink_version == 0
