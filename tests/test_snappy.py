"""Tests for the pure-Python Snappy decompressor."""

from __future__ import annotations

import pytest

from chromium_reader._snappy import SnappyError, decompress


def test_decompress_literal_only() -> None:
    # "hello" — declared length 5, single literal tag ((5-1) << 2) | 0, then bytes.
    payload = bytes([5, (5 - 1) << 2]) + b"hello"
    assert decompress(payload) == b"hello"


def test_decompress_with_copy() -> None:
    # "abcabc" — literal "abc" then a COPY_1B for length 3 at offset 3.
    # COPY_1B layout: ((length - 4) << 2) | tag | ((offset & 0x700) >> 3) <byte>
    # length=3 isn't representable in COPY_1B (min 4). Use literal of len 4
    # then COPY for the remaining 2 bytes of "abcabc" extended: pick a real case.
    # "abcdabcd" — literal "abcd" (4 bytes), then COPY_1B len=4 offset=4.
    literal_tag = (4 - 1) << 2  # upper 6 bits = len-1, tag bits 00 (LITERAL)
    copy_tag = ((4 - 4) << 2) | 0b01  # COPY_1B, length nibble 0 -> len 4
    payload = (
        bytes([8, literal_tag])
        + b"abcd"
        + bytes([copy_tag, 4])  # offset low byte = 4, high bits = 0
    )
    assert decompress(payload) == b"abcdabcd"


def test_decompress_rejects_zero_offset() -> None:
    literal_tag = (1 - 1) << 2
    bad = bytes([2, literal_tag, ord("a"), ((4 - 4) << 2) | 0b01, 0])
    with pytest.raises(SnappyError):
        decompress(bad)


def test_decompress_length_mismatch() -> None:
    # Declared length 10 but body only emits "hi".
    payload = bytes([10, (2 - 1) << 2]) + b"hi"
    with pytest.raises(SnappyError):
        decompress(payload)
