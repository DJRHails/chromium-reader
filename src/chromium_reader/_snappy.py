"""Pure-Python Snappy block decompression.

Derived from ``ccl_simplesnappy`` by CCL Forensics (MIT licensed,
Copyright 2020 CCL Forensics).

Only the block (non-framed) format is implemented because LevelDB stores
already-framed blocks with their own length/CRC envelope.

See: https://github.com/google/snappy/blob/main/format_description.txt
"""

from __future__ import annotations

import enum
import io
import struct
from typing import BinaryIO, cast


class SnappyError(ValueError):
    """Raised when Snappy-compressed data is malformed."""


class _ElementType(enum.IntEnum):
    LITERAL = 0
    COPY_1B = 1
    COPY_2B = 2
    COPY_4B = 3


def _read_le_varint(stream: BinaryIO) -> int | None:
    """Read an unsigned little-endian varint; returns None at EOF."""
    result = 0
    for i in range(10):
        raw = stream.read(1)
        if not raw:
            return None
        b = raw[0]
        result |= (b & 0x7F) << (i * 7)
        if (b & 0x80) == 0:
            return result
    raise SnappyError("Varint exceeded 10 bytes")


def _read_uint16(stream: BinaryIO) -> int:
    return struct.unpack("<H", stream.read(2))[0]


def _read_uint24(stream: BinaryIO) -> int:
    return struct.unpack("<I", stream.read(3) + b"\x00")[0]


def _read_uint32(stream: BinaryIO) -> int:
    return struct.unpack("<I", stream.read(4))[0]


def _literal_length(type_byte: int, stream: BinaryIO) -> int:
    """Compute literal length given the tag byte and (possibly) extra bytes."""
    upper = (type_byte & 0xFC) >> 2
    if upper < 60:
        return 1 + upper
    if upper == 60:
        return 1 + stream.read(1)[0]
    if upper == 61:
        return 1 + _read_uint16(stream)
    if upper == 62:
        return 1 + _read_uint24(stream)
    if upper == 63:
        return 1 + _read_uint32(stream)
    raise SnappyError("Impossible literal length tag")  # pragma: no cover


def _copy_params(type_byte: int, tag: int, stream: BinaryIO) -> tuple[int, int]:
    """Return (length, offset) for the various copy tag forms."""
    if tag == _ElementType.COPY_1B:
        length = ((type_byte & 0x1C) >> 2) + 4
        offset = ((type_byte & 0xE0) << 3) | stream.read(1)[0]
    elif tag == _ElementType.COPY_2B:
        length = 1 + ((type_byte & 0xFC) >> 2)
        offset = _read_uint16(stream)
    elif tag == _ElementType.COPY_4B:
        length = 1 + ((type_byte & 0xFC) >> 2)
        offset = _read_uint32(stream)
    else:  # pragma: no cover
        raise SnappyError("Impossible copy tag")
    if offset == 0:
        raise SnappyError("Copy offset cannot be zero")
    return length, offset


def decompress(data: bytes | bytearray | memoryview | BinaryIO) -> bytes:
    """Decompress a Snappy block.

    Accepts either raw bytes or any binary stream; returns the decompressed bytes.
    """
    if isinstance(data, bytes | bytearray | memoryview):
        stream: BinaryIO = io.BytesIO(bytes(data))
    else:
        stream = cast(BinaryIO, data)

    declared_length = _read_le_varint(stream)
    if declared_length is None:
        raise SnappyError("Missing length header")

    out = io.BytesIO()
    while True:
        type_byte_raw = stream.read(1)
        if not type_byte_raw:
            break
        type_byte = type_byte_raw[0]
        tag = type_byte & 0x03

        if tag == _ElementType.LITERAL:
            length = _literal_length(type_byte, stream)
            chunk = stream.read(length)
            if len(chunk) != length:
                raise SnappyError("Truncated literal")
            out.write(chunk)
            continue

        length, offset = _copy_params(type_byte, tag, stream)
        target = out.tell() - offset
        if target < 0:
            raise SnappyError("Copy offset out of bounds")
        buf = bytes(out.getbuffer()[target : target + length])
        if offset - length <= 0:
            buf = (buf * length)[:length]
        out.write(buf)

    result = out.getvalue()
    if declared_length != len(result):
        raise SnappyError(
            f"Length mismatch: header said {declared_length}, decompressed {len(result)}"
        )
    return result
