"""Blink ``SerializedScriptValue`` envelope around V8's serialised payload.

IndexedDB and postMessage in Chromium wrap the V8 payload in a small Blink
header that encodes:

- a one-byte version tag ``0xFF`` followed by a varint Blink version (>= 17)
- a host-object table (transferred ports, blobs, image bitmaps) — skipped here
- the V8 payload (its own ``0xFF`` + V8 version)

Blink host tags (Blob, File, FileList, ImageBitmap, etc.) are surfaced as
:class:`~chromium_reader._v8_deserializer.HostObject` placeholders. They are
recoverable by callers that need full fidelity, but the default behaviour is
to leave them opaque so that the surrounding object tree is still usable.

Derived in spirit from ``ccl_chromium_reader/serialization_formats/
ccl_blink_value_deserializer.py`` by CCL Forensics (MIT, Copyright 2020-2024).
Reimplemented from scratch for Python 3.11+.
"""

from __future__ import annotations

import dataclasses
import io
import logging
from typing import Any, BinaryIO

from chromium_reader._v8_deserializer import Deserializer as _V8Deserializer
from chromium_reader._v8_deserializer import HostObject

logger = logging.getLogger(__name__)

_HEADER_TAG = 0xFF
_TRAILER_TAG = 0xFE


@dataclasses.dataclass(frozen=True, slots=True)
class BlinkEnvelope:
    """Metadata extracted from the Blink header that wraps a V8 payload."""

    blink_version: int
    v8_version: int


class BlinkError(ValueError):
    """Raised when the Blink envelope is malformed or uses an unsupported version."""


def _read_varint(stream: BinaryIO) -> int:
    result = 0
    for shift in range(0, 70, 7):
        raw = stream.read(1)
        if not raw:
            raise BlinkError("Unexpected EOF in Blink varint")
        b = raw[0]
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result
    raise BlinkError("Blink varint exceeded 10 bytes")


def _blink_host_object_reader(tag: int, stream: BinaryIO) -> HostObject:
    """Read a Blink host-object payload as opaque bytes.

    Blink host tags are length-prefixed varints, so we capture exactly the
    payload that the Blink layer claims and surface it for callers that want
    to interpret specific types themselves.
    """
    length = _read_varint(stream)
    if length > 1 << 30:
        raise BlinkError(f"Implausible Blink host-object length: {length}")
    payload = stream.read(length)
    if len(payload) != length:
        raise BlinkError(f"Truncated Blink host object: expected {length}, got {len(payload)}")
    return HostObject(tag=tag, payload=payload)


def deserialize(data: bytes) -> tuple[Any, BlinkEnvelope]:
    """Decode a Blink-wrapped V8 value.

    Args:
        data: full payload as stored in IndexedDB or another Blink consumer.

    Returns:
        ``(value, envelope)`` — the recovered Python value and the version
        metadata for diagnostics.

    Raises:
        BlinkError: malformed Blink envelope.
        V8Error: malformed V8 payload.
    """
    stream: BinaryIO = io.BytesIO(data)
    blink_version = _read_blink_header(stream)
    v8_deserializer = _V8Deserializer(stream, host_object_reader=_blink_host_object_reader)
    v8_version = v8_deserializer.read_header()
    value = v8_deserializer.read_value()
    return value, BlinkEnvelope(blink_version=blink_version, v8_version=v8_version)


def _read_blink_header(stream: BinaryIO) -> int:
    """Consume the Blink envelope tag and return the Blink version.

    Both the Blink envelope and the V8 header begin with ``0xFF``. They are
    distinguished by their version varint range: Blink uses versions >= 17,
    V8 uses versions 13-15. When the leading byte is ``0xFF`` but the next
    varint falls into the V8 range, we treat the payload as un-enveloped
    and rewind so the V8 deserializer can read its own header.
    """
    start = stream.tell()
    tag = stream.read(1)
    if not tag:
        raise BlinkError("Empty Blink payload")
    if tag[0] != _HEADER_TAG:
        stream.seek(start)
        return 0
    version = _read_varint(stream)
    if version < 17:
        # Looks like a V8 header, not a Blink envelope — rewind for V8.
        stream.seek(start)
        return 0
    return version


def has_blink_envelope(data: bytes) -> bool:
    """Return True if ``data`` starts with what looks like a Blink header."""
    return len(data) >= 2 and data[0] == _HEADER_TAG and data[1] >= 17


_ = _TRAILER_TAG  # reserved for future use by Blink (trailer offsets, etc.)


__all__ = [
    "BlinkEnvelope",
    "BlinkError",
    "deserialize",
    "has_blink_envelope",
]
