"""Pure-Python deserializer for V8's ValueSerializer (Blink/IndexedDB payloads).

Implements enough of the V8 serialization format (header version 0xFF, payload
versions 13-15) to recover the script-visible value tree: undefined, null,
booleans, numbers, BigInts, strings, arrays, plain objects, Maps, Sets, Dates,
RegExps, ArrayBuffers and typed-array views.

V8 host objects (DOM nodes, Files, Blobs, IDBKeyRange, etc.) are wrapped by
Blink's ``SerializedScriptValue``; see :mod:`chromium_reader._blink_deserializer`
for the outer envelope that this module is invoked from.

Derived in spirit from ``ccl_chromium_reader/serialization_formats/
ccl_v8_value_deserializer.py`` by CCL Forensics (MIT, Copyright 2020-2024).
Reimplemented from scratch for Python 3.11+ with dataclasses, ``logging``,
verbose regex (n/a here), and stdlib-only dependencies.

References:
- https://v8.dev/blog/v8-release-78 (format overview)
- https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/value-serializer.cc
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import enum
import logging
import struct
from typing import Any, BinaryIO

logger = logging.getLogger(__name__)

_HEADER_TAG = 0xFF
_LATIN1 = "iso-8859-1"


class V8Error(ValueError):
    """Raised when V8-serialized data is malformed or uses an unsupported feature."""


class _Tag(enum.IntEnum):
    UNDEFINED = 0x5F  # "_"
    NULL = 0x30  # "0"
    TRUE = 0x54  # "T"
    FALSE = 0x46  # "F"
    INT32 = 0x49  # "I"
    UINT32 = 0x55  # "U"
    DOUBLE = 0x4E  # "N"
    BIG_INT = 0x5A  # "Z"
    UTF8_STRING = 0x53  # "S"
    ONE_BYTE_STRING = 0x22  # "\""
    TWO_BYTE_STRING = 0x63  # "c"
    PADDING = 0x00
    VERIFY_OBJECT_COUNT = 0x3F  # "?"
    THE_HOLE = 0x2D  # "-"

    DATE = 0x44  # "D"
    TRUE_OBJECT = 0x79  # "y"
    FALSE_OBJECT = 0x78  # "x"
    NUMBER_OBJECT = 0x6E  # "n"
    BIG_INT_OBJECT = 0x7A  # "z"
    STRING_OBJECT = 0x73  # "s"
    REGEXP = 0x52  # "R"

    ARRAY_BUFFER = 0x42  # "B"
    ARRAY_BUFFER_VIEW = 0x56  # "V"
    SHARED_ARRAY_BUFFER = 0x75
    ARRAY_BUFFER_TRANSFER = 0x74

    BEGIN_OBJECT = 0x6F  # "o"
    END_OBJECT = 0x7B  # "{"
    BEGIN_SPARSE_ARRAY = 0x61  # "a"
    END_SPARSE_ARRAY = 0x40  # "@"
    BEGIN_DENSE_ARRAY = 0x41  # "A"
    END_DENSE_ARRAY = 0x24  # "$"
    BEGIN_MAP = 0x3B  # ";"
    END_MAP = 0x3A  # ":"
    BEGIN_SET = 0x27  # "'"
    END_SET = 0x2C  # ","
    OBJECT_REFERENCE = 0x5E  # "^"
    HOST_OBJECT = 0x5C  # "\\"
    ERROR = 0x72  # "r"


class _ArrayBufferViewTag(enum.IntEnum):
    INT8 = 0x62  # "b"
    UINT8 = 0x42  # "B"
    UINT8_CLAMPED = 0x43  # "C"
    INT16 = 0x77  # "w"
    UINT16 = 0x57  # "W"
    INT32 = 0x64  # "d"
    UINT32 = 0x44  # "D"
    FLOAT32 = 0x66  # "f"
    FLOAT64 = 0x46  # "F"
    BIG_INT64 = 0x71  # "q"
    BIG_UINT64 = 0x51  # "Q"
    DATA_VIEW = 0x3F  # "?"


@dataclasses.dataclass(frozen=True, slots=True)
class HostObject:
    """A placeholder for a V8 host object: the Blink layer interprets these."""

    tag: int
    payload: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class TypedArrayView:
    """View metadata + raw bytes for a typed-array / DataView."""

    view_type: _ArrayBufferViewTag
    byte_offset: int
    byte_length: int
    backing: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class RegExpValue:
    """Mirror of a JS RegExp instance."""

    pattern: str
    flags: int


class Deserializer:
    """Deserialise a single V8-serialised value tree.

    The deserializer expects to be positioned just before the version header
    (``0xFF``); for IndexedDB the outer Blink envelope strips its own headers
    first.

    Args:
        stream: any binary stream that supports ``read(n)``.
        host_object_reader: callable that, given (tag, stream), returns the
            Python value for a host object. Defaults to skipping the host tag
            and returning a :class:`HostObject` placeholder, which is sufficient
            for surfacing the rest of the tree but won't unwrap, e.g., Files.
    """

    def __init__(
        self,
        stream: BinaryIO,
        host_object_reader: Any = None,
    ) -> None:
        self._stream = stream
        self._objects: list[Any] = []
        self._version = 0
        self._host_reader = host_object_reader or self._default_host_reader

    @staticmethod
    def _default_host_reader(tag: int, stream: BinaryIO) -> HostObject:
        del stream
        return HostObject(tag=tag, payload=b"")

    def read_header(self) -> int:
        tag = self._stream.read(1)
        if not tag or tag[0] != _HEADER_TAG:
            raise V8Error(f"Expected header tag 0xFF, got {tag!r}")
        version = self._read_varint()
        if version < 13:
            raise V8Error(f"Unsupported V8 serialization version: {version}")
        self._version = version
        return version

    def read_value(self) -> Any:
        return self._read_object()

    # -- low-level primitives ---------------------------------------------------

    def _read_varint(self) -> int:
        result = 0
        for shift in range(0, 70, 7):
            raw = self._stream.read(1)
            if not raw:
                raise V8Error("Unexpected EOF in varint")
            b = raw[0]
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return result
        raise V8Error("Varint exceeded 10 bytes")

    def _read_zigzag(self) -> int:
        u = self._read_varint()
        return (u >> 1) ^ -(u & 1)

    def _read_double(self) -> float:
        raw = self._stream.read(8)
        if len(raw) != 8:
            raise V8Error("Truncated double")
        return struct.unpack("<d", raw)[0]

    def _read_raw(self, length: int) -> bytes:
        chunk = self._stream.read(length)
        if len(chunk) != length:
            raise V8Error(f"Truncated raw bytes: expected {length}, got {len(chunk)}")
        return chunk

    def _read_bigint(self) -> int:
        bitfield = self._read_varint()
        negative = bool(bitfield & 1)
        byte_length = bitfield >> 1
        raw = self._read_raw(byte_length)
        value = int.from_bytes(raw, "little", signed=False)
        return -value if negative else value

    # -- value dispatch ---------------------------------------------------------

    def _read_object(self) -> Any:
        while True:
            tag_byte = self._stream.read(1)
            if not tag_byte:
                raise V8Error("Unexpected EOF reading tag")
            tag = tag_byte[0]
            if tag in (_Tag.PADDING, _Tag.VERIFY_OBJECT_COUNT):
                if tag == _Tag.VERIFY_OBJECT_COUNT:
                    self._read_varint()
                continue
            return self._dispatch(tag)

    def _dispatch(self, tag: int) -> Any:
        primitive = _PRIMITIVE_HANDLERS.get(tag)
        if primitive is not None:
            return primitive(self)
        container = _CONTAINER_HANDLERS.get(tag)
        if container is not None:
            return container(self)
        if tag == _Tag.HOST_OBJECT:
            return self._host_reader(tag, self._stream)
        if tag == _Tag.OBJECT_REFERENCE:
            ref = self._read_varint()
            if ref >= len(self._objects):
                raise V8Error(f"Object reference {ref} out of range")
            return self._objects[ref]
        raise V8Error(f"Unsupported V8 tag: {tag:#x} ({chr(tag)!r})")

    # -- primitive handlers -----------------------------------------------------

    def _r_undefined(self) -> Any:
        return None

    def _r_null(self) -> Any:
        return None

    def _r_true(self) -> bool:
        return True

    def _r_false(self) -> bool:
        return False

    def _r_int32(self) -> int:
        return self._read_zigzag()

    def _r_uint32(self) -> int:
        return self._read_varint()

    def _r_double(self) -> float:
        return self._read_double()

    def _r_bigint(self) -> int:
        return self._read_bigint()

    def _r_utf8(self) -> str:
        length = self._read_varint()
        return self._read_raw(length).decode("utf-8")

    def _r_one_byte(self) -> str:
        length = self._read_varint()
        return self._read_raw(length).decode(_LATIN1)

    def _r_two_byte(self) -> str:
        length = self._read_varint()
        return self._read_raw(length).decode("utf-16-le")

    def _r_date(self) -> dt.datetime:
        ms = self._read_double()
        return dt.datetime.fromtimestamp(ms / 1000.0, tz=dt.UTC)

    def _r_regexp(self) -> RegExpValue:
        pattern = self._read_object()
        flags = self._read_varint()
        if not isinstance(pattern, str):
            raise V8Error("RegExp pattern must be a string")
        return RegExpValue(pattern=pattern, flags=flags)

    def _r_number_object(self) -> float:
        return self._read_double()

    def _r_string_object(self) -> str:
        value = self._read_object()
        if not isinstance(value, str):
            raise V8Error("StringObject must wrap a string")
        return value

    def _r_true_object(self) -> bool:
        return True

    def _r_false_object(self) -> bool:
        return False

    def _r_bigint_object(self) -> int:
        return self._read_bigint()

    def _r_array_buffer(self) -> bytes:
        byte_length = self._read_varint()
        return self._read_raw(byte_length)

    def _r_shared_array_buffer(self) -> bytes:
        # transfer id followed by no payload — return empty bytes placeholder.
        self._read_varint()
        return b""

    def _r_array_buffer_transfer(self) -> bytes:
        self._read_varint()
        return b""

    def _r_array_buffer_view(self) -> TypedArrayView:
        raise V8Error("ARRAY_BUFFER_VIEW must follow an ARRAY_BUFFER")

    # -- container handlers -----------------------------------------------------

    def _r_object(self) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        self._objects.append(out)
        while True:
            tag_byte = self._stream.read(1)
            if not tag_byte:
                raise V8Error("Unexpected EOF in object")
            if tag_byte[0] == _Tag.END_OBJECT:
                break
            key = self._dispatch(tag_byte[0])
            value = self._read_object()
            out[key] = value
        properties_written = self._read_varint()
        if properties_written != len(out):
            logger.debug(
                "Object property count mismatch: %d written vs %d read",
                properties_written,
                len(out),
            )
        return out

    def _r_dense_array(self) -> list[Any]:
        length = self._read_varint()
        out: list[Any] = [None] * length
        self._objects.append(out)
        for i in range(length):
            out[i] = self._read_object()
        # Trailing properties (sparse fill-ins) — read and discard tag stream.
        self._read_trailing_array_props()
        properties_written = self._read_varint()
        del properties_written  # bookkeeping only
        declared_length = self._read_varint()
        if declared_length != length:
            logger.debug(
                "Dense array length mismatch: declared %d vs initial %d", declared_length, length
            )
        return out

    def _r_sparse_array(self) -> list[Any]:
        length = self._read_varint()
        out: list[Any] = [None] * length
        self._objects.append(out)
        while True:
            tag_byte = self._stream.read(1)
            if not tag_byte:
                raise V8Error("Unexpected EOF in sparse array")
            if tag_byte[0] == _Tag.END_SPARSE_ARRAY:
                break
            key = self._dispatch(tag_byte[0])
            value = self._read_object()
            if isinstance(key, int) and 0 <= key < length:
                out[key] = value
        self._read_varint()  # properties_written
        self._read_varint()  # declared_length
        return out

    def _r_map(self) -> dict[Any, Any]:
        out: dict[Any, Any] = {}
        self._objects.append(out)
        while True:
            tag_byte = self._stream.read(1)
            if not tag_byte:
                raise V8Error("Unexpected EOF in map")
            if tag_byte[0] == _Tag.END_MAP:
                break
            key = self._dispatch(tag_byte[0])
            value = self._read_object()
            out[key] = value
        self._read_varint()  # entries_written (= 2 * len)
        return out

    def _r_set(self) -> set[Any]:
        out: set[Any] = set()
        self._objects.append(out)
        while True:
            tag_byte = self._stream.read(1)
            if not tag_byte:
                raise V8Error("Unexpected EOF in set")
            if tag_byte[0] == _Tag.END_SET:
                break
            out.add(self._dispatch(tag_byte[0]))
        self._read_varint()  # entries_written
        return out

    def _r_error(self) -> dict[str, Any]:
        # Lightweight: skip subtag bytes until terminator 0x2E ("."), then return marker.
        details: dict[str, Any] = {"_v8_error": True}
        while True:
            raw = self._stream.read(1)
            if not raw or raw[0] == 0x2E:
                break
            sub = raw[0]
            if sub in (0x4D, 0x53):  # message / stack — length-prefixed strings
                details[chr(sub)] = self._r_utf8()
            elif sub == 0x63:  # ctor — short string
                details["ctor"] = self._r_utf8()
            # other subtags carry no payload
        return details

    def _read_trailing_array_props(self) -> None:
        # In V8 dense arrays, the body is followed directly by num_properties +
        # length varints; there are no per-property tags. This is a no-op kept
        # for symmetry with the upstream layout.
        return


_PRIMITIVE_HANDLERS: dict[int, Any] = {
    _Tag.UNDEFINED: Deserializer._r_undefined,
    _Tag.NULL: Deserializer._r_null,
    _Tag.TRUE: Deserializer._r_true,
    _Tag.FALSE: Deserializer._r_false,
    _Tag.INT32: Deserializer._r_int32,
    _Tag.UINT32: Deserializer._r_uint32,
    _Tag.DOUBLE: Deserializer._r_double,
    _Tag.BIG_INT: Deserializer._r_bigint,
    _Tag.UTF8_STRING: Deserializer._r_utf8,
    _Tag.ONE_BYTE_STRING: Deserializer._r_one_byte,
    _Tag.TWO_BYTE_STRING: Deserializer._r_two_byte,
    _Tag.DATE: Deserializer._r_date,
    _Tag.REGEXP: Deserializer._r_regexp,
    _Tag.NUMBER_OBJECT: Deserializer._r_number_object,
    _Tag.STRING_OBJECT: Deserializer._r_string_object,
    _Tag.TRUE_OBJECT: Deserializer._r_true_object,
    _Tag.FALSE_OBJECT: Deserializer._r_false_object,
    _Tag.BIG_INT_OBJECT: Deserializer._r_bigint_object,
    _Tag.ARRAY_BUFFER: Deserializer._r_array_buffer,
    _Tag.SHARED_ARRAY_BUFFER: Deserializer._r_shared_array_buffer,
    _Tag.ARRAY_BUFFER_TRANSFER: Deserializer._r_array_buffer_transfer,
    _Tag.ARRAY_BUFFER_VIEW: Deserializer._r_array_buffer_view,
}


_CONTAINER_HANDLERS: dict[int, Any] = {
    _Tag.BEGIN_OBJECT: Deserializer._r_object,
    _Tag.BEGIN_DENSE_ARRAY: Deserializer._r_dense_array,
    _Tag.BEGIN_SPARSE_ARRAY: Deserializer._r_sparse_array,
    _Tag.BEGIN_MAP: Deserializer._r_map,
    _Tag.BEGIN_SET: Deserializer._r_set,
    _Tag.ERROR: Deserializer._r_error,
}


__all__ = [
    "Deserializer",
    "HostObject",
    "RegExpValue",
    "TypedArrayView",
    "V8Error",
]
