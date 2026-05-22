"""Chromium-flavoured LevelDB reader.

Reads ``.ldb``/``.sst`` (sorted table) and ``.log`` (write-ahead) files as
produced by Chromium. Decompresses Snappy blocks, walks the index, and yields
:class:`Record` objects with the full user key, value, and provenance.

Derived in spirit from ``ccl_chromium_reader/storage_formats/ccl_leveldb.py``
by CCL Forensics (MIT, Copyright 2020-2021). Reimplemented for Python 3.11+
with dataclasses, ``pathlib``, and stdlib-only dependencies.

References:
- https://github.com/google/leveldb/blob/master/doc/table_format.md
- https://github.com/google/leveldb/blob/master/doc/log_format.md
"""

from __future__ import annotations

import dataclasses
import enum
import io
import logging
import re
import struct
from collections.abc import Iterator
from pathlib import Path
from types import MappingProxyType, TracebackType
from typing import BinaryIO, Self

from chromium_reader import _snappy

logger = logging.getLogger(__name__)

# Multi-line verbose regexes per project convention.
_DATA_FILE_PATTERN = re.compile(
    r"""(?x)
    ^[0-9]{6}        # six-digit file number
    \.(?P<ext>ldb|log|sst)
    $
    """
)

_MANIFEST_FILENAME_PATTERN = re.compile(
    r"""(?x)
    ^MANIFEST-
    (?P<num>[0-9A-Fa-f]{6})  # six hex digit manifest sequence
    $
    """
)


class FileType(enum.Enum):
    LDB = 1
    LOG = 2


class KeyState(enum.Enum):
    DELETED = 0
    LIVE = 1
    UNKNOWN = 2


class LogEntryType(enum.IntEnum):
    ZERO = 0
    FULL = 1
    FIRST = 2
    MIDDLE = 3
    LAST = 4


def _read_le_varint(stream: BinaryIO, *, is_32bit: bool = False) -> int | None:
    """Read an unsigned little-endian varint; returns None at EOF.

    Args:
        stream: any seekable binary stream.
        is_32bit: cap the varint at 5 bytes (used by leveldb's 32-bit varints).
    """
    limit = 5 if is_32bit else 10
    result = 0
    for i in range(limit):
        raw = stream.read(1)
        if not raw:
            return None
        b = raw[0]
        result |= (b & 0x7F) << (i * 7)
        if (b & 0x80) == 0:
            return result
    raise ValueError("Varint exceeded length cap")


def _read_length_prefixed(stream: BinaryIO) -> bytes:
    length = _read_le_varint(stream)
    if length is None:
        raise ValueError("Truncated length prefix")
    data = stream.read(length)
    if len(data) != length:
        raise ValueError(f"Truncated payload: expected {length}, got {len(data)}")
    return data


@dataclasses.dataclass(frozen=True, slots=True)
class BlockHandle:
    """Offset + length pointing at a Block in a table file."""

    offset: int
    length: int

    @classmethod
    def from_stream(cls, stream: BinaryIO) -> Self:
        offset = _read_le_varint(stream)
        length = _read_le_varint(stream)
        if offset is None or length is None:
            raise ValueError("Truncated block handle")
        return cls(offset, length)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        return cls.from_stream(io.BytesIO(data))


@dataclasses.dataclass(frozen=True, slots=True)
class RawBlockEntry:
    """A (key, value) entry within a Block, with its in-block offset."""

    key: bytes
    value: bytes
    block_offset: int


@dataclasses.dataclass(frozen=True, slots=True)
class Record:
    """A single key/value pair recovered from any leveldb file."""

    key: bytes
    value: bytes
    seq: int
    state: KeyState
    file_type: FileType
    origin_file: Path
    offset: int
    was_compressed: bool

    @property
    def user_key(self) -> bytes:
        """Strip the 8-byte (seq, type) trailer present on ldb-table keys."""
        if self.file_type == FileType.LDB and len(self.key) >= 8:
            return self.key[:-8]
        return self.key

    @classmethod
    def ldb_record(
        cls,
        key: bytes,
        value: bytes,
        origin: Path,
        offset: int,
        was_compressed: bool,
    ) -> Self:
        seq = struct.unpack("<Q", key[-8:])[0] >> 8
        if len(key) > 8:
            state = KeyState.DELETED if key[-8] == 0 else KeyState.LIVE
        else:
            state = KeyState.UNKNOWN
        return cls(key, value, seq, state, FileType.LDB, origin, offset, was_compressed)

    @classmethod
    def log_record(
        cls,
        key: bytes,
        value: bytes,
        seq: int,
        state: KeyState,
        origin: Path,
        offset: int,
    ) -> Self:
        return cls(key, value, seq, state, FileType.LOG, origin, offset, False)


class _Block:
    """In-memory representation of a leveldb table block (post-decompression)."""

    def __init__(self, raw: bytes, *, was_compressed: bool, origin: LdbFile, offset: int) -> None:
        self._raw = raw
        self.was_compressed = was_compressed
        self.origin = origin
        self.offset = offset
        self._restart_count = struct.unpack("<I", raw[-4:])[0]
        self._restart_offset = len(raw) - (self._restart_count + 1) * 4

    def _first_entry_offset(self) -> int:
        return struct.unpack("<i", self._raw[self._restart_offset : self._restart_offset + 4])[0]

    def __iter__(self) -> Iterator[RawBlockEntry]:
        buf = io.BytesIO(self._raw)
        buf.seek(self._first_entry_offset())
        key = b""
        while buf.tell() < self._restart_offset:
            start_offset = buf.tell()
            shared = _read_le_varint(buf, is_32bit=True)
            non_shared = _read_le_varint(buf, is_32bit=True)
            value_len = _read_le_varint(buf, is_32bit=True)
            if shared is None or non_shared is None or value_len is None:
                raise ValueError("Truncated block entry header")
            if shared > len(key):
                raise ValueError("Shared key length exceeds previous key")
            key = key[:shared] + buf.read(non_shared)
            value = buf.read(value_len)
            yield RawBlockEntry(key, value, start_offset)


class LdbFile:
    """A leveldb sorted-table file (``.ldb`` / ``.sst``)."""

    BLOCK_TRAILER_SIZE = 5
    FOOTER_SIZE = 48
    MAGIC = 0xDB4775248B80FB57

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(path)
        self.path = path
        self.file_no = int(path.stem, 16)
        self._f: BinaryIO = path.open("rb")

        self._f.seek(-LdbFile.FOOTER_SIZE, io.SEEK_END)
        self._meta_index_handle = BlockHandle.from_stream(self._f)
        self._index_handle = BlockHandle.from_stream(self._f)
        self._f.seek(-8, io.SEEK_END)
        magic = struct.unpack("<Q", self._f.read(8))[0]
        if magic != LdbFile.MAGIC:
            raise ValueError(f"Bad magic in {path}: {magic:#x}")
        self._index = self._load_index()

    def _read_block(self, handle: BlockHandle) -> _Block:
        self._f.seek(handle.offset)
        raw = self._f.read(handle.length)
        trailer = self._f.read(LdbFile.BLOCK_TRAILER_SIZE)
        if len(raw) != handle.length or len(trailer) != LdbFile.BLOCK_TRAILER_SIZE:
            raise ValueError(f"Truncated block at offset {handle.offset} of {self.path}")
        compressed = trailer[0] != 0
        if compressed:
            raw = _snappy.decompress(raw)
        return _Block(raw, was_compressed=compressed, origin=self, offset=handle.offset)

    def _load_index(self) -> tuple[tuple[bytes, BlockHandle], ...]:
        block = self._read_block(self._index_handle)
        return tuple((entry.key, BlockHandle.from_bytes(entry.value)) for entry in block)

    def __iter__(self) -> Iterator[Record]:
        for _block_key, handle in self._index:
            block = self._read_block(handle)
            for entry in block:
                yield Record.ldb_record(
                    entry.key,
                    entry.value,
                    self.path,
                    block.offset if block.was_compressed else block.offset + entry.block_offset,
                    block.was_compressed,
                )

    def close(self) -> None:
        self._f.close()


def _iter_log_blocks(stream: BinaryIO, path: Path) -> Iterator[tuple[int, bytes]]:
    """Yield (batch_offset, batch_bytes) reassembled across leveldb log blocks."""
    block_size = LogFile.LOG_BLOCK_SIZE
    in_record = False
    batch = b""
    start_offset = 0
    stream.seek(0)
    idx = 0
    while chunk := stream.read(block_size):
        with io.BytesIO(chunk) as buf:
            while buf.tell() < block_size - 6:
                header = buf.read(7)
                if len(header) < 7:
                    break
                _crc, length, btype = struct.unpack("<IHB", header)
                pos_in_log = idx * block_size + buf.tell()
                data = buf.read(length)
                if btype == LogEntryType.FULL:
                    if in_record:
                        raise ValueError(f"FULL inside open record at {pos_in_log} in {path}")
                    yield pos_in_log, data
                elif btype == LogEntryType.FIRST:
                    if in_record:
                        raise ValueError(f"FIRST inside open record at {pos_in_log} in {path}")
                    start_offset = pos_in_log
                    batch = data
                    in_record = True
                elif btype == LogEntryType.MIDDLE:
                    if not in_record:
                        raise ValueError(f"MIDDLE outside record at {pos_in_log} in {path}")
                    batch += data
                elif btype == LogEntryType.LAST:
                    if not in_record:
                        raise ValueError(f"LAST outside record at {pos_in_log} in {path}")
                    batch += data
                    in_record = False
                    yield start_offset, batch
                elif btype == LogEntryType.ZERO:
                    # Padding/zero record — skip remainder of this block.
                    break
                else:
                    raise ValueError(f"Unknown log entry type {btype} at {pos_in_log}")
        idx += 1


class LogFile:
    """A leveldb write-ahead log (``.log``) file."""

    LOG_BLOCK_SIZE = 32768

    def __init__(self, path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(path)
        self.path = path
        self.file_no = int(path.stem, 16)
        self._f: BinaryIO = path.open("rb")

    def __iter__(self) -> Iterator[Record]:
        for batch_offset, batch in _iter_log_blocks(self._f, self.path):
            buf = io.BytesIO(batch)
            header = buf.read(12)
            if len(header) < 12:
                continue
            seq, count = struct.unpack("<QI", header)
            for i in range(count):
                rec_offset = batch_offset + buf.tell()
                state_byte = buf.read(1)
                if not state_byte:
                    break
                state = KeyState(state_byte[0])
                key_len = _read_le_varint(buf, is_32bit=True)
                if key_len is None:
                    break
                key = buf.read(key_len)
                if state != KeyState.DELETED:
                    val_len = _read_le_varint(buf, is_32bit=True)
                    if val_len is None:
                        break
                    value = buf.read(val_len)
                else:
                    value = b""
                yield Record.log_record(key, value, seq + i, state, self.path, rec_offset)

    def close(self) -> None:
        self._f.close()


class _VersionEditTag(enum.IntEnum):
    COMPARATOR = 1
    LOG_NUMBER = 2
    NEXT_FILE_NUMBER = 3
    LAST_SEQUENCE = 4
    COMPACT_POINTER = 5
    DELETED_FILE = 6
    NEW_FILE = 7
    PREV_LOG_NUMBER = 9


@dataclasses.dataclass(frozen=True, slots=True)
class NewFileEntry:
    level: int
    file_no: int
    file_size: int
    smallest_key: bytes
    largest_key: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class VersionEdit:
    """Parsed VersionEdit record from a MANIFEST file."""

    comparator: str | None = None
    log_number: int | None = None
    prev_log_number: int | None = None
    last_sequence: int | None = None
    next_file_number: int | None = None
    new_files: tuple[NewFileEntry, ...] = ()
    deleted_files: tuple[tuple[int, int], ...] = ()

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Self:
        parsed = _ManifestParser(buffer).parse()
        return cls(**parsed)


class _ManifestParser:
    """Parse the body of a single VersionEdit record from a MANIFEST file.

    The leveldb VersionEdit format is a flat stream of (tag, payload) pairs
    terminated by EOF. Keeping each tag in its own handler keeps the dispatch
    loop inside the complexity cap.
    """

    def __init__(self, buffer: bytes) -> None:
        self._buf = io.BytesIO(buffer)
        self._len = len(buffer)
        self.comparator: str | None = None
        self.log_number: int | None = None
        self.prev_log_number: int | None = None
        self.last_sequence: int | None = None
        self.next_file_number: int | None = None
        self.new_files: list[NewFileEntry] = []
        self.deleted_files: list[tuple[int, int]] = []

    def parse(self) -> dict[str, object]:
        handlers = {
            _VersionEditTag.COMPARATOR: self._h_comparator,
            _VersionEditTag.LOG_NUMBER: self._h_log_number,
            _VersionEditTag.PREV_LOG_NUMBER: self._h_prev_log_number,
            _VersionEditTag.NEXT_FILE_NUMBER: self._h_next_file_number,
            _VersionEditTag.LAST_SEQUENCE: self._h_last_sequence,
            _VersionEditTag.COMPACT_POINTER: self._h_compact_pointer,
            _VersionEditTag.DELETED_FILE: self._h_deleted_file,
            _VersionEditTag.NEW_FILE: self._h_new_file,
        }
        while self._buf.tell() < self._len - 1:
            tag = _read_le_varint(self._buf, is_32bit=True)
            if tag is None:
                break
            try:
                edit_tag = _VersionEditTag(tag)
            except ValueError:
                break
            handler = handlers.get(edit_tag)
            if handler is None:
                break
            handler()
        return {
            "comparator": self.comparator,
            "log_number": self.log_number,
            "prev_log_number": self.prev_log_number,
            "last_sequence": self.last_sequence,
            "next_file_number": self.next_file_number,
            "new_files": tuple(self.new_files),
            "deleted_files": tuple(self.deleted_files),
        }

    def _h_comparator(self) -> None:
        self.comparator = _read_length_prefixed(self._buf).decode("utf-8")

    def _h_log_number(self) -> None:
        self.log_number = _read_le_varint(self._buf)

    def _h_prev_log_number(self) -> None:
        self.prev_log_number = _read_le_varint(self._buf)

    def _h_next_file_number(self) -> None:
        self.next_file_number = _read_le_varint(self._buf)

    def _h_last_sequence(self) -> None:
        self.last_sequence = _read_le_varint(self._buf)

    def _h_compact_pointer(self) -> None:
        _read_le_varint(self._buf, is_32bit=True)
        _read_length_prefixed(self._buf)

    def _h_deleted_file(self) -> None:
        level = _read_le_varint(self._buf, is_32bit=True)
        file_no = _read_le_varint(self._buf)
        if level is None or file_no is None:
            return
        self.deleted_files.append((level, file_no))

    def _h_new_file(self) -> None:
        level = _read_le_varint(self._buf, is_32bit=True)
        file_no = _read_le_varint(self._buf)
        file_size = _read_le_varint(self._buf)
        if level is None or file_no is None or file_size is None:
            return
        smallest = _read_length_prefixed(self._buf)
        largest = _read_length_prefixed(self._buf)
        self.new_files.append(NewFileEntry(level, file_no, file_size, smallest, largest))


class ManifestFile:
    """A leveldb MANIFEST file. Maps file numbers to their level."""

    def __init__(self, path: Path) -> None:
        match = _MANIFEST_FILENAME_PATTERN.match(path.name)
        if not match:
            raise ValueError(f"Not a MANIFEST file: {path.name}")
        self.file_no = int(match.group("num"), 16)
        self.path = path
        self._f: BinaryIO = path.open("rb")
        levels: dict[int, int] = {}
        for edit in self:
            for nf in edit.new_files:
                levels[nf.file_no] = nf.level
        self.file_to_level: MappingProxyType[int, int] = MappingProxyType(levels)

    def __iter__(self) -> Iterator[VersionEdit]:
        for _offset, batch in _iter_log_blocks(self._f, self.path):
            yield VersionEdit.from_buffer(batch)

    def close(self) -> None:
        self._f.close()


class RawLevelDb:
    """A whole Chromium-flavoured leveldb directory.

    Use as a context manager:

        with RawLevelDb(path) as db:
            for rec in db.iterate_records_raw():
                ...
    """

    def __init__(self, in_dir: Path | str) -> None:
        self._in_dir = Path(in_dir)
        if not self._in_dir.is_dir():
            raise ValueError(f"{self._in_dir} is not a directory")

        self._files: list[LdbFile | LogFile] = []
        latest_manifest: tuple[int, Path | None] = (-1, None)
        for entry in self._in_dir.iterdir():
            if not entry.is_file():
                continue
            data_match = _DATA_FILE_PATTERN.match(entry.name)
            if data_match:
                ext = data_match.group("ext").lower()
                if ext == "log":
                    self._files.append(LogFile(entry))
                else:
                    self._files.append(LdbFile(entry))
                continue
            man_match = _MANIFEST_FILENAME_PATTERN.match(entry.name)
            if man_match:
                num = int(man_match.group("num"), 16)
                if num > latest_manifest[0]:
                    latest_manifest = (num, entry)

        self.manifest: ManifestFile | None = (
            ManifestFile(latest_manifest[1]) if latest_manifest[1] else None
        )

    @property
    def in_dir_path(self) -> Path:
        return self._in_dir

    def iterate_records_raw(self, *, reverse: bool = False) -> Iterator[Record]:
        for file in sorted(self._files, key=lambda f: f.file_no, reverse=reverse):
            yield from file

    def close(self) -> None:
        for f in self._files:
            f.close()
        if self.manifest:
            self.manifest.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = [
    "BlockHandle",
    "FileType",
    "KeyState",
    "LdbFile",
    "LogFile",
    "ManifestFile",
    "NewFileEntry",
    "RawBlockEntry",
    "RawLevelDb",
    "Record",
    "VersionEdit",
]
