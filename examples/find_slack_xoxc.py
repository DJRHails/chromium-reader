"""Locate xoxc-prefixed Slack tokens in the local Arc browser localStorage.

The script prints structural information about each token (host, length,
segment lengths) but NEVER the token itself.

Usage:
    uv run examples/find_slack_xoxc.py
"""

from __future__ import annotations

import logging
from pathlib import Path

from chromium_reader.localstorage import LocalStorageReader

logging.basicConfig(level=logging.WARNING)

ARC_BASE = Path.home() / "Library/Application Support/Arc/User Data"
TERMINATORS = ('"', "\\", "'", "\n", " ")


def _token_length(value: str, start: int) -> int:
    tail = value[start:]
    end = len(tail)
    for terminator in TERMINATORS:
        pos = tail.find(terminator)
        if pos != -1 and pos < end:
            end = pos
    return end


def _scan_profile(ldb: Path) -> int:
    found = 0
    with LocalStorageReader(ldb) as reader:
        for record in reader.records():
            if not record.value or "xoxc-" not in record.value:
                continue
            idx = record.value.find("xoxc-")
            length = _token_length(record.value, idx)
            found += 1
            print(
                f"  host={record.storage_key} "
                f"script={record.script_key[:50]!r} "
                f"found xoxc-prefixed value of length {length}, masked"
            )
    return found


def main() -> None:
    profile_dirs = [ARC_BASE / "Default", *sorted(ARC_BASE.glob("Profile *"))]
    total = 0
    for profile in profile_dirs:
        ldb = profile / "Local Storage" / "leveldb"
        if not ldb.is_dir():
            continue
        print(f"=== {profile.name} ===")
        try:
            total += _scan_profile(ldb)
        except Exception as exc:
            print(f"  ERROR: {exc}")
    print(f"\nTotal xoxc-prefixed values across profiles: {total}")


if __name__ == "__main__":
    main()
