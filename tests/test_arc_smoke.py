"""Browser smoke test against the user's Arc localStorage.

This test is marked ``requires_browser`` and skipped by default. Run with
``pytest -m requires_browser`` to execute.

It scans every Arc profile under ``~/Library/Application Support/Arc`` for
xoxc-prefixed Slack tokens. The token bytes are NEVER written to test output
or stored anywhere — only their lengths are asserted and reported.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from chromium_reader.localstorage import LocalStorageReader

ARC_BASE = Path.home() / "Library/Application Support/Arc/User Data"

pytestmark = pytest.mark.requires_browser


def _profile_leveldbs() -> list[Path]:
    candidates = [ARC_BASE / "Default", *sorted(ARC_BASE.glob("Profile *"))]
    return [
        ldb for profile in candidates if (ldb := profile / "Local Storage" / "leveldb").is_dir()
    ]


def test_arc_localstorage_yields_full_xoxc_token() -> None:
    profiles = _profile_leveldbs()
    if not profiles:
        pytest.skip("No Arc localStorage profiles found on this machine")

    total_token_count = 0
    max_token_length = 0

    for ldb in profiles:
        with LocalStorageReader(ldb) as reader:
            for record in reader.records():
                if not record.value or "xoxc-" not in record.value:
                    continue
                idx = record.value.find("xoxc-")
                tail = record.value[idx:]
                # A real xoxc token is ASCII; the closing delimiter in the
                # surrounding JSON/HTML is a quote.
                end = len(tail)
                for terminator in ('"', "\\", "'", "\n", " "):
                    pos = tail.find(terminator)
                    if pos != -1 and pos < end:
                        end = pos
                token_length = end
                total_token_count += 1
                max_token_length = max(max_token_length, token_length)

    if total_token_count == 0:
        pytest.skip("No xoxc tokens recoverable from local Arc profiles")

    # A full xoxc token is roughly xoxc- + 4 dash-separated segments of ~26 chars
    # each; the minimum truncated length we ever saw under buggy readers is ~35.
    assert max_token_length >= 90, (
        f"Recovered token max length is only {max_token_length} chars — "
        "likely truncated. Full xoxc tokens are 90+ chars."
    )
