"""Shared utilities — generic key search predicates used across stores."""

from __future__ import annotations

import re
from collections.abc import Callable, Collection
from typing import TypeAlias

KeySearch: TypeAlias = str | re.Pattern[str] | Collection[str] | Callable[[str], bool]
"""A predicate over string keys.

May be:
- a literal string (exact match)
- a compiled regex (matched with :py:meth:`re.Pattern.search`)
- a collection of strings (membership test)
- a callable returning a bool
"""


def matches(search: KeySearch, value: str) -> bool:
    """Return True iff ``value`` satisfies the search predicate."""
    if isinstance(search, str):
        return value == search
    if isinstance(search, re.Pattern):
        return search.search(value) is not None
    if callable(search):
        return bool(search(value))
    if isinstance(search, Collection):
        return value in search
    raise TypeError(f"Unsupported KeySearch type: {type(search).__name__}")
