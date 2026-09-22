"""Clean knowledge-base corpus loader.

The articles live in data/kb.json rather than inline, so the corpus is editable as
data and this module stays small. Content is deliberately large and overlapping: a
poisoned document has to compete for the top 5 against the support vocabulary the
scenarios actually use, and against a small corpus that gate says nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

DATA_PATH: Final = Path(__file__).parent / "data" / "kb.json"


def _load() -> tuple[tuple[str, str, str], ...]:
    parsed: Any = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    return tuple(
        (str(row["title"]), str(row["body"]), ",".join(row["tags"]))
        for row in parsed
    )


_ROWS: Final[tuple[tuple[str, str, str], ...]] = _load()


def clean_titles() -> tuple[str, ...]:
    return tuple(row[0] for row in _ROWS)


def clean_rows() -> tuple[tuple[str, str, str], ...]:
    """(title, body, comma-separated tags). Ids are assigned by the loader."""
    return _ROWS
