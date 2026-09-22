"""Canonical JSON for taint sets.

Structured JSON is the canonical form, never the `TOOL_OUTPUT:<tool>` display string:
a delimited string moves the forgery surface from the boundary into the log.

Ordering is deterministic so two rows carrying the same labels compare equal as text.
"""

from __future__ import annotations

import json
from typing import Any, Final

from pydantic import TypeAdapter

from warden.policy.labels import TaintLabel, TaintSet, ToolOutput

_ADAPTER: Final[TypeAdapter[frozenset[TaintLabel]]] = TypeAdapter(frozenset[TaintLabel])


def dump_taint(taint: TaintSet) -> str:
    rows: list[dict[str, str]] = []
    for label in taint:
        row: dict[str, str] = {"kind": label.kind}
        if isinstance(label, ToolOutput):
            row["tool"] = label.tool
        rows.append(row)
    rows.sort(key=lambda r: (r["kind"], r.get("tool", "")))
    return json.dumps(rows, separators=(",", ":"))


def load_taint(payload: str) -> TaintSet:
    parsed: Any = json.loads(payload)
    return _ADAPTER.validate_python(parsed)
