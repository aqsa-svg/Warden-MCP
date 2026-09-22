"""Registry value types.

ToolAdvertisement is deliberately not an MCP type. The registry is testable without a
running server, and the MCP-shaped conversion happens once at the ingestion boundary.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, NamedTuple


class ToolState(StrEnum):
    """Whether a tool has been triaged into the policy's classification table.

    UNGOVERNED is the default for anything newly advertised. It is the registry's own
    vocabulary and unrelated to runs.variant, which uses the same two words for
    whether a run's decisions were enforced.
    """

    UNGOVERNED = "UNGOVERNED"
    GOVERNED = "GOVERNED"


class ToolAdvertisement(NamedTuple):
    """One entry as offered by an upstream server's tools/list."""

    name: str
    description: str
    input_schema: dict[str, Any]


class RegisteredTool(NamedTuple):
    server_name: str
    tool_name: str
    schema_hash: str
    description_hash: str
    state: ToolState


class Rejection(NamedTuple):
    server_name: str
    raw_name: str
    reason: str


class IngestResult(NamedTuple):
    accepted: tuple[RegisteredTool, ...]
    rejected: tuple[Rejection, ...]
    drifted: tuple[str, ...]
    """Tool names whose schema or description hash changed since last seen."""


def canonical_hash(payload: Any) -> str:
    """Stable sha256 over a JSON-serialisable value.

    sort_keys makes the hash independent of dict ordering, so a server that
    reserialises its schema does not read as drift.
    """
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
