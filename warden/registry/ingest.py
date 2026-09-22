"""tools/list ingestion.

Tool names are validated against the same charset used to construct taint labels, and
a failing name causes the tool to be REJECTED rather than sanitised. Sanitising would
mean two names for one tool and a mapping table, which is itself a forgery surface.

Newly accepted tools enter UNGOVERNED. Nothing here classifies a tool: the policy
file's classification block is authoritative, and an untriaged tool resolves to
unclassified-tool and denies.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Final, Iterable

from warden.policy.labels import TOOL_NAME_PATTERN
from warden.registry.models import (
    IngestResult,
    Rejection,
    RegisteredTool,
    ToolAdvertisement,
    ToolState,
    canonical_hash,
)

_NAME_RE: Final = re.compile(TOOL_NAME_PATTERN)
REJECT_BAD_NAME: Final = f"tool name does not match {TOOL_NAME_PATTERN}"


def ingest_tools(
    conn: sqlite3.Connection,
    server_name: str,
    advertised: Iterable[ToolAdvertisement],
    *,
    now_us: int,
) -> IngestResult:
    accepted: list[RegisteredTool] = []
    rejected: list[Rejection] = []
    drifted: list[str] = []

    for advert in advertised:
        if not _NAME_RE.match(advert.name):
            rejected.append(Rejection(server_name, advert.name, REJECT_BAD_NAME))
            conn.execute(
                "INSERT INTO tool_rejection (server_name, raw_name, reason, "
                "first_seen_us, last_seen_us) VALUES (?,?,?,?,?) "
                "ON CONFLICT(server_name, raw_name) DO UPDATE SET last_seen_us=?",
                (server_name, advert.name, REJECT_BAD_NAME, now_us, now_us, now_us),
            )
            continue

        schema_hash = canonical_hash(advert.input_schema)
        description_hash = canonical_hash(advert.description)
        previous = conn.execute(
            "SELECT schema_hash, description_hash, state FROM tool_registry "
            "WHERE server_name=? AND tool_name=?",
            (server_name, advert.name),
        ).fetchone()

        if previous is None:
            state = ToolState.UNGOVERNED
            conn.execute(
                "INSERT INTO tool_registry (server_name, tool_name, first_seen_us, "
                "last_seen_us, schema_hash, description_hash, state) "
                "VALUES (?,?,?,?,?,?,?)",
                (server_name, advert.name, now_us, now_us, schema_hash,
                 description_hash, state.value),
            )
        else:
            state = ToolState(previous[2])
            if (previous[0], previous[1]) != (schema_hash, description_hash):
                drifted.append(advert.name)
            conn.execute(
                "UPDATE tool_registry SET last_seen_us=?, schema_hash=?, "
                "description_hash=? WHERE server_name=? AND tool_name=?",
                (now_us, schema_hash, description_hash, server_name, advert.name),
            )

        accepted.append(
            RegisteredTool(server_name, advert.name, schema_hash, description_hash, state)
        )

    return IngestResult(tuple(accepted), tuple(rejected), tuple(drifted))
