"""Registry tables. Same SQLite database as the call log."""

from __future__ import annotations

import sqlite3
from typing import Final

REGISTRY_DDL: Final = """
CREATE TABLE IF NOT EXISTS tool_registry (
  server_name          TEXT NOT NULL,
  tool_name            TEXT NOT NULL,
  first_seen_us        INTEGER NOT NULL,
  last_seen_us         INTEGER NOT NULL,
  schema_hash          TEXT NOT NULL,
  description_hash     TEXT NOT NULL,
  state                TEXT NOT NULL CHECK (state IN ('UNGOVERNED','GOVERNED')),
  PRIMARY KEY (server_name, tool_name)
);

-- A tool whose name fails validation is recorded, never silently dropped: evidence
-- that a server offered a malformed name is exactly what an operator needs to see.
CREATE TABLE IF NOT EXISTS tool_rejection (
  server_name  TEXT NOT NULL,
  raw_name     TEXT NOT NULL,
  reason       TEXT NOT NULL,
  first_seen_us INTEGER NOT NULL,
  last_seen_us  INTEGER NOT NULL,
  PRIMARY KEY (server_name, raw_name)
);
"""


def init_registry(conn: sqlite3.Connection) -> None:
    conn.executescript(REGISTRY_DDL)
    conn.commit()
