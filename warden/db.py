"""Single entry point for opening the Warden database.

The call log and the tool registry share one SQLite file. Both are created on open,
idempotently, so there is no ordering requirement between them.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from warden.log.schema import init_db
from warden.registry.schema import init_registry


def open_db(path: str | Path) -> sqlite3.Connection:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    init_registry(conn)
    return conn
