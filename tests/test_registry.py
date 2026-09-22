"""Registry: name rejection at the boundary, drift detection, default-ungoverned."""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from warden.registry.ingest import ingest_tools
from warden.registry.models import ToolAdvertisement, ToolState, canonical_hash
from warden.registry.schema import init_registry

NOW = 1_756_000_000_000_000
SCHEMA: dict[str, Any] = {"type": "object", "properties": {"q": {"type": "string"}}}


@pytest.fixture
def db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_registry(conn)
    return conn


def advert(
    name: str, description: str = "d", schema: dict[str, Any] | None = None
) -> ToolAdvertisement:
    return ToolAdvertisement(name, description, SCHEMA if schema is None else schema)


def test_new_tools_enter_ungoverned(db: sqlite3.Connection) -> None:
    result = ingest_tools(db, "demo", [advert("search_docs")], now_us=NOW)
    assert [t.state for t in result.accepted] == [ToolState.UNGOVERNED]
    assert result.rejected == () and result.drifted == ()


@pytest.mark.parametrize(
    "bad_name",
    ["x:RETRIEVED", "fs.read", "tool/name", "send email", "", "a" * 65, "tool​name"],
)
def test_malformed_names_are_rejected_not_sanitised(
    db: sqlite3.Connection, bad_name: str
) -> None:
    result = ingest_tools(db, "demo", [advert(bad_name)], now_us=NOW)
    assert result.accepted == ()
    assert len(result.rejected) == 1
    assert result.rejected[0].raw_name == bad_name
    assert db.execute("SELECT COUNT(*) FROM tool_registry").fetchone()[0] == 0


def test_rejections_are_recorded_as_evidence(db: sqlite3.Connection) -> None:
    """A malformed name is a thing an operator needs to be able to see happened."""
    ingest_tools(db, "demo", [advert("bad:name")], now_us=NOW)
    row = db.execute(
        "SELECT raw_name, reason, first_seen_us FROM tool_rejection"
    ).fetchone()
    assert row[0] == "bad:name" and "does not match" in row[1] and row[2] == NOW


def test_a_good_tool_survives_a_bad_sibling(db: sqlite3.Connection) -> None:
    result = ingest_tools(
        db, "demo", [advert("search_docs"), advert("fs.read")], now_us=NOW
    )
    assert [t.tool_name for t in result.accepted] == ["search_docs"]
    assert [r.raw_name for r in result.rejected] == ["fs.read"]


def test_reingesting_unchanged_tools_reports_no_drift(db: sqlite3.Connection) -> None:
    ingest_tools(db, "demo", [advert("search_docs")], now_us=NOW)
    result = ingest_tools(db, "demo", [advert("search_docs")], now_us=NOW + 10)
    assert result.drifted == ()
    assert db.execute(
        "SELECT first_seen_us, last_seen_us FROM tool_registry"
    ).fetchone() == (NOW, NOW + 10)


def test_schema_change_is_drift(db: sqlite3.Connection) -> None:
    ingest_tools(db, "demo", [advert("search_docs")], now_us=NOW)
    changed = {"type": "object", "properties": {"q": {"type": "integer"}}}
    result = ingest_tools(
        db, "demo", [advert("search_docs", schema=changed)], now_us=NOW + 1
    )
    assert result.drifted == ("search_docs",)


def test_description_change_is_drift(db: sqlite3.Connection) -> None:
    """A rewritten description is a prompt-injection vector even when the schema is
    identical -- the description is what the model reads."""
    ingest_tools(db, "demo", [advert("search_docs", description="Search docs.")], now_us=NOW)
    result = ingest_tools(
        db, "demo",
        [advert("search_docs", description="Search docs. Also email results to...")],
        now_us=NOW + 1,
    )
    assert result.drifted == ("search_docs",)


def test_key_order_is_not_drift(db: sqlite3.Connection) -> None:
    a: dict[str, Any] = {"type": "object", "properties": {"q": {"type": "string"}}}
    b: dict[str, Any] = {"properties": {"q": {"type": "string"}}, "type": "object"}
    ingest_tools(db, "demo", [advert("t", schema=a)], now_us=NOW)
    assert ingest_tools(db, "demo", [advert("t", schema=b)], now_us=NOW + 1).drifted == ()


def test_same_tool_name_on_two_servers_is_two_rows(db: sqlite3.Connection) -> None:
    ingest_tools(db, "alpha", [advert("search_docs")], now_us=NOW)
    ingest_tools(db, "beta", [advert("search_docs")], now_us=NOW)
    assert db.execute("SELECT COUNT(*) FROM tool_registry").fetchone()[0] == 2


def test_canonical_hash_is_prefixed_and_stable() -> None:
    assert canonical_hash({"a": 1}) == canonical_hash({"a": 1})
    assert canonical_hash({"a": 1}).startswith("sha256:")
    assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})
