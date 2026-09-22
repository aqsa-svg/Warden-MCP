"""Rule id namespace.

Rule ids are append-only: they key report columns, so renaming one makes historical
logs uninterpretable. Authored ids and synthetic ids live in disjoint namespaces by
construction -- see AUTHORED_RULE_ID_PATTERN in schema.py -- so a policy author
cannot collide with a synthetic id even by accident. The explicit reserved set below
is defence in depth for the three bare ids, which contain no separator and so are
not excluded structurally.
"""

from typing import Final

RULE_ID_UNKNOWN_TOOL: Final = "unknown-tool"
RULE_ID_UNCLASSIFIED_TOOL: Final = "unclassified-tool"
RULE_ID_DEFAULT_DENY: Final = "default-deny"
RULE_ID_BUDGET_EXCEEDED: Final = "budget-exceeded"
"""A blunt per-run call-count cap tripped. Unlike the taint rules, this does not
detect the attack -- it caps damage once too many calls have been made. Reserved so an
author cannot mint it and so the report can separate damage-capping from detection."""

RULE_ID_NOT_EVALUATED: Final = "not-evaluated"
"""No policy ran. Week-1 transparent-proxy rows only; component 4 replaces it.
Reserved so an author cannot mint it, and so a report can filter these rows out of
any governed/ungoverned comparison rather than counting them as ALLOW decisions."""

RULE_ID_SCHEMA_DRIFT_ANNOUNCED: Final = "schema-drift-announced"
"""Upstream schema changed AND the server sent notifications/tools/list_changed.
A legitimate update; requires re-approval rather than refusal."""

RULE_ID_SCHEMA_DRIFT_SILENT: Final = "schema-drift-silent"
"""Upstream schema changed and the server never announced it. This is the rug-pull
signature: grading drift by whether it was announced is the actual detection."""

FAIL_OPEN_PREFIX: Final = "fail-open:"
FAIL_CLOSED_PREFIX: Final = "fail-closed:"

RESERVED_RULE_IDS: Final[frozenset[str]] = frozenset(
    {
        RULE_ID_UNKNOWN_TOOL,
        RULE_ID_UNCLASSIFIED_TOOL,
        RULE_ID_DEFAULT_DENY,
        RULE_ID_NOT_EVALUATED,
        RULE_ID_BUDGET_EXCEEDED,
        RULE_ID_SCHEMA_DRIFT_ANNOUNCED,
        RULE_ID_SCHEMA_DRIFT_SILENT,
    }
)
RESERVED_RULE_ID_PREFIXES: Final[tuple[str, ...]] = (FAIL_OPEN_PREFIX, FAIL_CLOSED_PREFIX)


def is_reserved_rule_id(rule_id: str) -> bool:
    """True if `rule_id` belongs to the synthetic namespace and may not be authored."""
    return rule_id in RESERVED_RULE_IDS or rule_id.startswith(RESERVED_RULE_ID_PREFIXES)
