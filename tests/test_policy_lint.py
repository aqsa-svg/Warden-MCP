"""Rule-set lint: high-consequence rules must predicate on every untrusted provenance.

The reachability test cannot catch a *widening* edit. Dropping RETRIEVED from a deny
rule's any_of leaves the rule reachable and the call still denied -- by default-deny,
one rule lower -- so nothing structural notices. This lint does.

It is a check over the rule set, not new predicate vocabulary. A rule that genuinely
needs only one provenance opts out with an explicit `# lint: allow-partial-taint`
comment inside its block, so the omission is a visible decision rather than a typo.
"""

from __future__ import annotations

import pathlib
import re
from typing import Final

import yaml

from warden.policy.decision import SideEffect
from warden.policy.schema import PolicyConfig, Rule

POLICY_PATH: Final = pathlib.Path(__file__).parent.parent / "policies" / "default.yaml"

GUARDED_SIDE_EFFECTS: Final[frozenset[SideEffect]] = frozenset(
    {
        SideEffect.EXTERNAL_COMMS,
        SideEffect.CODE_EXEC,
        SideEffect.CREDENTIAL_ACCESS,
        SideEffect.DESTRUCTIVE,
    }
)
"""Side effects whose rules must name every untrusted provenance. LOCAL_WRITE is
excluded: a narrow rule such as search-output-into-local-write is a legitimate
single-provenance rule, not an omission."""

UNTRUSTED_KINDS: Final[frozenset[str]] = frozenset({"RETRIEVED", "TOOL_OUTPUT"})
OPT_OUT_MARKER: Final = "lint: allow-partial-taint"

_RULE_ID_LINE: Final = re.compile(r"^\s*-\s+id:\s*(\S+)")


def opt_outs(policy_text: str) -> frozenset[str]:
    """Rule ids whose YAML block carries the opt-out comment.

    Comments do not survive yaml.safe_load, so this scans the raw text. A marker is
    attributed to the most recent `- id:` line above it, i.e. it must sit inside the
    block of the rule it exempts.
    """
    found: set[str] = set()
    current: str | None = None
    for line in policy_text.splitlines():
        match = _RULE_ID_LINE.match(line)
        if match:
            current = match.group(1)
        if current is not None and OPT_OUT_MARKER in line:
            found.add(current)
    return frozenset(found)


def predicated_kinds(rule: Rule) -> frozenset[str]:
    """Every taint kind the rule mentions, in either clause."""
    predicate = rule.match.argument_taint
    if predicate is None:
        return frozenset()
    clauses = (predicate.any_of or ()) + (predicate.none_of or ())
    return frozenset(pattern.kind for pattern in clauses)


def partial_taint_violations(
    config: PolicyConfig, exempt: frozenset[str]
) -> list[str]:
    violations: list[str] = []
    for rule in config.rules:
        if rule.id in exempt:
            continue
        guarded = frozenset(rule.match.side_effect or ()) & GUARDED_SIDE_EFFECTS
        if not guarded:
            continue
        missing = UNTRUSTED_KINDS - predicated_kinds(rule)
        if missing:
            violations.append(
                f"{rule.id} guards {sorted(s.value for s in guarded)} "
                f"but does not predicate on {sorted(missing)}"
            )
    return violations


def test_shipped_policy_has_no_partial_taint_rules() -> None:
    text = POLICY_PATH.read_text(encoding="utf-8")
    config = PolicyConfig.model_validate(yaml.safe_load(text))
    assert not partial_taint_violations(config, opt_outs(text))


def test_lint_catches_the_widening_edit() -> None:
    """The mut3 mutation: RETRIEVED dropped from the exfil rule's any_of.

    A lint that cannot fail is worthless, so this asserts it fails on the exact edit
    that the reachability test and an outcome-only table both miss.
    """
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    rule = next(r for r in raw["rules"] if r["id"] == "exfil-via-external-comms")
    clause = rule["match"]["argument_taint"]["any_of"]
    rule["match"]["argument_taint"]["any_of"] = [
        p for p in clause if p["kind"] != "RETRIEVED"
    ]
    violations = partial_taint_violations(
        PolicyConfig.model_validate(raw), frozenset()
    )
    assert violations == [
        "exfil-via-external-comms guards ['EXTERNAL_COMMS'] "
        "but does not predicate on ['RETRIEVED']"
    ]


def test_opt_out_marker_suppresses_the_violation() -> None:
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    rule = next(r for r in raw["rules"] if r["id"] == "exfil-via-external-comms")
    clause = rule["match"]["argument_taint"]["any_of"]
    rule["match"]["argument_taint"]["any_of"] = [
        p for p in clause if p["kind"] != "RETRIEVED"
    ]
    config = PolicyConfig.model_validate(raw)
    assert partial_taint_violations(config, frozenset({"exfil-via-external-comms"})) == []


def test_opt_out_marker_is_scoped_to_its_own_rule_block() -> None:
    """A marker inside one rule must not exempt the rule below it."""
    text = (
        "rules:\n"
        "  - id: first-rule  # lint: allow-partial-taint\n"
        "    match: {tool: [a]}\n"
        "    outcome: DENY\n"
        "  - id: second-rule\n"
        "    match: {tool: [b]}\n"
        "    outcome: DENY\n"
    )
    assert opt_outs(text) == frozenset({"first-rule"})
