"""Table-driven policy decisions, plus rule-set coverage and reachability.

Every case asserts the matched rule_id, not merely the outcome: a rule that denies
for the wrong reason is a policy bug that an outcome-only assertion reads as working.
Cases also assert matched_taint, because it is the column that answers "which label
caused this false positive" and it is easy to silently widen.
"""

from __future__ import annotations

import itertools
import pathlib
from typing import Final

import pytest
import yaml

from warden.policy.decision import (
    ClassifiedTool,
    Decision,
    Outcome,
    ToolCallRequest,
    UnclassifiedTool,
    UnknownTool,
)
from warden.policy.engine import evaluate
from warden.policy.labels import Retrieved, TaintLabel, TaintSet, ToolOutput, UserInput
from warden.policy.rule_ids import (
    RULE_ID_DEFAULT_DENY,
    RULE_ID_UNCLASSIFIED_TOOL,
    RULE_ID_UNKNOWN_TOOL,
)
from warden.policy.schema import PolicyConfig

POLICY_PATH: Final = pathlib.Path(__file__).parent.parent / "policies" / "default.yaml"
CONFIG: Final = PolicyConfig.model_validate(
    yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
)
AGENT: Final = "demo-agent"

USER: Final = UserInput()
RETR: Final = Retrieved()
SEARCH: Final = ToolOutput(tool="search_docs")
READF: Final = ToolOutput(tool="read_file")
EMPTY: Final[TaintSet] = frozenset()


def classified(tool: str) -> ToolCallRequest:
    cls = CONFIG.classification[tool]
    return ToolCallRequest(
        tool=tool,
        agent=AGENT,
        resolution=ClassifiedTool(
            tool=tool, risk_level=cls.risk_level, side_effect=cls.side_effect
        ),
    )


def unclassified(tool: str) -> ToolCallRequest:
    return ToolCallRequest(
        tool=tool, agent=AGENT, resolution=UnclassifiedTool(tool=tool)
    )


def unknown(tool: str) -> ToolCallRequest:
    return ToolCallRequest(tool=tool, agent=AGENT, resolution=UnknownTool())


Case = tuple[str, ToolCallRequest, TaintSet, Outcome, str, TaintSet]

CASES: Final[list[Case]] = [
    # -- exfiltration: untrusted provenance reaching a tool that talks outward ------
    ("retrieved-into-email", classified("send_email"), frozenset({RETR}),
     Outcome.DENY, "exfil-via-external-comms", frozenset({RETR})),
    ("tool-output-into-http", classified("http_post"), frozenset({SEARCH}),
     Outcome.DENY, "exfil-via-external-comms", frozenset({SEARCH})),
    ("two-labels-both-attributed", classified("send_email"), frozenset({RETR, SEARCH}),
     Outcome.DENY, "exfil-via-external-comms", frozenset({RETR, SEARCH})),
    ("user-taint-alone-does-not-trigger-exfil-rule", classified("send_email"),
     frozenset({USER}), Outcome.DENY, RULE_ID_DEFAULT_DENY, EMPTY),

    # -- code execution ------------------------------------------------------------
    ("retrieved-into-shell", classified("run_shell"), frozenset({RETR}),
     Outcome.DENY, "tainted-code-exec", frozenset({RETR})),
    ("untainted-shell-still-escalates", classified("run_shell"), frozenset({USER}),
     Outcome.REQUIRE_APPROVAL, "critical-always-approves", EMPTY),
    ("credential-read-escalates", classified("read_secret"), EMPTY,
     Outcome.REQUIRE_APPROVAL, "critical-always-approves", EMPTY),

    # -- local write ---------------------------------------------------------------
    ("search-output-into-write-escalates", classified("write_file"), frozenset({SEARCH}),
     Outcome.REQUIRE_APPROVAL, "search-output-into-local-write", frozenset({SEARCH})),
    ("other-tool-output-into-write-denies", classified("write_file"), frozenset({READF}),
     Outcome.DENY, RULE_ID_DEFAULT_DENY, EMPTY),
    ("user-only-write-allowed", classified("write_file"), frozenset({USER}),
     Outcome.ALLOW, "untainted-local-write", EMPTY),

    # -- read only -----------------------------------------------------------------
    ("read-only-ignores-taint", classified("search_docs"), frozenset({RETR}),
     Outcome.ALLOW, "read-only-allow", EMPTY),

    # -- resolution failures: three distinct deny stories --------------------------
    ("tool-absent-from-registry", unknown("ghost_tool"), frozenset({USER}),
     Outcome.DENY, RULE_ID_UNKNOWN_TOOL, EMPTY),
    ("tool-in-registry-but-untriaged", unclassified("new_tool"), frozenset({USER}),
     Outcome.DENY, RULE_ID_UNCLASSIFIED_TOOL, EMPTY),

    # -- empty-set semantics: stated, not emergent ---------------------------------
    # any_of over frozenset() is False -> the exfil rule does not fire, falls through.
    ("empty-taint-any-of-is-false", classified("send_email"), EMPTY,
     Outcome.DENY, RULE_ID_DEFAULT_DENY, EMPTY),
    # none_of over frozenset() is True -> the untainted-write rule does fire.
    ("empty-taint-none-of-is-true", classified("write_file"), EMPTY,
     Outcome.ALLOW, "untainted-local-write", EMPTY),
]


@pytest.mark.parametrize(
    "name,request_,taint,outcome,rule_id,matched",
    CASES,
    ids=[c[0] for c in CASES],
)
def test_policy_decision(
    name: str,
    request_: ToolCallRequest,
    taint: TaintSet,
    outcome: Outcome,
    rule_id: str,
    matched: TaintSet,
) -> None:
    decision: Decision = evaluate(request_, taint, CONFIG)
    assert decision.rule_id == rule_id, f"{name}: wrong rule fired"
    assert decision.outcome is outcome, f"{name}: wrong outcome"
    assert decision.matched_taint == matched, f"{name}: wrong taint attribution"


def test_every_authored_rule_is_exercised() -> None:
    """A rule with no case is a rule nobody has checked does what it claims."""
    covered = {case[4] for case in CASES}
    missing = [rule.id for rule in CONFIG.rules if rule.id not in covered]
    assert not missing, f"rules with no table-driven case: {missing}"


def test_every_synthetic_rule_id_is_exercised() -> None:
    covered = {case[4] for case in CASES}
    synthetic = {RULE_ID_UNKNOWN_TOOL, RULE_ID_UNCLASSIFIED_TOOL, RULE_ID_DEFAULT_DENY}
    assert synthetic <= covered, f"uncovered synthetic ids: {synthetic - covered}"


LABEL_UNIVERSE: Final[tuple[TaintLabel, ...]] = (USER, RETR, SEARCH, READF)


def _all_taint_sets() -> list[TaintSet]:
    sets: list[TaintSet] = []
    for size in range(len(LABEL_UNIVERSE) + 1):
        for combo in itertools.combinations(LABEL_UNIVERSE, size):
            sets.append(frozenset(combo))
    return sets


def _sweep() -> set[str]:
    """Every (classified tool x taint subset) input, and which rule each one hits."""
    reached: set[str] = set()
    for tool in CONFIG.classification:
        for taint in _all_taint_sets():
            reached.add(evaluate(classified(tool), taint, CONFIG).rule_id)
    return reached


def test_no_rule_is_shadowed() -> None:
    """First-match-wins lets a broad rule silently swallow a narrower one below it.

    A rule that can never fire is a policy bug that reads as working code.
    """
    reached = _sweep()
    unreachable = [rule.id for rule in CONFIG.rules if rule.id not in reached]
    assert not unreachable, f"rules unreachable given the rules above them: {unreachable}"


def test_default_deny_is_reachable() -> None:
    """If authored rules covered every input, default-deny would be dead code and
    its report row would read 0 for reasons that have nothing to do with security."""
    assert RULE_ID_DEFAULT_DENY in _sweep()


def test_evaluation_is_deterministic() -> None:
    for tool in CONFIG.classification:
        for taint in _all_taint_sets():
            first = evaluate(classified(tool), taint, CONFIG)
            second = evaluate(classified(tool), taint, CONFIG)
            assert first == second
