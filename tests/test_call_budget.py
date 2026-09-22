"""Per-run call budget: a blunt damage-cap, verified as a pure decision.

The budget does not detect the excessive-calls attack -- it bounds it. These tests
pin that it trips at the cap, ignores taint and tool identity, and yields to the
stronger resolution signals (unknown/unclassified) rather than masking them.
"""

from __future__ import annotations

import yaml

from warden.gateway.wrapper import budget_decision
from warden.policy.decision import (
    ClassifiedTool,
    Outcome,
    RiskLevel,
    SideEffect,
    ToolCallRequest,
    UnknownTool,
)
from warden.policy.rule_ids import RULE_ID_BUDGET_EXCEEDED
from warden.policy.schema import PolicyConfig

POLICY = PolicyConfig.model_validate(
    yaml.safe_load(open("policies/demo.yaml", encoding="utf-8"))
)
_cap = POLICY.budgets.max_calls_per_run
assert _cap is not None, "the demo policy must set a call budget for these tests"
CAP: int = _cap


def classified_request(tool: str = "search_docs") -> ToolCallRequest:
    c = POLICY.classification[tool]
    return ToolCallRequest(
        tool=tool, agent="a",
        resolution=ClassifiedTool(
            tool=tool, risk_level=c.risk_level, side_effect=c.side_effect
        ),
    )


def test_calls_below_the_cap_are_not_denied() -> None:
    for n in range(CAP):
        assert budget_decision(classified_request(), POLICY, n) is None


def test_the_call_at_the_cap_is_the_first_denied() -> None:
    """calls_so_far == cap means `cap` calls have already been made, so this one is
    the (cap+1)th and the first over budget."""
    decision = budget_decision(classified_request(), POLICY, CAP)
    assert decision is not None
    assert decision.outcome is Outcome.DENY
    assert decision.rule_id == RULE_ID_BUDGET_EXCEEDED


def test_denial_carries_the_tools_classification_for_the_log() -> None:
    decision = budget_decision(classified_request("send_email"), POLICY, CAP)
    assert decision is not None
    assert decision.risk_level is RiskLevel.HIGH
    assert decision.side_effect is SideEffect.EXTERNAL_COMMS


def test_budget_is_blind_to_taint_and_tool() -> None:
    """A blunt cap: read-only search over budget is denied just like a write would be.
    The read-only tool proves the cap ignores side effect."""
    decision = budget_decision(classified_request("search_docs"), POLICY, CAP + 5)
    assert decision is not None and decision.rule_id == RULE_ID_BUDGET_EXCEEDED


def test_no_budget_configured_never_denies() -> None:
    no_budget = POLICY.model_copy(
        update={"budgets": POLICY.budgets.model_copy(update={"max_calls_per_run": None})}
    )
    assert budget_decision(classified_request(), no_budget, 10_000) is None


def test_unknown_tool_over_budget_still_reports_no_classification() -> None:
    """An unknown tool has no risk level; a budget denial on it must not fabricate one.
    (In the full flow resolution_decision denies it first as unknown-tool; this checks
    the budget path alone stays honest about the absent classification.)"""
    request = ToolCallRequest(tool="ghost", agent="a", resolution=UnknownTool())
    decision = budget_decision(request, POLICY, CAP)
    assert decision is not None
    assert decision.risk_level is None and decision.side_effect is None
