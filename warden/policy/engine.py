"""First-match-wins policy matcher.

evaluate() is pure: no clock, no database, no network, no filesystem. It raises
nothing for any well-typed input, because every branch terminates in a Decision.
Errors during *input resolution* -- registry lookup, taint resolution, schema fetch --
are the gateway wrapper's concern, and the wrapper maps them through the per-risk-level
fail-mode map. Nothing in this module knows fail modes exist.

Rules are tried in file order. The first whose every stated predicate holds decides
the call. A synthetic default-deny terminates the list, so every path returns a
Decision carrying exactly one rule_id.
"""

from __future__ import annotations

from warden.policy.decision import (
    ClassifiedTool,
    Decision,
    Outcome,
    ToolCallRequest,
    UnclassifiedTool,
    UnknownTool,
)
from warden.policy.labels import TaintSet
from warden.policy.rule_ids import (
    RULE_ID_DEFAULT_DENY,
    RULE_ID_UNCLASSIFIED_TOOL,
    RULE_ID_UNKNOWN_TOOL,
)
from warden.policy.schema import Match, PolicyConfig


def _match(
    match: Match,
    request: ToolCallRequest,
    resolved: ClassifiedTool,
    taint: TaintSet,
) -> TaintSet | None:
    """None when the rule does not apply; otherwise the labels that triggered it.

    Returning the matched labels rather than a bool keeps the definition of
    matched_taint in one place. Recomputing it in the caller would let the two drift.

    A rule with no argument_taint clause matches on tool/agent/side-effect/risk alone
    and attributes no labels, which is the honest answer: no taint caused it.
    """
    if match.tool is not None and request.tool not in match.tool:
        return None
    if match.agent is not None and request.agent not in match.agent:
        return None
    if match.side_effect is not None and resolved.side_effect not in match.side_effect:
        return None
    if match.risk_level is not None and resolved.risk_level not in match.risk_level:
        return None
    if match.argument_taint is not None:
        if not match.argument_taint.holds(taint):
            return None
        return match.argument_taint.matched(taint)
    return frozenset()


def evaluate(
    request: ToolCallRequest, taint: TaintSet, config: PolicyConfig
) -> Decision:
    """Authorize one tool call. Total over well-typed inputs; never raises."""
    resolved = request.resolution

    if isinstance(resolved, UnknownTool):
        return Decision(outcome=Outcome.DENY, rule_id=RULE_ID_UNKNOWN_TOOL)

    if isinstance(resolved, UnclassifiedTool):
        return Decision(outcome=Outcome.DENY, rule_id=RULE_ID_UNCLASSIFIED_TOOL)

    for rule in config.rules:
        matched = _match(rule.match, request, resolved, taint)
        if matched is not None:
            return Decision(
                outcome=rule.outcome,
                rule_id=rule.id,
                risk_level=resolved.risk_level,
                side_effect=resolved.side_effect,
                matched_taint=matched,
            )

    return Decision(
        outcome=Outcome.DENY,
        rule_id=RULE_ID_DEFAULT_DENY,
        risk_level=resolved.risk_level,
        side_effect=resolved.side_effect,
    )
