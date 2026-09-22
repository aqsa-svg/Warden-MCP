"""The enforcement wrapper: the impure shell around a pure decision.

Ordering, fixed:

    registry lookup -> schema-drift check -> taint resolve -> evaluate -> [approval]
    -> args_hash -> write+commit decision row -> inject credentials -> forward
    -> result -> update row -> accumulate taint

Two properties this ordering exists to guarantee:

  * The audit row is durable BEFORE anything executes. If the process dies mid-forward
    the row survives with execution_outcome NULL, so a call that ran is never
    unrecorded. Audit integrity beats transactional tidiness.
  * args_hash is computed BEFORE credential injection. Hashing credential-bearing
    arguments would make the log secret-derived, and it would break determinism
    across credential rotation -- which would fail the replay-determinism test in a
    way that looks like flakiness rather than a bug.

Fail modes live here and nowhere else. evaluate() is pure and total over resolved
inputs; what can fail is the resolution of those inputs, which is this module's job.

There is exactly ONE place variant is consulted: enforce(). A shadow (UNGOVERNED) run
takes the identical path and logs the identical decision, and simply does not act on
it -- including when the decision came from a fail mode. `fail-closed:HIGH` recorded
against a call that then executed is correct: it is the "would have blocked" record.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Awaitable, Callable

from warden.errors import WardenError
from warden.log.models import ExecutionOutcome, RunVariant
from warden.policy.decision import (
    Decision,
    FailMode,
    Outcome,
    RiskLevel,
    ToolCallRequest,
    UnclassifiedTool,
    UnknownTool,
)
from warden.policy.engine import evaluate
from warden.policy.labels import TaintSet
from warden.policy.rule_ids import (
    FAIL_CLOSED_PREFIX,
    FAIL_OPEN_PREFIX,
    RULE_ID_BUDGET_EXCEEDED,
    RULE_ID_SCHEMA_DRIFT_ANNOUNCED,
    RULE_ID_SCHEMA_DRIFT_SILENT,
    RULE_ID_UNCLASSIFIED_TOOL,
    RULE_ID_UNKNOWN_TOOL,
)
from warden.policy.schema import PolicyConfig
from warden.gateway.drift import DriftFinding

UNKNOWN_RISK_LEVEL = RiskLevel.CRITICAL
"""A failure during registry lookup leaves the tool's risk level unknown, so the
fail-mode map cannot be keyed. Unknown is treated as CRITICAL and fails closed."""


def fail_mode_decision(
    risk_level: RiskLevel | None, config: PolicyConfig
) -> Decision:
    """Turn a failed check into a Decision that still carries a rule id.

    Two structural guards, not conventions:

      * A None risk level keys the map as CRITICAL. It never falls through to
        permissive.
      * ALLOW is refused above MEDIUM regardless of what the map says. The loader also
        rejects HIGH/CRITICAL = OPEN, but a hand-built FailModeMap in a test or a
        future call site would bypass that, and this is the one function in the system
        that converts an exception into permission.
    """
    level = UNKNOWN_RISK_LEVEL if risk_level is None else risk_level
    mode = config.fail_modes[level]

    if mode is FailMode.OPEN and level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        mode = FailMode.CLOSED

    if mode is FailMode.OPEN:
        return Decision(
            outcome=Outcome.ALLOW,
            rule_id=f"{FAIL_OPEN_PREFIX}{level.value}",
            risk_level=risk_level,
        )
    return Decision(
        outcome=Outcome.DENY,
        rule_id=f"{FAIL_CLOSED_PREFIX}{level.value}",
        risk_level=risk_level,
    )


def drift_decision(finding: DriftFinding, request: ToolCallRequest) -> Decision | None:
    """A drift finding graded by whether the server announced the change.

    Announced drift is a legitimate update needing re-approval. Silent drift is the
    rug-pull signature and is refused outright.
    """
    resolved = request.resolution
    risk = getattr(resolved, "risk_level", None)
    side_effect = getattr(resolved, "side_effect", None)

    if finding is DriftFinding.ANNOUNCED:
        return Decision(
            outcome=Outcome.REQUIRE_APPROVAL,
            rule_id=RULE_ID_SCHEMA_DRIFT_ANNOUNCED,
            risk_level=risk,
            side_effect=side_effect,
        )
    if finding is DriftFinding.SILENT:
        return Decision(
            outcome=Outcome.DENY,
            rule_id=RULE_ID_SCHEMA_DRIFT_SILENT,
            risk_level=risk,
            side_effect=side_effect,
        )
    return None


def resolution_decision(request: ToolCallRequest) -> Decision | None:
    """The two resolution states that decide without consulting any rule."""
    resolved = request.resolution
    if isinstance(resolved, UnknownTool):
        return Decision(outcome=Outcome.DENY, rule_id=RULE_ID_UNKNOWN_TOOL)
    if isinstance(resolved, UnclassifiedTool):
        return Decision(outcome=Outcome.DENY, rule_id=RULE_ID_UNCLASSIFIED_TOOL)
    return None


@dataclass(frozen=True)
class DecisionTiming:
    """Three separately reported costs, so no two ever blend into one figure.

    decision_us   receipt of the call to ready-to-forward, excluding approval wait
                  and excluding the audit commit
    approval_us   time the call sat blocked on a human, or None
    commit_us     the mandatory audit fsync, or None
    """

    decision_us: int
    approval_us: int | None
    commit_us: int | None = None


Approver = Callable[[ToolCallRequest, Decision], Awaitable[bool]]
"""Returns True to permit. Auto-denies in benchmark runs."""


def enforce(decision: Decision, variant: RunVariant) -> bool:
    """The only place variant is consulted. True means forward the call.

    In a GOVERNED run anything other than ALLOW stops here. In an UNGOVERNED run the
    decision has already been logged and is not acted on -- which is what makes the
    governed/ungoverned comparison a comparison of the same decisions rather than of
    two different code paths.
    """
    if variant is RunVariant.UNGOVERNED:
        return True
    return decision.outcome is Outcome.ALLOW


def budget_decision(
    request: ToolCallRequest, config: PolicyConfig, calls_so_far: int
) -> Decision | None:
    """Deny once a run has made its allowed number of tool calls.

    A blunt control: it caps damage rather than detecting an attack, so it consults
    neither taint nor rules -- once the cap is reached every further call is denied,
    whatever it is. `calls_so_far` counts calls already attempted in this run, so the
    Nth call (0-indexed N == cap) is the first refused.
    """
    cap = config.budgets.max_calls_per_run
    if cap is None or calls_so_far < cap:
        return None
    resolved = request.resolution
    return Decision(
        outcome=Outcome.DENY,
        rule_id=RULE_ID_BUDGET_EXCEEDED,
        risk_level=getattr(resolved, "risk_level", None),
        side_effect=getattr(resolved, "side_effect", None),
    )


async def decide(
    request: ToolCallRequest,
    config: PolicyConfig,
    *,
    resolve_taint: Callable[[], TaintSet],
    verify_schema: Callable[[], Awaitable[DriftFinding]],
    approve: Approver | None,
    variant: RunVariant,
    monotonic_us: Callable[[], int],
    calls_so_far: int = 0,
) -> tuple[Decision, TaintSet, DecisionTiming]:
    """Run the decision path and time it. Performs no I/O of its own.

    Every failure of a resolution step is caught and converted into a Decision by the
    fail-mode map, so this returns rather than raises for any upstream problem. A
    WardenError escaping here would be a bug in this function.
    """
    started = monotonic_us()
    approval_us: int | None = None
    taint: TaintSet = frozenset()

    # 1. Resolution states decide on their own, before any rule is consulted. The
    #    risk level is unknown for them, which is why they cannot key a fail mode.
    early = resolution_decision(request)
    if early is not None:
        return early, taint, DecisionTiming(monotonic_us() - started, None)

    # 2. The per-run call budget. Checked before the policy because it is a volume cap
    #    that applies regardless of what the call is; a run past its budget is denied
    #    even for a call the policy would allow.
    over_budget = budget_decision(request, config, calls_so_far)
    if over_budget is not None:
        return over_budget, taint, DecisionTiming(monotonic_us() - started, None)

    risk_level = getattr(request.resolution, "risk_level", None)

    # 2-4. Anything that raises from here has a known risk level, so the fail-mode
    #      map can be keyed properly.
    try:
        finding = await verify_schema()
        drift = drift_decision(finding, request)
        if drift is not None:
            decision = drift
        else:
            taint = resolve_taint()
            decision = evaluate(request, taint, config)
    except WardenError:
        return (
            fail_mode_decision(risk_level, config),
            taint,
            DecisionTiming(monotonic_us() - started, None),
        )

    # 5. Approval, and only in a governed run: a shadow run logs REQUIRE_APPROVAL
    #    without stopping to ask anyone.
    if (
        decision.outcome is Outcome.REQUIRE_APPROVAL
        and variant is RunVariant.GOVERNED
        and approve is not None
    ):
        paused_at = monotonic_us()
        granted = await approve(request, decision)
        approval_us = monotonic_us() - paused_at
        started += approval_us  # the wait is recorded, never charged to the decision
        if granted:
            decision = Decision(
                outcome=Outcome.ALLOW,
                rule_id=decision.rule_id,
                risk_level=decision.risk_level,
                side_effect=decision.side_effect,
                matched_taint=decision.matched_taint,
            )

    return decision, taint, DecisionTiming(monotonic_us() - started, approval_us)


def monotonic_us() -> int:
    return time.perf_counter_ns() // 1_000


def outcome_for(is_error: bool) -> ExecutionOutcome:
    return ExecutionOutcome.ERROR if is_error else ExecutionOutcome.OK
