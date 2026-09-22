"""Fail modes, drift grading, credential projection, and the enforcement point."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from warden.errors import WardenError
from warden.gateway.credentials import (
    CredentialStore,
    assert_projection_is_subset,
    project_schema,
)
from warden.gateway.drift import DriftFinding, SchemaGuard
from warden.gateway.wrapper import fail_mode_decision
from warden.log.models import RunVariant
from warden.policy.decision import (
    ClassifiedTool,
    Decision,
    FailMode,
    Outcome,
    RiskLevel,
    SideEffect,
    ToolCallRequest,
)
from warden.policy.rule_ids import (
    RULE_ID_SCHEMA_DRIFT_ANNOUNCED,
    RULE_ID_SCHEMA_DRIFT_SILENT,
)
from warden.policy.schema import PolicyConfig
from warden.gateway.wrapper import drift_decision, enforce

DEMO_POLICY = PolicyConfig.model_validate(
    yaml.safe_load(open("policies/demo.yaml", encoding="utf-8"))
)


# -- fail modes ----------------------------------------------------------------


def test_low_risk_fails_open() -> None:
    decision = fail_mode_decision(RiskLevel.LOW, DEMO_POLICY)
    assert decision.outcome is Outcome.ALLOW
    assert decision.rule_id == "fail-open:LOW"


@pytest.mark.parametrize(
    "level", [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
)
def test_higher_risk_fails_closed(level: RiskLevel) -> None:
    decision = fail_mode_decision(level, DEMO_POLICY)
    assert decision.outcome is Outcome.DENY
    assert decision.rule_id == f"fail-closed:{level.value}"


def test_unknown_risk_level_is_treated_as_critical() -> None:
    """A failure during registry lookup leaves the risk level unknown, so the map
    cannot be keyed. It must not fall through to permissive."""
    decision = fail_mode_decision(None, DEMO_POLICY)
    assert decision.outcome is Outcome.DENY
    assert decision.rule_id == "fail-closed:CRITICAL"
    assert decision.risk_level is None, "the absence stays visible in the log"


def test_a_permissive_map_cannot_produce_allow_above_medium() -> None:
    """The loader rejects HIGH/CRITICAL = OPEN, but a hand-built map in a test or a
    future call site would bypass that. This is the one function that turns an
    exception into permission, so it refuses structurally."""
    permissive = DEMO_POLICY.model_copy(
        update={
            "fail_modes": {
                RiskLevel.LOW: FailMode.OPEN,
                RiskLevel.MEDIUM: FailMode.OPEN,
                RiskLevel.HIGH: FailMode.OPEN,
                RiskLevel.CRITICAL: FailMode.OPEN,
            }
        }
    )
    assert fail_mode_decision(RiskLevel.MEDIUM, permissive).outcome is Outcome.ALLOW
    for level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        decision = fail_mode_decision(level, permissive)
        assert decision.outcome is Outcome.DENY
        assert decision.rule_id == f"fail-closed:{level.value}"


def test_loader_rejects_a_permissive_posture_above_medium() -> None:
    raw = yaml.safe_load(open("policies/demo.yaml", encoding="utf-8"))
    raw["fail_modes"]["HIGH"] = "OPEN"
    with pytest.raises(ValueError, match="non-negotiable"):
        PolicyConfig.model_validate(raw)


def test_loader_permits_a_permissive_posture_at_or_below_medium() -> None:
    raw = yaml.safe_load(open("policies/demo.yaml", encoding="utf-8"))
    raw["fail_modes"]["MEDIUM"] = "OPEN"
    assert PolicyConfig.model_validate(raw).fail_modes[RiskLevel.MEDIUM] is FailMode.OPEN


# -- drift grading -------------------------------------------------------------


def request_for(tool: str) -> ToolCallRequest:
    classification = DEMO_POLICY.classification[tool]
    return ToolCallRequest(
        tool=tool, agent="demo-agent",
        resolution=ClassifiedTool(
            tool=tool, risk_level=classification.risk_level,
            side_effect=classification.side_effect,
        ),
    )


def test_announced_drift_requires_reapproval() -> None:
    decision = drift_decision(DriftFinding.ANNOUNCED, request_for("send_email"))
    assert decision is not None
    assert decision.outcome is Outcome.REQUIRE_APPROVAL
    assert decision.rule_id == RULE_ID_SCHEMA_DRIFT_ANNOUNCED
    assert decision.side_effect is SideEffect.EXTERNAL_COMMS


def test_silent_drift_is_denied() -> None:
    """The rug-pull signature. Grading by whether the server announced the change is
    the actual detection, and it costs nothing."""
    decision = drift_decision(DriftFinding.SILENT, request_for("send_email"))
    assert decision is not None
    assert decision.outcome is Outcome.DENY
    assert decision.rule_id == RULE_ID_SCHEMA_DRIFT_SILENT


def test_no_drift_yields_no_decision() -> None:
    assert drift_decision(DriftFinding.NONE, request_for("send_email")) is None


@pytest.mark.anyio
async def test_guard_grades_the_same_change_by_whether_it_was_announced() -> None:
    schemas = {"send_email": "sha256:original"}

    async def discover() -> dict[str, str]:
        return dict(schemas)

    # TTL 0 forces a refresh on every verify.
    silent = SchemaGuard({"send_email": "sha256:original"}, discover, ttl_us=0)
    schemas["send_email"] = "sha256:changed"
    assert await silent.verify("send_email", now_us=1) is DriftFinding.SILENT

    announced = SchemaGuard({"send_email": "sha256:original"}, discover, ttl_us=0)
    announced.note_list_changed()
    assert await announced.verify("send_email", now_us=1) is DriftFinding.ANNOUNCED


@pytest.mark.anyio
async def test_silent_drift_keeps_reporting_but_announced_is_repinned() -> None:
    schemas = {"t": "sha256:b"}

    async def discover() -> dict[str, str]:
        return dict(schemas)

    silent = SchemaGuard({"t": "sha256:a"}, discover, ttl_us=0)
    assert await silent.verify("t", now_us=1) is DriftFinding.SILENT
    assert await silent.verify("t", now_us=2) is DriftFinding.SILENT

    announced = SchemaGuard({"t": "sha256:a"}, discover, ttl_us=0)
    announced.note_list_changed()
    assert await announced.verify("t", now_us=1) is DriftFinding.ANNOUNCED
    assert await announced.verify("t", now_us=2) is DriftFinding.NONE


@pytest.mark.anyio
async def test_a_vanished_tool_counts_as_drift() -> None:
    async def discover() -> dict[str, str]:
        return {}

    guard = SchemaGuard({"t": "sha256:a"}, discover, ttl_us=0)
    assert await guard.verify("t", now_us=1) is DriftFinding.SILENT


# -- credentials ---------------------------------------------------------------

UPSTREAM: dict[str, Any] = {
    "type": "object",
    "properties": {
        "to": {"type": "string"},
        "subject": {"type": "string"},
        "api_key": {"type": "string"},
    },
    "required": ["to", "subject", "api_key"],
}


def test_projection_strips_the_credential_parameter() -> None:
    projected = project_schema(UPSTREAM, frozenset({"api_key"}))
    assert set(projected["properties"]) == {"to", "subject"}
    assert projected["required"] == ["to", "subject"]
    assert_projection_is_subset(UPSTREAM, projected)


def test_projection_that_adds_a_parameter_is_rejected() -> None:
    bad = project_schema(UPSTREAM, frozenset({"api_key"}))
    bad["properties"]["extra"] = {"type": "string"}
    with pytest.raises(WardenError, match="added parameters"):
        assert_projection_is_subset(UPSTREAM, bad)


def test_projection_that_retypes_a_parameter_is_rejected() -> None:
    bad = project_schema(UPSTREAM, frozenset({"api_key"}))
    bad["properties"]["to"] = {"type": "integer"}
    with pytest.raises(WardenError, match="altered parameter"):
        assert_projection_is_subset(UPSTREAM, bad)


def test_projection_that_widens_required_is_rejected() -> None:
    upstream: dict[str, Any] = {
        "type": "object",
        "properties": {"to": {"type": "string"}},
        "required": [],
    }
    bad = {"type": "object", "properties": {"to": {"type": "string"}}, "required": ["to"]}
    with pytest.raises(WardenError, match="requires parameters upstream does not"):
        assert_projection_is_subset(upstream, bad)


def test_injection_adds_the_secret_and_leaves_others_alone() -> None:
    store = CredentialStore({"send_email": {"api_key": "s3cr3t"}})
    injected = store.inject("send_email", {"to": "a@example.com"})
    assert injected == {"to": "a@example.com", "api_key": "s3cr3t"}
    assert store.inject("search_docs", {"query": "x"}) == {"query": "x"}


def test_credential_parameters_come_from_warden_not_the_server() -> None:
    """A tool Warden has no credential config for gets nothing injected, whatever
    its schema advertises."""
    store = CredentialStore({"send_email": {"api_key": "s3cr3t"}})
    assert store.parameters_for("send_email") == frozenset({"api_key"})
    assert store.parameters_for("delete_customer") == frozenset()


# -- the enforcement point -----------------------------------------------------


@pytest.mark.parametrize(
    "outcome,governed_forwards",
    [(Outcome.ALLOW, True), (Outcome.DENY, False), (Outcome.REQUIRE_APPROVAL, False)],
)
def test_governed_forwards_only_allow(
    outcome: Outcome, governed_forwards: bool
) -> None:
    decision = Decision(outcome=outcome, rule_id="a-rule")
    assert enforce(decision, RunVariant.GOVERNED) is governed_forwards


@pytest.mark.parametrize("outcome", list(Outcome))
def test_ungoverned_forwards_everything(outcome: Outcome) -> None:
    """A shadow run logs the decision and does not act on it -- including a
    fail-closed decision. `fail-closed:HIGH` against a call that then executed is the
    "would have blocked" record, not an inconsistency."""
    decision = Decision(outcome=outcome, rule_id="fail-closed:HIGH")
    assert enforce(decision, RunVariant.UNGOVERNED) is True
