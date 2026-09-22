"""On-disk policy grammar for policies/*.yaml and its Pydantic v2 loader models.

Every model here is closed (extra="forbid"). An unrecognised key is a load-time
error, never a silently ignored one: `side_efect: [EXTERNAL_COMMS]` must fail loudly,
because ignored it would produce a rule with zero predicates that matches every call
at whatever position it occupies in the ordered list.

Matching is first-match-wins over `rules` in file order, with a synthetic terminal
default-deny below them. Within one `match` block, every key present must hold (AND);
within a list-valued key, membership suffices (OR).
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Final, Mapping, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from warden.policy.decision import (
    FailMode,
    Outcome,
    RiskLevel,
    SideEffect,
    ToolClass,
)
from warden.policy.labels import AgentId, TaintPredicate, ToolName
from warden.policy.rule_ids import is_reserved_rule_id

AUTHORED_RULE_ID_PATTERN: Final = r"^[a-z0-9][a-z0-9-]{0,63}$"
"""Authored ids admit no ':', so they cannot collide with fail-open:/fail-closed:
ids by construction. The reserved-id check covers the three bare synthetic ids."""

AuthoredRuleId: TypeAlias = Annotated[
    str, Field(pattern=AUTHORED_RULE_ID_PATTERN)
]

SCHEMA_VERSION: Final = 1


class _Closed(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Match(_Closed):
    """A closed predicate vocabulary. Adding a key here is a schema version bump.

    Tool names match exactly. Globs and namespace prefixes are deliberately absent:
    the tool-name charset has no namespace separator, so a prefix has no natural
    boundary and `send*` would match both `send_email` and `send_all_credentials`.
    """

    tool: Annotated[tuple[ToolName, ...], Field(min_length=1)] | None = None
    agent: Annotated[tuple[AgentId, ...], Field(min_length=1)] | None = None
    side_effect: Annotated[tuple[SideEffect, ...], Field(min_length=1)] | None = None
    risk_level: Annotated[tuple[RiskLevel, ...], Field(min_length=1)] | None = None
    argument_taint: TaintPredicate | None = None

    @model_validator(mode="after")
    def _at_least_one_predicate(self) -> Match:
        if all(getattr(self, name) is None for name in type(self).model_fields):
            raise ValueError(
                "match requires at least one predicate; an empty match block "
                "matches every call at its position in the ordered rule list"
            )
        return self


class Rule(_Closed):
    id: AuthoredRuleId
    match: Match
    outcome: Outcome
    description: str = ""

    @model_validator(mode="after")
    def _id_not_reserved(self) -> Rule:
        if is_reserved_rule_id(self.id):
            raise ValueError(
                f"rule id {self.id!r} is reserved for synthetic decisions; report "
                "columns key on rule_id, so a collision makes reports silently wrong"
            )
        return self


class Budgets(_Closed):
    """Per-run resource caps. A blunt damage-capping control, not a detector.

    max_calls_per_run bounds how many tool calls one run may make. It does not look at
    taint or side effect -- once the cap is hit, every further call is denied. Tokens
    are not capped here: the gateway does not see the model's token accounting on the
    stdio transport, so a token budget would be unenforceable and is deliberately
    omitted rather than declared and ignored.
    """

    max_calls_per_run: Annotated[int, Field(ge=1)] | None = None


class PolicyConfig(_Closed):
    """A whole policy file.

    `fail_modes` must name every RiskLevel explicitly. There is no default for any
    level, MEDIUM included: "fail modes are explicit per risk level" is a project
    non-negotiable, and a defaulted level is precisely the implicitness it forbids.
    """

    schema_version: int = SCHEMA_VERSION
    fail_modes: dict[RiskLevel, FailMode]
    classification: Mapping[ToolName, ToolClass] = Field(default_factory=dict)
    retrieval_tools: tuple[ToolName, ...] = ()
    """Tools whose output is document or knowledge-store content, and therefore also
    carries the RETRIEVED label alongside TOOL_OUTPUT:<tool>.

    This declaration lives in the policy file, never in the server's tools/list, for
    a specific reason: a server that declares its own provenance can shed taint. A
    compromised or malicious MCP server would simply announce itself as non-retrieval
    and its output would stop being treated as untrusted. The trust boundary is
    exactly here, so the classification is the operator's to make.
    """
    rules: tuple[Rule, ...] = ()
    budgets: Budgets = Field(default_factory=lambda: Budgets())

    @field_validator("classification", mode="after")
    @classmethod
    def _freeze_classification(
        cls, value: Mapping[str, ToolClass]
    ) -> Mapping[str, ToolClass]:
        """frozen=True does not protect a dict field -- a caller can inject a
        classification in place. evaluate() never reads this (resolution arrives
        pre-resolved on the request), but component 4's resolver does, and closing
        it before that code exists is cheaper than after."""
        return MappingProxyType(dict(value))

    @field_serializer("classification")
    def _dump_classification(
        self, value: Mapping[str, ToolClass]
    ) -> dict[str, ToolClass]:
        return dict(value)

    @model_validator(mode="after")
    def _fail_modes_cover_every_risk_level(self) -> PolicyConfig:
        missing = sorted(level.value for level in RiskLevel if level not in self.fail_modes)
        if missing:
            raise ValueError(f"fail_modes is missing required risk levels: {missing}")
        return self

    @model_validator(mode="after")
    def _high_risk_must_fail_closed(self) -> PolicyConfig:
        """Requiring a key and constraining its value are independent requirements.

        "Fail modes are explicit per risk level" removed implicit defaults; it did not
        make every posture reachable. LOW and MEDIUM are the operator's choice.
        """
        offenders = sorted(
            level.value
            for level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            if self.fail_modes.get(level) is FailMode.OPEN
        )
        if offenders:
            raise ValueError(
                f"fail_modes sets OPEN for {offenders}, violating the project "
                "non-negotiable that HIGH and CRITICAL tools fail closed when a "
                "check errors. LOW and MEDIUM may be either."
            )
        return self

    @model_validator(mode="after")
    def _rule_ids_unique(self) -> PolicyConfig:
        seen: set[str] = set()
        duplicates: list[str] = []
        for rule in self.rules:
            if rule.id in seen:
                duplicates.append(rule.id)
            seen.add(rule.id)
        if duplicates:
            raise ValueError(f"duplicate rule ids: {sorted(set(duplicates))}")
        return self
