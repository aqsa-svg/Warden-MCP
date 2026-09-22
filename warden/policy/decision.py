"""The Decision record and the resolved inputs evaluate() consumes.

Decision is the single value every authorization path produces -- the pure matcher,
and the gateway's fail-mode wrapper alike -- so that "one JSON line per policy
decision, including the matched rule id" is structurally impossible to violate.

Decision carries no timestamp. The wrapper stamps the log row when it writes it.
A clock field on a value returned by a pure function is the first thing that quietly
breaks purity, and it would have to be injected to test.

Decision carries no human-readable reason either. The explanation is a property of
the rule, lives once in the YAML `description`, and is joined by rule_id at render
time -- so editing a description is not a schema change. It is also attack surface:
anything that can reach the agent through a PolicyDenied error teaches an injected
prompt how the policy is shaped. The refusal returned to the caller is fixed and
generic; the full detail goes to the log row only.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from warden.policy.labels import AgentId, TaintSet, ToolName

RULE_ID_PATTERN: Final = r"^[a-z0-9][a-zA-Z0-9:_-]{0,63}$"
"""Accepts both authored and synthetic ids. Uppercase is permitted after the first
character because synthetic fail-mode ids embed the RiskLevel value verbatim --
`fail-closed:HIGH`. Authored ids are separately constrained to lowercase and no
colon (AUTHORED_RULE_ID_PATTERN in schema.py), so the two namespaces stay disjoint
by construction rather than by blocklist."""

RuleId: TypeAlias = Annotated[str, StringConstraints(pattern=RULE_ID_PATTERN)]


class Outcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SideEffect(StrEnum):
    """Effect class of a tool. The ASR table groups by this."""

    READ_ONLY = "READ_ONLY"
    LOCAL_WRITE = "LOCAL_WRITE"
    EXTERNAL_COMMS = "EXTERNAL_COMMS"
    CODE_EXEC = "CODE_EXEC"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DESTRUCTIVE = "DESTRUCTIVE"


class FailMode(StrEnum):
    """What the gateway wrapper does when a check *errors*, per risk level."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolClass(_Frozen):
    """A policy author's classification of one tool."""

    risk_level: RiskLevel
    side_effect: SideEffect


class UnknownTool(_Frozen):
    """Not present in the registry built from tools/list. Denies as unknown-tool."""

    resolution: Literal["UNKNOWN"] = "UNKNOWN"


class UnclassifiedTool(_Frozen):
    """In the registry, absent from the policy classification table."""

    resolution: Literal["UNCLASSIFIED"] = "UNCLASSIFIED"
    tool: ToolName


class ClassifiedTool(_Frozen):
    """In the registry and classified. Cannot exist without a risk level."""

    resolution: Literal["CLASSIFIED"] = "CLASSIFIED"
    tool: ToolName
    risk_level: RiskLevel
    side_effect: SideEffect


ToolResolution: TypeAlias = Annotated[
    UnknownTool | UnclassifiedTool | ClassifiedTool, Field(discriminator="resolution")
]


class ToolCallRequest(_Frozen):
    """Fully resolved inputs to evaluate(). No lookups remain to be performed."""

    tool: ToolName
    agent: AgentId
    resolution: ToolResolution


class Decision(_Frozen):
    """The outcome of one authorization, and the whole of what the log row records.

    `risk_level` and `side_effect` are None exactly when the tool did not resolve to
    a classification -- unknown-tool, or a wrapper failure that occurred *during*
    registry lookup. The absence is deliberately visible rather than defaulted: the
    wrapper's rule is that an unknown risk level keys the fail-mode map as CRITICAL,
    and that reads clearly only when None is a real state.

    Both are copied from the resolution at decision time rather than recomputed at
    report time, so the ASR table's grouping cannot disagree with what was true when
    the call was authorized.
    """

    outcome: Outcome
    rule_id: RuleId
    risk_level: RiskLevel | None = None
    side_effect: SideEffect | None = None
    matched_taint: TaintSet = Field(default_factory=frozenset)
