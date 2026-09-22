"""Taint labels, taint patterns, and the taint predicate.

A TaintLabel records the provenance of content that reached a tool call argument.
It is a closed discriminated union, not an enum: USER_INPUT and RETRIEVED are
nullary, TOOL_OUTPUT is parameterised by the upstream tool that produced it.

Illegal states are unrepresentable rather than merely rejected: there is no way to
construct a TOOL_OUTPUT label without a tool, or a USER_INPUT label carrying one.

Tool names are constrained at construction to TOOL_NAME_PATTERN. The same constraint
is applied at tools/list ingestion in the registry, where a server offering a
non-conforming name has that tool rejected. This is what makes the delimiter in the
`TOOL_OUTPUT:<tool>` display form unforgeable: a tool cannot be named `x:RETRIEVED`
in the first place. Policy rules never predicate on that string form regardless --
they predicate on the structured variant fields via TaintPattern.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, TypeAlias, assert_never

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

TOOL_NAME_PATTERN: Final = r"^[a-zA-Z0-9_-]{1,64}$"
AGENT_ID_PATTERN: Final = r"^[a-zA-Z0-9_-]{1,64}$"

ToolName: TypeAlias = Annotated[str, StringConstraints(pattern=TOOL_NAME_PATTERN)]
AgentId: TypeAlias = Annotated[str, StringConstraints(pattern=AGENT_ID_PATTERN)]

TaintKind: TypeAlias = Literal["USER_INPUT", "RETRIEVED", "TOOL_OUTPUT"]


class _Frozen(BaseModel):
    """Immutable, hashable, and closed to unrecognised keys."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class UserInput(_Frozen):
    """Content that arrived directly from the human operator.

    Semi-trusted, not trusted: direct prompt injection arrives through this label.
    The absence of RETRIEVED and TOOL_OUTPUT taint does not by itself mean safe.
    """

    kind: Literal["USER_INPUT"] = "USER_INPUT"


class Retrieved(_Frozen):
    """Content fetched from a document or knowledge store."""

    kind: Literal["RETRIEVED"] = "RETRIEVED"


class ToolOutput(_Frozen):
    """Content returned by an upstream MCP tool, tagged with which tool produced it."""

    kind: Literal["TOOL_OUTPUT"] = "TOOL_OUTPUT"
    tool: ToolName


TaintLabel: TypeAlias = Annotated[
    UserInput | Retrieved | ToolOutput, Field(discriminator="kind")
]
TaintSet: TypeAlias = frozenset[TaintLabel]


def label_str(label: TaintLabel) -> str:
    """Display-only projection. Never parsed, never matched against, never canonical.

    The canonical form in the call log is structured JSON.
    """
    match label:
        case UserInput():
            return "USER_INPUT"
        case Retrieved():
            return "RETRIEVED"
        case ToolOutput():
            return f"TOOL_OUTPUT:{label.tool}"
        case _:  # pragma: no cover - static exhaustiveness guard
            assert_never(label)


class TaintPattern(_Frozen):
    """A partial match over a TaintLabel's structured fields.

    `tool` omitted means any tool, and is only meaningful for TOOL_OUTPUT; a pattern
    naming a tool for any other kind is a load-time error rather than a rule that
    silently never fires.
    """

    kind: TaintKind
    tool: ToolName | None = None

    @model_validator(mode="after")
    def _tool_requires_tool_output(self) -> TaintPattern:
        if self.tool is not None and self.kind != "TOOL_OUTPUT":
            raise ValueError(
                f"taint pattern kind={self.kind!r} cannot carry tool={self.tool!r}; "
                "only TOOL_OUTPUT is parameterised by a tool"
            )
        return self

    def matches(self, label: TaintLabel) -> bool:
        if label.kind != self.kind:
            return False
        if self.tool is None:
            return True
        return isinstance(label, ToolOutput) and label.tool == self.tool


_Patterns: TypeAlias = Annotated[tuple[TaintPattern, ...], Field(min_length=1)]


class TaintPredicate(_Frozen):
    """A condition over the union of taint labels across all call arguments.

    Empty-set semantics are defined, not emergent. A call with no arguments, or with
    arguments carrying no taint, presents ``frozenset()``. Against that empty set:

      * ``any_of``  is **False** -- nothing is present, so nothing matched.
      * ``none_of`` is **True**  -- nothing prohibited is present.

    Both keys may be given, in which case both must hold. At least one is required;
    a predicate that constrains nothing is a rule that matches everything at whatever
    position it occupies in the ordered list, which is the footgun this forbids.

    ``all_of`` is deliberately absent until a rule needs it. Adding it later is a
    schema version bump, not a breaking change.
    """

    any_of: _Patterns | None = None
    none_of: _Patterns | None = None

    @model_validator(mode="after")
    def _at_least_one_clause(self) -> TaintPredicate:
        if self.any_of is None and self.none_of is None:
            raise ValueError("argument_taint requires at least one of any_of, none_of")
        return self

    def matched(self, taint: TaintSet) -> TaintSet:
        """Labels in `taint` that satisfy `any_of`.

        Always empty when only `none_of` is set: none_of holds precisely when nothing
        matched, so it has no labels to attribute. The accompanying rule_id is what
        disambiguates such a log line.
        """
        if self.any_of is None:
            return frozenset()
        return frozenset(
            label for label in taint for pat in self.any_of if pat.matches(label)
        )

    def holds(self, taint: TaintSet) -> bool:
        if self.any_of is not None and not self.matched(taint):
            return False
        if self.none_of is not None and any(
            pat.matches(label) for label in taint for pat in self.none_of
        ):
            return False
        return True
