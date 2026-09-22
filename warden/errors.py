"""The WardenError hierarchy, mapped once at the MCP protocol boundary.

PolicyDenied deliberately carries no policy detail. Anything that can reach the agent
through an error teaches an injected prompt how the policy is shaped and lets it probe
for a permitted path. The refusal returned to the caller is fixed and generic; the
rule id, matched taint, and risk classification go to the call log only.
"""

from __future__ import annotations

from typing import Final

REFUSAL_MESSAGE: Final = "This tool call was not permitted."
"""The entire text a denied caller ever sees. Never interpolate into this."""


class WardenError(Exception):
    """Base for every error Warden raises."""


class PolicyDenied(WardenError):
    """A tool call was refused by policy.

    Constructed without arguments on purpose: there is no field in which a rule id or
    a description could be smuggled back to the agent.
    """

    def __init__(self) -> None:
        super().__init__(REFUSAL_MESSAGE)


class SchemaDrift(WardenError):
    """An upstream tool's schema no longer matches what was classified."""


BUDGET_MESSAGE: Final = "This run has exceeded its allowed number of tool calls."
"""What a budget-denied caller sees. A rate signal, not policy shape -- safe to
surface, unlike a policy denial's reasoning."""


class BudgetExceeded(WardenError):
    """A run exhausted its configured call, token, or time budget.

    Constructed with no argument for the caller-facing refusal (the fixed generic
    message); internal raises pass their own diagnostic string.
    """

    def __init__(self, message: str = BUDGET_MESSAGE) -> None:
        super().__init__(message)


class UpstreamUnavailable(WardenError):
    """An upstream MCP server could not be reached."""


class ToolTimeout(WardenError):
    """An upstream tool exceeded its configured deadline."""


class LogIntegrityError(WardenError):
    """A call log row violated an invariant the schema cannot express.

    Raised rather than asserted because `python -O` strips assert statements, and
    these invariants guard the rows the reported metrics are computed from.
    """
