"""Identifiers and closed vocabularies for the call log."""

from __future__ import annotations

from enum import StrEnum
from typing import Final, NewType

from ulid import ULID

NO_POLICY: Final = "none"
"""runs.policy_hash for a run where no policy was evaluated at all. Not a hash, and
deliberately not a valid one, so it cannot be confused with a real policy digest."""

RunId = NewType("RunId", str)
CallId = NewType("CallId", str)


def new_run_id() -> RunId:
    return RunId(str(ULID()))


def new_call_id() -> CallId:
    return CallId(str(ULID()))


class RunMode(StrEnum):
    LIVE = "LIVE"
    BENCH = "BENCH"


class RunVariant(StrEnum):
    """Whether the policy decision was acted on, or only recorded.

    UNGOVERNED still resolves taint and runs evaluate() -- evaluate() is pure, so the
    result costs nothing and is simply not enforced. That is what lets Table 1 say
    "the ungoverned agent made N calls the policy would have blocked, and here are
    their rule ids" rather than only reporting an aggregate.
    """

    GOVERNED = "GOVERNED"
    UNGOVERNED = "UNGOVERNED"


class ExecutionOutcome(StrEnum):
    """What happened when the call ran. NOT_RUN means it never did."""

    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    NOT_RUN = "NOT_RUN"


class Suite(StrEnum):
    ATTACK = "ATTACK"
    BENIGN = "BENIGN"


class Oracle(StrEnum):
    """How a scenario's verdict was decided.

    JUDGED exists so that goal hijacking, the one partly-judged oracle, is labelled
    in the data. A report cannot render it as deterministic by accident.
    """

    CANARY = "CANARY"
    CALL_LOG = "CALL_LOG"
    JUDGED = "JUDGED"
