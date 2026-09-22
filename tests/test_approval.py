"""Approval: fail-closed fallbacks, and the refusal reveals nothing."""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable

import pytest

from warden.errors import REFUSAL_MESSAGE, PolicyDenied
from warden.gateway.approval import TTY_PATH, _prompt_text, make_approver
from warden.log.models import RunMode
from warden.policy.decision import (
    ClassifiedTool,
    Decision,
    Outcome,
    RiskLevel,
    SideEffect,
    ToolCallRequest,
)
from warden.policy.labels import Retrieved, ToolOutput

def run(awaitable: Awaitable[bool]) -> bool:
    """asyncio.run wants a Coroutine; Approver is typed as returning an Awaitable."""

    async def wrapped() -> bool:
        return await awaitable

    return asyncio.run(wrapped())


REQUEST = ToolCallRequest(
    tool="send_email",
    agent="demo-agent",
    resolution=ClassifiedTool(
        tool="send_email",
        risk_level=RiskLevel.HIGH,
        side_effect=SideEffect.EXTERNAL_COMMS,
    ),
)
DECISION = Decision(
    outcome=Outcome.REQUIRE_APPROVAL,
    rule_id="comms-untainted-requires-approval",
    risk_level=RiskLevel.HIGH,
    side_effect=SideEffect.EXTERNAL_COMMS,
    matched_taint=frozenset({Retrieved(), ToolOutput(tool="search_docs")}),
)


def test_bench_runs_auto_deny_without_touching_a_terminal() -> None:
    """A suite that waits for a human is not a benchmark."""
    events: list[tuple[str, dict[str, Any]]] = []

    def log(event: str, **fields: Any) -> None:
        events.append((event, fields))

    approve = make_approver(RunMode.BENCH, log)
    assert run(approve(REQUEST, DECISION)) is False
    assert events[0][0] == "approval_auto_denied"
    assert events[0][1]["reason"] == "bench-run"


def test_missing_controlling_terminal_fails_closed(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """No /dev/tty -- CI, a pipe, Windows. Deny rather than guess."""
    events: list[tuple[str, dict[str, Any]]] = []

    def log(event: str, **fields: Any) -> None:
        events.append((event, fields))

    def explode(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("no such device or address")

    monkeypatch.setattr("warden.gateway.approval.open", explode, raising=False)
    approve = make_approver(RunMode.LIVE, log)
    assert run(approve(REQUEST, DECISION)) is False
    assert events[-1][1]["reason"] == "no-controlling-tty"


def test_approval_opens_the_terminal_not_stdin(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    """stdin IS the JSON-RPC channel on the stdio transport, so prompting through it
    would corrupt the protocol stream. Assert the path actually opened."""
    opened: list[str] = []

    class FakeTty:
        def __enter__(self) -> "FakeTty":
            return self

        def __exit__(self, *_exc: Any) -> None:
            return None

        def write(self, _text: str) -> None:
            return None

        def flush(self) -> None:
            return None

        def readline(self) -> str:
            return "y" + chr(10)

    def fake_open(path: str, *_args: Any, **_kwargs: Any) -> FakeTty:
        opened.append(path)
        return FakeTty()

    monkeypatch.setattr("warden.gateway.approval.open", fake_open, raising=False)
    approve = make_approver(RunMode.LIVE, lambda *_a, **_k: None)
    assert run(approve(REQUEST, DECISION)) is True
    assert opened == [TTY_PATH]
    assert TTY_PATH == "/dev/tty"


def test_operator_prompt_carries_detail_the_agent_must_never_see() -> None:
    """The prompt is written to the terminal. It is deliberately informative, which
    is exactly why it must not be the thing returned to the caller."""
    prompt = _prompt_text(REQUEST, DECISION)
    assert "comms-untainted-requires-approval" in prompt
    assert "EXTERNAL_COMMS" in prompt
    assert "RETRIEVED" in prompt


def test_the_refusal_returned_to_the_caller_reveals_nothing() -> None:
    """Decision carries no `reason` field because anything reaching the agent teaches
    an injected prompt how to probe the policy. Interactive approval must not
    reintroduce that path."""
    refusal = str(PolicyDenied())
    assert refusal == REFUSAL_MESSAGE
    for leak in (
        "comms-untainted-requires-approval",
        "EXTERNAL_COMMS",
        "HIGH",
        "RETRIEVED",
        "search_docs",
    ):
        assert leak not in refusal

    with pytest.raises(TypeError):
        PolicyDenied("denied by rule comms-untainted-requires-approval")  # type: ignore[call-arg]
