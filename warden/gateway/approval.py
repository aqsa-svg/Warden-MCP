"""Interactive approval over /dev/tty.

On the stdio transport, stdin IS the JSON-RPC channel -- reading it to prompt a human
would corrupt the protocol stream. Opening the controlling terminal directly leaves
that channel untouched, which is what makes human approval a real state in the
workflow rather than a claim.

Where there is no controlling terminal -- CI, a non-TTY pipe, Windows -- this falls
back to auto-deny. Benchmark runs auto-deny unconditionally: a suite that waits for a
human is not a benchmark.

Nothing the operator is shown here can reach the agent. The prompt is written to the
terminal, and the refusal returned to the caller is the fixed, argument-less
PolicyDenied message. That is why Decision carries no `reason` field, and this must
not reintroduce the path.
"""

from __future__ import annotations

import asyncio
from typing import Callable, TextIO

from warden.log.models import RunMode
from warden.gateway.wrapper import Approver
from warden.policy.decision import Decision, ToolCallRequest

TTY_PATH = "/dev/tty"
AFFIRMATIVE = frozenset({"y", "yes"})

Logger = Callable[..., None]


def _prompt_text(request: ToolCallRequest, decision: Decision) -> str:
    """Operator-facing only. Never returned to the caller."""
    risk = "unknown" if decision.risk_level is None else decision.risk_level.value
    side_effect = (
        "unknown" if decision.side_effect is None else decision.side_effect.value
    )
    taint = ", ".join(sorted(label.kind for label in decision.matched_taint)) or "none"
    return (
        f"\n[warden] approval required\n"
        f"  tool        {request.tool}\n"
        f"  agent       {request.agent}\n"
        f"  risk        {risk}\n"
        f"  side effect {side_effect}\n"
        f"  rule        {decision.rule_id}\n"
        f"  taint       {taint}\n"
        f"  approve? [y/N] "
    )


def _ask_on_tty(prompt: str) -> bool:
    """Blocking. Called via asyncio.to_thread so the event loop keeps serving."""
    tty: TextIO
    with open(TTY_PATH, "r+", encoding="utf-8") as tty:
        tty.write(prompt)
        tty.flush()
        answer = tty.readline()
    return answer.strip().lower() in AFFIRMATIVE


def make_approver(mode: RunMode, log: Logger) -> Approver:
    """Build the approver for a run."""

    async def approve(request: ToolCallRequest, decision: Decision) -> bool:
        if mode is RunMode.BENCH:
            log("approval_auto_denied", tool=request.tool, reason="bench-run")
            return False
        try:
            granted = await asyncio.to_thread(
                _ask_on_tty, _prompt_text(request, decision)
            )
        except OSError as exc:
            # No controlling terminal. Fail closed rather than guess.
            log(
                "approval_auto_denied",
                tool=request.tool,
                reason="no-controlling-tty",
                detail=type(exc).__name__,
            )
            return False
        log(
            "approval_resolved",
            tool=request.tool,
            rule_id=decision.rule_id,
            granted=granted,
        )
        return granted

    return approve
