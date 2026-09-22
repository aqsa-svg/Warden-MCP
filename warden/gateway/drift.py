"""Schema-drift detection with announced/silent grading.

MCP returns no schema on tools/call, so per-call verification would put a tools/list
round trip on the critical path. Instead: pinned hashes in memory, re-discovery on the
server's notifications/tools/list_changed, and a TTL backstop -- because a malicious
server simply will not send the notification.

The grading is the actual detection, and it is free. A server that announces a change
and whose schema then differs is doing a legitimate update, and the call needs
re-approval. A server whose schema changed and that never announced it is the rug-pull
signature. Same observation, two very different findings.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Final

DEFAULT_TTL_US: Final = 60_000_000
"""Backstop re-discovery interval. Configurable; a server that never notifies is
exactly the case this exists for."""

Discover = Callable[[], Awaitable[dict[str, str]]]
"""Returns {tool_name: schema_hash} from a fresh tools/list."""


class DriftFinding(StrEnum):
    NONE = "NONE"
    ANNOUNCED = "ANNOUNCED"
    SILENT = "SILENT"


class SchemaGuard:
    def __init__(
        self,
        pinned: dict[str, str],
        discover: Discover,
        *,
        ttl_us: int = DEFAULT_TTL_US,
        pinned_at_us: int = 0,
    ) -> None:
        self._pinned = dict(pinned)
        self._discover = discover
        self._ttl_us = ttl_us
        self._refreshed_at_us = pinned_at_us
        self._announced = False

    def note_list_changed(self) -> None:
        """Handler for notifications/tools/list_changed.

        Marks the next observed difference as announced, and forces a refresh on the
        next verify.
        """
        self._announced = True
        self._refreshed_at_us = 0

    def pinned_hash(self, tool: str) -> str | None:
        return self._pinned.get(tool)

    async def verify(self, tool: str, *, now_us: int) -> DriftFinding:
        """Compare the tool's live schema hash against its pin.

        A tool that has disappeared from tools/list counts as drift: the agent was
        told about a tool the server no longer offers under that shape.

        An announced change is re-pinned, because the approval path is what gates it.
        A silent change is never re-pinned, so it keeps being reported rather than
        being accepted after a single hit.
        """
        if now_us - self._refreshed_at_us < self._ttl_us:
            return DriftFinding.NONE

        fresh = await self._discover()
        self._refreshed_at_us = now_us
        announced, self._announced = self._announced, False

        changed = [
            name for name, pin in self._pinned.items() if fresh.get(name) != pin
        ]
        if not changed:
            return DriftFinding.NONE

        if announced:
            self._pinned.update(
                {name: fresh[name] for name in changed if name in fresh}
            )
            return DriftFinding.ANNOUNCED if tool in changed else DriftFinding.NONE

        return DriftFinding.SILENT if tool in changed else DriftFinding.NONE
