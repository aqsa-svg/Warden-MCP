"""The demo MCP server: five tools over stdio.

send_email writes an .eml file to an outbox and never sends. delete_customer is a soft
delete. Both remain observable as side effects in the state directory without being
irreversible between benchmark runs.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

from mcp.server.mcpserver import MCPServer

from warden.demo_server.catalog import BY_NAME
from warden.demo_server.corpus import Document, corpus
from warden.demo_server.state import DemoState

DEFAULT_SEARCH_LIMIT = 5
MAX_SEARCH_LIMIT = 20


_WORD_RE: Final = re.compile(r"[a-z0-9-]+")
STOPWORDS: Final[frozenset[str]] = frozenset(
    {"the", "and", "for", "was", "are", "not", "but", "has", "had", "its", "our",
     "you", "your", "get", "getting", "since", "after", "over", "from", "with",
     "this", "that", "when", "have", "been", "does", "did", "can"}
)
MIN_TERM_LEN: Final = 3


def _terms(query: str) -> list[str]:
    """Word tokens, not substrings. `str.count` would match "on" inside "Connecting"."""
    return [
        t for t in _WORD_RE.findall(query.lower())
        if len(t) >= MIN_TERM_LEN and t not in STOPWORDS
    ]


def _score(text: str, terms: list[str]) -> int:
    tokens = Counter(_WORD_RE.findall(text.lower()))
    return sum(tokens[term] for term in terms)


def build_server(
    state: DemoState,
    appends: Sequence[Document] = (),
    replacements: Sequence[Document] = (),
) -> MCPServer:
    server: MCPServer = MCPServer(
        name="meridian-support",
        instructions="Support tooling for the Meridian analytics product.",
    )

    @server.tool(description=BY_NAME["search_docs"].description)
    def search_docs(query: str, limit: int = DEFAULT_SEARCH_LIMIT) -> list[dict[str, str]]:
        terms = _terms(query)
        capped = max(1, min(limit, MAX_SEARCH_LIMIT))
        scored = [
            (_score(f"{d.title} {d.body} {' '.join(d.tags)}", terms), d)
            for d in corpus(appends, replacements=replacements)
        ]
        hits = sorted(
            (pair for pair in scored if pair[0] > 0), key=lambda p: -p[0]
        )[:capped]
        return [
            {"doc_id": d.doc_id, "title": d.title, "body": d.body}
            for _, d in hits
        ]

    @server.tool(description=BY_NAME["get_customer"].description)
    def get_customer(customer_id: str) -> dict[str, Any]:
        customer = state.get_customer(customer_id)
        if customer is None:
            return {"error": f"no such customer: {customer_id}"}
        return {
            "customer_id": customer.customer_id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "plan": customer.plan,
            "open_issue": customer.open_issue,
            "deleted": customer.deleted,
        }

    @server.tool(description=BY_NAME["create_ticket"].description)
    def create_ticket(
        customer_id: str, subject: str, body: str, priority: str = "normal"
    ) -> dict[str, str]:
        ticket = state.create_ticket(customer_id, subject, body, priority)
        return {"ticket_id": ticket.ticket_id, "status": "open"}

    @server.tool(description=BY_NAME["send_email"].description)
    def send_email(
        to: str, subject: str, body: str, api_key: str = ""
    ) -> dict[str, str]:
        """api_key is supplied by Warden after the authorization decision. It is
        stripped from the schema the agent sees, so the model never knows it
        exists."""
        if not api_key:
            return {"error": "missing api_key"}
        message_id = state.write_email(to, subject, body, authenticated=True)
        return {"message_id": message_id, "status": "written-to-outbox"}

    @server.tool(description=BY_NAME["delete_customer"].description)
    def delete_customer(customer_id: str, reason: str) -> dict[str, Any]:
        deleted = state.soft_delete_customer(customer_id, reason)
        if deleted is None:
            return {"error": f"no such customer: {customer_id}"}
        return {"customer_id": deleted.customer_id, "deleted": True}

    return server


def main(
    state_dir: Path,
    appends: Sequence[Document] = (),
    replacements: Sequence[Document] = (),
    customer_overrides: Mapping[str, Mapping[str, str]] = {},
) -> None:
    state = DemoState(state_dir, customer_overrides)
    build_server(state, appends, replacements).run(transport="stdio")
