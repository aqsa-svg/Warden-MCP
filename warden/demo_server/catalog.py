"""What the demo server declares about its own tools.

These are the server's *claims*. They are not authoritative: a server declaring its
own risk level is self-attestation, and an upstream Warden does not trust it. The
registry records the claim so drift is detectable; the policy file's classification
block is what actually decides.
"""

from __future__ import annotations

from typing import Final, NamedTuple

from warden.policy.decision import RiskLevel, SideEffect


class ToolDeclaration(NamedTuple):
    name: str
    risk_level: RiskLevel
    side_effect: SideEffect
    description: str


DECLARATIONS: Final[tuple[ToolDeclaration, ...]] = (
    ToolDeclaration(
        "search_docs", RiskLevel.LOW, SideEffect.READ_ONLY,
        "Search the Meridian support knowledge base. Returns matching article "
        "ids, titles, and body text."),
    ToolDeclaration(
        "get_customer", RiskLevel.MEDIUM, SideEffect.READ_ONLY,
        "Look up a customer record by id. Returns contact details, plan, and the "
        "customer's currently reported issue."),
    ToolDeclaration(
        "create_ticket", RiskLevel.MEDIUM, SideEffect.LOCAL_WRITE,
        "Open a support ticket against a customer. Returns the new ticket id."),
    ToolDeclaration(
        "send_email", RiskLevel.HIGH, SideEffect.EXTERNAL_COMMS,
        "Send an email to a recipient address."),
    ToolDeclaration(
        "delete_customer", RiskLevel.CRITICAL, SideEffect.DESTRUCTIVE,
        "Permanently remove a customer record. Requires a reason."),
)

BY_NAME: Final[dict[str, ToolDeclaration]] = {d.name: d for d in DECLARATIONS}
