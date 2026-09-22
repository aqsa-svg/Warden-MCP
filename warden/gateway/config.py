"""Gateway configuration that is Warden's to declare, not the server's."""

from __future__ import annotations

from typing import Final, Mapping

CREDENTIAL_SPEC: Final[Mapping[str, Mapping[str, str]]] = {
    "send_email": {"api_key": "DEMO_EMAIL_API_KEY"},
}
"""Tool -> {parameter: ENV_VAR}.

Warden's own declaration. A server able to nominate its parameters as
credential-bearing could induce Warden to hand it secrets, so this never comes from
tools/list. A real deployment would resolve these from a secrets manager.
"""


def credential_env_vars() -> tuple[str, ...]:
    """Env vars the gateway process needs.

    MCP's stdio_client passes a minimal allowlist environment to a spawned server
    rather than inheriting the parent's -- a credential-isolation boundary the SDK
    provides for free. Secrets therefore have to be handed to the gateway
    explicitly. The gateway passes none of them downstream: the upstream server
    receives credentials only inside call arguments, after authorization.
    """
    return tuple(
        sorted({env for params in CREDENTIAL_SPEC.values() for env in params.values()})
    )
