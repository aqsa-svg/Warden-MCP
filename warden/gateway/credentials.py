"""Credential holding, schema projection, and post-decision injection.

The agent sees tool schemas; Warden holds the credentials. The parameter Warden fills
is stripped from the schema the agent is shown, so the model never learns the
parameter exists and cannot supply a value for it.

Which parameters are credential-bearing comes from Warden's own configuration, never
from the server's tools/list. A server able to nominate its own parameters as
credential-bearing could induce Warden to hand it secrets -- the same
self-attestation boundary as retrieval_tools.

Two schemas, one hash: the registry pins and drift-checks the UPSTREAM schema, and the
agent-facing schema is a pure projection of it. A second hash over the projection
would be a derived value that can only ever agree.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

from warden.errors import WardenError


class CredentialConfigError(WardenError):
    """A credential was declared but is not available in the environment."""


class CredentialStore:
    """Tool -> {parameter: secret}.

    Values leave this object only into arguments, only after the authorization
    decision, and are never hashed, logged, or serialised.
    """

    def __init__(
        self,
        secrets: Mapping[str, Mapping[str, str]],
        declared: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._secrets = {tool: dict(params) for tool, params in secrets.items()}
        # Which parameters are credential-bearing is DECLARED, and is deliberately
        # independent of whether the value could be resolved. Deriving it from the
        # resolved secrets means a credential the gateway failed to load silently
        # stops being stripped, and the agent is shown a parameter it must never
        # see. Declaration drives the projection; resolution drives injection.
        self._declared = (
            {tool: frozenset(params) for tool, params in declared.items()}
            if declared is not None
            else {tool: frozenset(params) for tool, params in self._secrets.items()}
        )

    @classmethod
    def from_env(
        cls, spec: Mapping[str, Mapping[str, str]], *, require: bool = True
    ) -> CredentialStore:
        """Build from tool -> {parameter: ENV_VAR_NAME}.

        Values come from the environment so no secret is ever written into a config
        file that could be committed.
        """
        resolved: dict[str, dict[str, str]] = {}
        missing: list[str] = []
        for tool, params in spec.items():
            for parameter, env_var in params.items():
                value = os.environ.get(env_var)
                if not value:
                    missing.append(f"{tool}.{parameter} <- ${env_var}")
                    continue
                resolved.setdefault(tool, {})[parameter] = value
        if missing and require:
            raise CredentialConfigError(
                "credentials declared but unavailable: " + ", ".join(sorted(missing))
            )
        declared = {tool: frozenset(params) for tool, params in spec.items()}
        return cls(resolved, declared)

    def parameters_for(self, tool: str) -> frozenset[str]:
        """The DECLARED credential parameters, resolved or not. Drives projection."""
        return self._declared.get(tool, frozenset())

    def inject(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Add the tool's credentials.

        Called only after the decision is made and the audit row is committed, and
        always after args_hash has been computed over the un-injected arguments.
        """
        held = self._secrets.get(tool, {})
        unresolved = sorted(self._declared.get(tool, frozenset()) - set(held))
        if unresolved:
            # Fail closed. Forwarding without the credential would send the upstream
            # a call it will reject, having already stripped the parameter from the
            # agent's schema -- an unexplainable failure at the far end.
            raise CredentialConfigError(
                f"{tool} declares credentials that were never resolved: {unresolved}"
            )
        merged = dict(arguments)
        merged.update(held)
        return merged


def project_schema(
    upstream: Mapping[str, Any], credential_params: frozenset[str]
) -> dict[str, Any]:
    """The agent-facing schema: upstream minus the credential parameters."""
    projected: dict[str, Any] = dict(upstream)
    properties = upstream.get("properties")
    if isinstance(properties, dict):
        projected["properties"] = {
            name: value
            for name, value in properties.items()
            if name not in credential_params
        }
    required = upstream.get("required")
    if isinstance(required, list):
        projected["required"] = [
            name for name in required if name not in credential_params
        ]
    return projected


def assert_projection_is_subset(
    upstream: Mapping[str, Any], projected: Mapping[str, Any]
) -> None:
    """The projection may only remove.

    Adding or retyping a parameter would mean the agent is told about a schema
    upstream will reject. One cheap invariant catches the whole class.
    """
    upstream_properties = upstream.get("properties")
    projected_properties = projected.get("properties")
    up = upstream_properties if isinstance(upstream_properties, dict) else {}
    pr = projected_properties if isinstance(projected_properties, dict) else {}

    added = sorted(set(pr) - set(up))
    if added:
        raise WardenError(f"projection added parameters absent upstream: {added}")

    retyped = sorted(name for name in pr if pr[name] != up[name])
    if retyped:
        raise WardenError(f"projection altered parameter definitions: {retyped}")

    upstream_required = upstream.get("required")
    projected_required = projected.get("required")
    up_required = set(upstream_required) if isinstance(upstream_required, list) else set()
    pr_required = set(projected_required) if isinstance(projected_required, list) else set()
    widened = sorted(pr_required - up_required)
    if widened:
        raise WardenError(
            f"projection requires parameters upstream does not: {widened}"
        )
