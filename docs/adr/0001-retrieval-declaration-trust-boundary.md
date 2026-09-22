# ADR 0001 — The retrieval declaration lives in policy, not in `tools/list`

**Status:** accepted

## Context

A `TaintLabel` has three variants: `USER_INPUT`, `RETRIEVED`, and
`TOOL_OUTPUT:<tool>`. In an MCP architecture every piece of non-operator content
arrives through a tool call, so `RETRIEVED` cannot be an independent provenance
channel. It can only mean *this tool reads a document or knowledge store*.

Something has to declare which tools those are. The two candidates are the server
(via `tools/list` metadata or MCP tool annotations) and the operator (via the policy
file).

## Decision

`retrieval_tools` is a key in the policy YAML, validated by Pydantic at load. Warden
never reads a provenance claim from the server.

## Rationale

The decisive argument is not "avoid self-attestation" in the abstract. It is that
**server self-attestation lets a compromised or malicious MCP server shed taint.** A
server that could declare its own provenance would simply announce itself as
non-retrieval, and everything it returned would stop being treated as untrusted —
silently, with no error and no signal in the log. The attack requires no exploit; it
requires editing one field in a response.

The trust boundary is exactly at the classification. So the classification is the
operator's to make.

The same reasoning applies to two other declarations, and they are deliberately
symmetric:

- **`classification`** (risk level and side effect per tool) — a server could declare
  `delete_customer` as `READ_ONLY`.
- **Credential-bearing parameters** (ADR 0003, in `warden/gateway/credentials.py`) — a
  server able to nominate its own parameters as credential-bearing could induce
  Warden to hand it secrets.

## Consequences

- A newly discovered tool is untriaged until an operator classifies it, and resolves
  to `unclassified-tool`, which denies. Default deny is the cost and the point.
- The policy file must be maintained as the upstream tool set changes. Schema-drift
  detection exists partly to make that maintenance burden visible rather than silent.
- Retrieval tools emit **both** `RETRIEVED` and `TOOL_OUTPUT:<tool>` rather than
  `RETRIEVED` alone. Disjoint labels would mean a rule matching only
  `kind: TOOL_OUTPUT` silently misses the most obviously untrusted source in the
  system. Redundancy fails safe; disjointness fails silent. The taint lint also
  enforces that high-consequence rules name both, but a lint is the wrong thing to
  hang a security invariant on.

## Rejected

**Trust the server's declaration and detect lies via drift.** Drift detection compares
a schema against its own pin; it cannot tell you that a claim was false from the
outset. A server that declares itself non-retrieval on first contact is never
inconsistent with itself.
