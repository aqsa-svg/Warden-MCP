# ADR 0005 — Policy as YAML, not Cedar or OPA

**Status:** accepted

## Context

Warden's authorization policy is a list of ordered rules, each matching on a tool's
side-effect class, risk level, and the taint present on the run, and resolving to ALLOW,
REQUIRE_APPROVAL or DENY. Policy-as-code engines exist for exactly this shape — AWS
Cedar, Open Policy Agent (Rego) — and reaching for one would be the conventional choice.

The question is whether a general policy engine earns its place in a single-tenant
gateway with a closed, small predicate vocabulary.

## Decision

The policy is a YAML file (`policies/*.yaml`), parsed into Pydantic v2 models with
`extra="forbid"`, evaluated by a ~100-line first-match-wins engine
(`warden/policy/engine.py`). No external policy engine is a dependency.

## Rationale

- **The predicate vocabulary is closed and tiny.** Rules predicate on a fixed set:
  side-effect class, risk level, and `any_of` / `none_of` over taint labels. There is no
  user-defined attribute algebra, no entity hierarchy, no cross-resource relationship to
  evaluate. Cedar and OPA are built to express things this policy deliberately cannot —
  and that expressiveness is attack surface and cognitive load, not benefit.
- **Validation and type-safety come from Pydantic, which is already a dependency.**
  `extra="forbid"` rejects an unknown key at load (a typo in a rule becomes a loud error,
  not a silently-ignored clause). Reserved rule ids are enforced in `warden/policy/rule_ids.py`.
  A Rego or Cedar policy would move this validation into a second language and a second
  toolchain.
- **Auditability of the decision.** A first-match-wins list is readable top-to-bottom by
  a human reviewer, and every decision records the exact `rule_id` that produced it. A
  general engine's evaluation trace is harder to tie to a single, citable line of policy.
- **The threat model is the specification.** Rules are scoped by side-effect class *from
  the threat model* ([ADR 0002](0002-tainted-write-scoping.md)), not tuned. A richer
  language invites tuning, which is the thing the methodology forbids.

## Migration threshold

This decision is scoped to the current shape and is expected to be revisited if **any**
of the following hold:

1. **Multi-tenancy** — per-tenant policies that must compose, or be delegated to tenant
   admins, need a real policy language with isolation guarantees.
2. **A relational predicate appears** — e.g. "allow if the caller owns the resource", or
   any rule that must reason over entity relationships rather than a tool's static
   classification. That is Cedar's home ground and hand-rolling it would be a mistake.
3. **Policy authorship leaves the operator** — if non-engineers must write policy with
   tooling support (linting, formal analysis, coverage), OPA's ecosystem becomes worth
   its weight.

Until one of those is real, a dependency-free YAML engine is the honest size of the
problem. The migration path is clean because the policy is already declarative data, not
imperative code.

## Rejected

- **Cedar now, for future-proofing.** Rejected: it pays the full cost of a policy
  language (new syntax, new validation, new failure modes) to buy expressiveness the
  threat model explicitly excludes. Adopting it before a relational predicate exists is
  speculative generality.
- **OPA/Rego as a sidecar.** Rejected: introduces a network hop or embedded runtime on
  the decision path, which [ADR 0003](0003-synchronous-audit-commit.md) is already
  measuring to the microsecond, for no gain at this vocabulary size.
