# ADR 0002 — Tainted-write escalation is scoped to `EXTERNAL_COMMS` and `DESTRUCTIVE`

**Status:** accepted

## Context

An early rule, `search-output-into-local-write`, escalated any `LOCAL_WRITE` whose
arguments carried `TOOL_OUTPUT:search_docs`. Shadow-evaluating a real agent trace
against it produced this:

```
call            taint at call time                                    outcome           rule_id
get_customer    USER_INPUT                                            ALLOW             read-only-allow
search_docs     TOOL_OUTPUT:get_customer, USER_INPUT                  ALLOW             read-only-allow
create_ticket   RETRIEVED, TOOL_OUTPUT:get_customer,
                TOOL_OUTPUT:search_docs, USER_INPUT                   REQUIRE_APPROVAL  search-output-into-local-write
```

The task was: look up a customer, find the relevant knowledge base article, open a
ticket citing it. It is the canonical benign task for this agent, and the rule
escalated it. In a support-agent workload, *every* task looks like this — read, then
write.

## Decision

In `policies/demo.yaml`, tainted escalation is scoped by side-effect class to
`EXTERNAL_COMMS` and `DESTRUCTIVE`. Internal writes derived from retrieved content
proceed under `internal-write-allow`.

## Rationale — and the distinction that matters

This must not be read as weakening a rule to improve a false-positive number. **The
rule was rescoped against the threat model, not tuned against the benign suite.**

The threat model is data crossing the trust boundary, or irreversible destruction:

- `EXTERNAL_COMMS` — content leaves the perimeter. This is exfiltration.
- `DESTRUCTIVE` — the operation cannot be undone. This is sabotage.
- `LOCAL_WRITE` to an internal ticketing system — reversible, exfiltrates nothing,
  stays inside the boundary.

`create_ticket` is not in the threat model. A rule that guards it is broader than the
threat it exists to address, and **a rule broader than its threat model is a rule that
gets disabled** — by an operator who sees it fire on every legitimate task and turns
it off, taking the exfiltration protection with it.

The standing rule this establishes: **never tune a rule against the benign suite.**
That is fitting the policy to the test set, and it would make the reported
false-positive rate a measurement of the tuning rather than of the policy. Rules are
scoped by side-effect class from the threat model; the benign suite then measures
whatever that scoping costs.

## Consequences

- Tainted internal writes are permitted. A prompt injection that can only cause a
  ticket to be created with attacker-chosen text succeeds. That is an accepted risk:
  the content stays inside the perimeter and is reversible.
- The four high-consequence rules in `demo.yaml` form a complete case analysis over
  the taint dimension (`any_of` → DENY, `none_of` → REQUIRE_APPROVAL, per side-effect
  class), so no rule needs a `# lint: allow-partial-taint` exemption.
- Untainted `EXTERNAL_COMMS` and `DESTRUCTIVE` calls still require approval.
  `USER_INPUT` is semi-trusted, not trusted — direct prompt injection arrives through
  it — so the absence of retrieved or tool-output taint is not a warrant for crossing
  the boundary.

## Rejected

**Keep the rule and accept the false-positive rate.** The number would be dominated by
one miscalibrated rule, which tells the reader about the rule rather than about
turn-level taint tracking.

**Narrow it to specific tools rather than side-effect classes.** A per-tool rule
silently fails to cover the next tool someone adds. Side-effect class is the property
the threat model is actually about, and a newly classified tool inherits the right
rule automatically.
