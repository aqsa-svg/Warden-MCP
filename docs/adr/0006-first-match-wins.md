# ADR 0006 — First-match-wins over precedence scoring

**Status:** accepted

## Context

A policy is an ordered list of rules. When a tool call could match more than one rule,
something has to decide which rule governs. There are two broad families:

- **First-match-wins** — rules are evaluated top to bottom; the first that matches
  decides, and evaluation stops.
- **Precedence scoring** — every matching rule is collected, and a resolution function
  (most-specific-wins, highest-priority-wins, explicit DENY-overrides-ALLOW, numeric
  weights) picks the winner.

## Decision

Warden evaluates rules **first-match-wins**, in file order, with a synthetic terminal
**default-deny** rule appended after the operator's rules
(`warden/policy/engine.py`). The matched rule's `rule_id` is recorded on the decision.

## Rationale

- **The policy is readable as a sequence.** A reviewer reads top to bottom and can state,
  for any call, which rule fires — because it is the first one that matches, full stop.
  Precedence scoring requires simulating the resolution function in your head over the
  *set* of matches, which is where authors form wrong mental models of their own policy.
- **Order is an explicit, visible control.** "Put the specific deny above the general
  allow" is a decision the author makes and can see on the page. With scoring, specificity
  is inferred by the engine, and two rules can tie, forcing yet another tie-break rule
  that lives in the engine rather than the policy.
- **The terminal default-deny is a rule, not a fallthrough.** Appending default-deny as an
  actual last rule means an unmatched call produces a normal decision with a real
  `rule_id` (`default-deny`), not a special-cased null path. Default deny is the posture,
  and making it a rule keeps the "no rule matched" case on the same audited code path as
  every other decision.
- **It composes with the closed predicate vocabulary** ([ADR 0005](0005-yaml-policy-over-cedar-opa.md)).
  With no relational predicates, there is no case where "most specific" is genuinely more
  correct than "first in an order the author chose".

## Consequences

- **A shadowed rule is an author error, and is caught.** A rule that can never fire
  because an earlier rule always matches first is a latent bug. The test suite includes
  shadowed-rule detection so this surfaces at review rather than hiding as a clause that
  silently never runs.
- **Rule ids are unique and append-only.** Because decisions are audited by `rule_id`,
  reusing or renumbering an id would corrupt the meaning of historical audit rows. Ids are
  reserved and validated (`warden/policy/rule_ids.py`).
- **Reordering is a semantic change.** Moving a rule can change outcomes, so policy order
  is reviewed like code, not treated as cosmetic.

## Rejected

- **DENY-overrides (collect all matches, deny if any denies).** Rejected: it sounds safe
  but it hides which rule denied behind "some rule did", weakening the audit trail, and it
  removes the author's ability to write a narrow allow that intentionally sits above a
  broad deny.
- **Numeric priority weights.** Rejected: weights are a second, invisible ordering layered
  on top of file order, and tuning weights to get the desired outcome is exactly the kind
  of fitting the methodology forbids. File order is the one ordering, and it is visible.
