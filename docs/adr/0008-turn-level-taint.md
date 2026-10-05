# ADR 0008 — Turn-level taint over span-level attribution

**Status:** accepted

## Context

Warden has to decide whether a consequential argument (the recipient of a `send_email`,
the id of a `delete_customer`) was derived from untrusted content. Two granularities are
possible:

- **Span / argument-level attribution** — track provenance per field, so the system can
  say "this specific argument came from the operator's task" vs "this one came from a
  retrieved document", and gate the call on the provenance of the *argument that matters*.
- **Turn / run-level taint** — track a single monotone union of taint labels over the whole
  run, and gate a boundary call on whether the run as a whole has touched untrusted content.

Span-level is strictly more precise and would eliminate a known class of false positive
(a user-authorized deletion that follows a benign read). The question is whether that
precision is *reliably recoverable* from a real agent.

## Decision

Warden tracks taint at **run level**, as a monotone union
(`warden/taint/`). A boundary call is evaluated against the full accumulated union, not
against the provenance of its individual arguments.

## Rationale — the measured justification

The project's provenance work ran a live `gemini-3.6-flash` trace to test whether
argument provenance could be recovered by matching an argument back to its source. It
could not, reliably: in one measured case **the model copied a customer field into a query
after lowercasing a single character**. A span tracker keyed on value identity loses the
link at that point — the argument no longer byte-matches its source — and would mislabel
attacker-influenced data as clean. That is a false *negative* on a security control, the
dangerous direction.

The failure is fundamental, not an implementation gap: the agent transforms content
freely (paraphrase, case-fold, reformat, decode), so there is no robust, model-agnostic
way to attribute a transformed argument to its origin without the model's cooperation —
which an attacker-influenced step will not reliably give. Turn-level taint makes no attempt
to follow the value; it records that the run *touched* an untrusted source and treats every
later boundary call accordingly. It cannot be defeated by a transformation.

## Consequences — the cost, measured not hidden

The cost is coarseness, and it is reported as a measured false positive rather than
asserted as acceptable:

- A careful agent that **reads a record before deleting it** taints the run, so a
  user-authorized deletion is caught by the destructive taint rule even though the
  *argument* (the customer id) came from the operator
  ([docs/findings/benign-erasure-deviation.md](../findings/benign-erasure-deviation.md)).
- Because the benign deletion and the privilege-escalation attack are **observably
  identical at turn level**, the rule cannot be made smarter without the span-level
  attribution this ADR rejects. The resolution was therefore not a smarter rule but a
  policy change: [ADR 0004](0004-destructive-escalates-not-denies.md) makes a tainted
  destructive operation *escalate to a human* rather than hard-deny — moving the false
  positive from the correctness-defect column (DENY) to the designed-toil column
  (REQUIRE_APPROVAL), while still stopping the attack.
- It also drives the stratification confound
  ([docs/findings/stratification-confound.md](../findings/stratification-confound.md)): an
  *untainted* boundary call can only ever be the first tool call, because any earlier read
  taints the run.

## Rejected

- **Span-level attribution by value matching.** Rejected: measured to produce a false
  negative under a one-character transformation, which is the worst failure direction for a
  security control.
- **Span-level attribution by asking the model to self-report provenance.** Rejected: an
  attacker-influenced step is exactly where self-reported provenance is least trustworthy.
- **Resetting taint between sub-tasks within a run.** Rejected: it reintroduces the
  transformation-laundering gap (read untrusted content, "finish" a sub-task, then act on
  laundered data in a fresh clean context).

The coarseness is a deliberate, measured trade: a known and bounded false-positive cost in
exchange for a control that a content transformation cannot silently defeat.
