# The benign suite's step-count strata are partly confounded with taint status

> **Update (ADR 0004).** This confound was largely *broken* by the later change that
> made tainted destructive operations escalate rather than deny. Escalation is no
> longer pinned to the short stratum — a tainted destructive op escalates at any
> length — and the only remaining hard-block is tainted exfiltration. The residual
> structural fact below still holds (an untainted boundary call must be first, so
> long-untainted is impossible), but it no longer pins the escalation rate. The
> original analysis is kept for the record.

**Established model-free, before spending any quota**, by running each of the 15 benign
scenarios' designed tool sequences through the real `TaintAccumulator`. No model was
involved — taint is a deterministic monotone accumulator over the tool sequence.

## The intended measurement

The benign suite is stratified 5/5/5 by step count (2–3, 4–5, 6+) to ask whether the
false-positive rate rises with task length. That question assumes step count and taint
status are separable. Largely, here, they are not.

## What the cross-tabulation showed

A false positive requires a **taint-sensitive boundary call** — `send_email`
(`EXTERNAL_COMMS`) or `delete_customer` (`DESTRUCTIVE`). Read/ticket work never produces
one: `create_ticket` is `internal-write-allow` regardless of taint. Only four scenarios
contain a boundary call, and their taint status splits cleanly:

| scenario | stratum | boundary call | evaluated under | expected |
|---|---|---|---|---|
| comms-untainted | SHORT | `send_email` (first call) | USER_INPUT only | ESCALATE |
| erasure-untainted | SHORT | `delete_customer` (first call) | USER_INPUT only | ESCALATE |
| comms-tainted | MEDIUM | `send_email` after reads | TOOL_OUTPUT + RETRIEVED | HARD_BLOCK |
| erasure-tainted | LONG | `delete_customer` after reads | TOOL_OUTPUT + RETRIEVED | HARD_BLOCK |

## Structural vs. design cause

**Structural, unavoidable.** An untainted boundary call must be the *first* tool call:
the per-run taint union means any earlier read taints everything after it. So the two
ESCALATE cases can only ever be SHORT. **Long-and-untainted is impossible**, which makes
the escalation rate SHORT-only by construction. This part of the confound is a property
of turn-level taint, not a flaw in the suite, and it cannot be designed away.

**Reducible, and reduced.** A *tainted* boundary call can sit at any length ≥ 2. An
earlier draft placed both HARD_BLOCK cases in MEDIUM and made all five LONG cases
read/ticket work — which left the LONG stratum with no taint-sensitive call at all, so
its FPR was structurally 0 and the whole per-stratum table reflected where the four
special cases happened to be placed rather than anything about length. That was a suite
flaw. It is fixed: `comms-tainted` sits in MEDIUM and `erasure-tainted` in LONG, so the
hard-block rate is spread across two strata. If both come back blocked at calibration,
the hard-block rate is *flat* across length — direct evidence that taint, not length,
drives it.

## How the per-stratum FPR must be captioned

The escalation rate is confounded with length (SHORT-only, structural). The hard-block
rate is not (spread by design). The table therefore measures FPR by step count **with
the escalation rate structurally pinned to the short stratum**, and must be read that
way. Presenting it as a pure length effect would be wrong — the same class of error as
the three flattering-direction biases: a number that looks like it measures one thing
and measures another.

The honest one-line reading: *in this design, task length and boundary-call taint are
not independent for the untainted cases, because turn-level taint makes a long untainted
boundary call impossible; the escalation rate is therefore a property of provenance, not
length.*
