# ADR 0007 — Governed ASR is derived from shadow evaluation

**Status:** accepted

## Context

The headline comparison is ungoverned attack success rate vs governed attack success
rate. The obvious way to produce it is two batches of runs per attack: `n` runs with
Warden absent, `n` runs with Warden enforcing. At `n=3` across several templates and
mutations, on a free tier of 20 model requests per day, that doubling is the difference
between a week of calibration and two.

Warden's gateway already evaluates policy on **every** run — it only *enforces* the
decision when the run is governed. An ungoverned run therefore records, for each call, the
`policy_outcome` and `rule_id` Warden *would* have applied, while still executing the call
(the decision is shadowed, not enforced).

## Decision

**The governed attack success rate is derived from the shadow decisions recorded on the
ungoverned runs, not measured from a separate governed batch.** An ungoverned run that
succeeds as an attack, but whose shadow decision on the consequential call is DENY (or
REQUIRE_APPROVAL that would auto-deny in a benchmark), counts as an attack Warden would
have stopped.

This is paired with a **disclosure requirement** (below) and with a separate,
non-rate verification that enforcement is faithful.

## Rationale

- **It halves the quota cost of the central comparison** with no loss of validity for the
  rate itself: the shadow decision is the *same decision* the enforcing path would make,
  produced by the same code, on the same run.
- **It avoids a subtle confound.** Re-running an attack under enforcement produces a
  *different* run (the model is nondeterministic), so a separate governed batch measures
  Warden against different agent behaviour than the ungoverned batch. Deriving the governed
  outcome from the ungoverned run holds the agent's behaviour fixed and varies only whether
  the decision was enforced — which is exactly the contrast the table claims to show.

## The disclosure requirement

Shadow derivation changes what the governed column *is*, so it must never be read as `n`
independent governed runs. This is stated wherever the number appears:

- the README methodological-commitments section says it in words;
- `warden/report/generate.py` labels the governed column as the control Warden applies and
  whether enforcement was confirmed live or is shadow-derived;
- a rate below `n=3` is rendered as a bare fraction, and suite metadata marks a template
  as gate-satisfied-but-rate-unestablished until it reaches `n=3`.

Hiding the derivation would make the governed column look like twice the evidence it is.
Disclosing it is the condition on which the shortcut is legitimate.

## What shadow evaluation cannot establish

Shadow evaluation proves what Warden would *decide*. It does **not** prove that
enforcement *faithfully executes* that decision — that a call decided DENY actually did not
run, or that an ALLOW did. That is a verification, not a rate, and `n=1` suffices for it.
It is covered by:

- `assert_enforcement_fidelity` (`warden/log/integrity.py`), which fails loudly if any
  governed call's execution diverged from its decision — a DENY that ran, or an ALLOW that
  did not;
- the gateway wrapper tests and the credential-isolation suite;
- one live GOVERNED run per working attack, as the end-to-end confirmation.

## Rejected

- **Measure a full governed batch.** Rejected on cost, and — more importantly — because it
  introduces the nondeterminism confound above. It remains available for any result where
  the shadow assumption is in doubt.
- **Report governed numbers without the disclosure.** Rejected: it would overstate the
  independence of the evidence. The shortcut is only sound because it is disclosed.
