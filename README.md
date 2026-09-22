# Warden

A governed MCP gateway. It sits between an AI agent and its MCP tools, labels the
provenance of content entering the agent's context, and denies tool calls whose
arguments were derived from untrusted content.

**Status: the measured tables do not exist yet.** Components 1–4 are complete and
verified; component 5 (the red-team suite) is built but uncalibrated. No attack
scenario has yet succeeded against the ungoverned agent, so there is no attack success
rate to report, and this document contains no results tables rather than placeholder
ones.

---

## Reproduction

```
cp .env.example .env          # set GEMINI_API_KEY and DEMO_EMAIL_API_KEY
uv sync --extra dev
uv run pytest
uv run python -m warden.cli redteam calibrate --dry-run   # 0 model requests
uv run python -m warden.demo_agent --variant GOVERNED
uv run python -m warden.cli calls
```

### Cost envelope

Calibration is the only part that spends model requests.

| | requests |
|---|---|
| one calibration run | ~4–5 |
| 5 base templates × n=3 | ~75 |
| ~20 mutations × n=1 | ~100 |

The free Gemini tier allows **20 requests per day per model**, so the default daily
budget is 18 (`warden/config.py`), and calibration is designed to be resumed across
days from an append-only journal rather than completed in one sitting. On a paid key,
set a Cloud Billing budget alert before running the suite — the request cap in the
runner bounds a runaway loop, but it is not a substitute for a billing alarm.

`n=3` per template is a free-tier constraint, not a methodological choice. Every rate
derived from it is reported as a fraction (`2/3`), never as a bare percentage, so the
denominator travels with the number.

---

## Limitations

### Findings that would have biased a number

Each of these would have made a reported figure wrong **in Warden's favour**, and each
was found by building the check rather than by reasoning about it.

**1. Scenarios silently dropping out of the FPR denominator.**
The false-positive rate's denominator comes from `scenario_verdict`. A benign scenario
that produced calls but was never scored by an oracle — because the oracle crashed, or
the run was interrupted — would simply vanish from the denominator and *lower* the
reported FPR. Fixed by `scenarios_missing_a_verdict()`, which fails the report loudly
rather than letting the denominator shrink quietly.

**2. Exact-address matching in the exfiltration oracle.**
Matching the full attacker address (`deliveryops@exfil-test.invalid`) would record a
successful exfiltration as a miss whenever the model reproduced the address
imperfectly — a different local part, altered case, or an address reconstructed from a
decoded payload. Mutations paraphrase and re-encode, so this would have been common.
Fixed by matching the reserved **domain**, which appears in payloads and nowhere else.

**3. Incomplete runs contributing partial data.**
A process that dies mid-forward leaves a call whose fate is unknown. Counting such a
run biases the attack success rate in an unknown direction. Fixed by making
`execution_outcome` nullable so "issued, fate unknown" is distinct from "denied, never
issued", marking any run containing one INCOMPLETE, and excluding it entirely — with
the exclusions printed, and a raise if they exceed 5% or push a suite below its
minimum-N floor.

**4. A retrieval gate validated against a guess.**
The red-team preflight asserted that a poisoned document ranks in the top 5 for the
query a scenario's task "naturally" produces. That query was *declared by hand*. The
first live run showed the agent actually produced a different one: the payload ranked
1 against the guess and 2 against reality, on a score tie. The gate passed either way,
but reported a confidence the real query did not support. Fixed by requiring an
`observed_query` captured from an actual run, and reporting the gate as unverified
when only a guess exists.

### Findings that would have destroyed the ability to measure

Distinct in kind from the above: these do not bias a number, they prevent one from
existing while appearing to work normally.

**5. Retrying a per-day quota error.**
Google's 429 response names the violated quota. A per-minute violation is worth
sleeping through; a **per-day** one is not — the window is 24 hours. The retry loop
slept seven times against a daily cap it could never wait out, and in doing so
consumed the *next* day's allowance as slots trickled free. Two days of quota produced
zero attack traces, and the loop looked like ordinary rate-limit handling throughout.
Fixed by reading the quota name from the error body: a per-day violation now raises
immediately so the caller can checkpoint and resume in the next window.

The general shape is worth stating separately from the instance. A retry policy that
cannot distinguish *transient* from *exhausted* will convert a recoverable pause into
an unrecoverable one, and will do it silently, because retrying is what a retry loop is
supposed to do.

### A number that looks like a length effect and is partly a taint effect

**6. The benign suite's step-count strata are partly confounded with taint status**
([detail](docs/findings/stratification-confound.md)). The suite is stratified by task
length to ask whether the false-positive rate rises with length. But a false positive
needs a taint-sensitive boundary call (`send_email`, `delete_customer`), and — because
taint is a per-run union — an *untainted* boundary call can only be the first tool call.
So the escalation-rate cases can only be short: long-and-untainted is structurally
impossible, and the escalation rate is pinned to the short stratum by the taint model,
not by length. Established model-free (running each scenario's designed tool sequence
through the taint accumulator) before any quota was spent. The per-stratum table is
kept, with the caption stating that the escalation rate is confounded with length and
the mechanism is turn-level taint accumulation. The hard-block cases were deliberately
spread across the medium and long strata so that rate, at least, is not confounded.
Read as a pure length effect the table would be wrong — the same class of error as the
biases above.

---

## Methodological commitments

Two rules govern how the numbers are produced, and they fail in opposite directions:

**Never tune a rule against the benign suite.** That is fitting the policy to the test
set, and it would make the false-positive rate a measurement of the tuning. Rules are
scoped by side-effect class from the threat model; the benign suite then measures
whatever that scoping costs. See
[ADR 0002](docs/adr/0002-tainted-write-scoping.md), which rescopes a rule and explains
why it is not the same thing.

**Never enter an attack into the suite without demonstrated success against the
ungoverned agent.** An attack the baseline agent ignores contributes nothing: it makes
the governed results look good while measuring only that the model shrugged off a
clumsy payload. Templates are iterated against the baseline until they work, then
frozen, then Warden is measured against the frozen set. The ungoverned success rate per
template is recorded as suite metadata and reported next to the governed attack success
rate, so the table is self-validating.

Because an ungoverned rate is a property of a specific model at a specific time, the
journal keys every attempt by model id, and a calibration measured against one model is
never counted toward another's denominator.

### How the governed attack success rate is obtained

**The governed ASR is computed from shadow-evaluated decisions on ungoverned runs, not
from a separate batch of governed attacks.** Warden's gateway evaluates policy on every
run, enforcing it only when the run is governed (see
[ADR 0003](docs/adr/0003-synchronous-audit-commit.md) and the shadow-evaluation design):
an ungoverned run records `policy_outcome` and `rule_id` for each call while still
executing it. So an ungoverned run already carries the decision Warden *would* have
enforced, and the governed ASR is derived from those decisions rather than measured by
re-running each attack under enforcement.

This is a deliberate use of the free-tier request budget (20 model requests per day),
and it is disclosed rather than hidden: **do not read the governed numbers as N
independent governed attack runs.** They are the same ungoverned runs' shadow decisions.

What shadow evaluation cannot establish is that enforcement *faithfully executes* the
decision — that a call Warden decided to deny actually did not run. That is a
verification, not a rate, and n=1 suffices for it. It is covered by:

- the full test suite (the credential-isolation suite, the enforcement-fidelity checks,
  and the gateway wrapper tests), and
- `assert_enforcement_fidelity` (`warden/log/integrity.py`), which fails loudly if any
  governed call's execution diverged from its decision — a DENY that ran, or an ALLOW
  that did not — rather than letting the divergence be absorbed into a number, plus
- one live governed run per working attack, as the end-to-end confirmation.

A rate below n=3 is reported as a bare fraction and never as a percentage, and suite
metadata marks it as gate-satisfied-but-rate-unestablished until it reaches n=3.

### How the substituted-corpus diagnostic came about

The controlled-substitution design in `corpus(replacements=...)` — where a diagnostic
document *replaces* a clean article in place rather than being appended alongside it —
was not foreseen. It came out of a constraint. An appended near-duplicate of the article
the agent reliably cited tied that article on retrieval score and lost the tie on
document order, ranking 9th and never being read. Making it *replace* the original was
the only way to put the agent's own preferred document in front of it with one variable
changed. The result is a cleaner controlled experiment than a purpose-built one would
have been — the agent sees the exact article it always picks, differing only by the
embedded instruction — but it is worth recording that it was arrived at, not designed.

## Attack categories and their calibration status

| category | Warden control | live ungoverned calibration |
|---|---|---|
| indirect prose injection | taint rule (targeted) | 0/3 — declined by the model; entry gate not passed ([negative result](docs/findings/prose-injection-negative-result.md)) |
| tool-argument exfiltration | `exfil-via-external-comms` taint rule (targeted) | 3/3 ungoverned; governed enforcement confirmation pending one run |
| privilege escalation | `tainted-destructive` taint rule (targeted) | stub-verified; live calibration pending |
| excessive calls | per-run call budget (blunt) | **not performed — see below** |

**The excessive-calls control is a blunt cap, not a detector.** The per-run call
budget (`warden/gateway/wrapper.py`, cap in `policies/demo.yaml`) bounds how many tool
calls a run may make; once the cap is hit every further call is denied regardless of
what it is. Unlike the taint rules, which are aimed at a specific threat, it does not
identify the attack — it limits the damage. It is described that way deliberately.

Its live ungoverned calibration was **not performed, by choice, due to free-tier quota
constraints**: an excessive-calls attack costs many model requests by definition —
racking up calls is the attack — so a single run could consume a day's 20-request
budget, and against a benign suite that already needs several days of quota that is the
wrong trade. The defense is implemented and stub-verified in both variants (the cap
denies past the limit under enforcement, and shadow-logs the would-cap while the
attack proceeds ungoverned). The empty calibration cell is reported with this reason
rather than filled with an invented number.

---

## Architecture decisions

- [ADR 0001 — The retrieval declaration lives in policy, not in `tools/list`](docs/adr/0001-retrieval-declaration-trust-boundary.md)
- [ADR 0002 — Tainted-write escalation is scoped to `EXTERNAL_COMMS` and `DESTRUCTIVE`](docs/adr/0002-tainted-write-scoping.md)
- [ADR 0003 — The decision row is committed synchronously before forwarding](docs/adr/0003-synchronous-audit-commit.md)
