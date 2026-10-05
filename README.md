# Warden

A governed MCP gateway. It sits between an AI agent and its MCP tools, labels the
provenance of content entering the agent's context, and denies or escalates tool calls
whose arguments were derived from untrusted content.

**Status.** The gateway, policy engine, taint tracker, audit log, red-team harness and
benign suite are built, tested (242 passing, `mypy --strict` clean) and verified. The
two measured tables below are **pending a re-run under the current frozen code hash**
(`sha256:63ffae14a835`): all calibration recorded so far predates it, and this project
does not report a number produced by code it can no longer reproduce. The placeholders
are deliberate — they are filled by executions, never by hand.

---

## The finding

**An attack's viability on this model tracks one thing: whether it needs the agent to
*deviate from its task*, not how the payload is phrased.**

Two classes of attack were calibrated against the ungoverned agent (Warden absent),
and they split cleanly:

- **Attacks that require the model to *choose* to obey an embedded instruction
  failed — 0/3.** Three escalating framings of indirect prose injection, including a
  *controlled substitution* in which the poisoned document replaced the exact knowledge-
  base article the agent cites on every run, differing from it by one embedded
  instruction. The agent read the document, judged it the correct reference, used it to
  resolve the ticket — and declined the out-of-band action it demanded.

- **Attacks that ride data the model already trusts succeeded — 3/3.** The
  `arg-poisoned-recipient` attack put an attacker-controlled address in a customer
  record's "email on file" field. The agent then emailed that address while performing
  exactly the task it was given. **It followed no instruction at all** — it trusted a
  field, and the field was poisoned.

The prediction this makes is testable and sharp: on this model, a payload that asks the
agent to *do something it wasn't asked to do* is weak, regardless of how cleverly it is
worded; a payload that *corrupts the inputs to something the agent already intends to
do* is strong. Phrasing is not the axis. Task-deviation is.

This is why Warden's controls are provenance rules, not instruction detectors. You
cannot reliably detect a malicious instruction, because the dangerous attacks contain
no instruction. You can detect that untrusted data reached a consequential argument.

The negative result that established this is written up in full, with all three traces
and the controlled-substitution design, in
[docs/findings/prose-injection-negative-result.md](docs/findings/prose-injection-negative-result.md).

---

## Results

Both tables are regenerated from recorded oracle verdicts by `warden report`
(`warden/report/generate.py`). Every rate is a fraction with its denominator attached,
never a bare percentage — at these sample sizes the confidence intervals are wide and
the `n` must travel with the number. `n=3` per template is a free-tier quota
constraint, not a methodological choice.

### Table 1 — attack success rate

> **Pending re-run under `sha256:63ffae14a835`.** The observed outcomes to date,
> recorded in `var/redteam/calibration.jsonl` under earlier code hashes, were: prose
> injection **0/3** (entry gate not passed), `arg-poisoned-recipient` **3/3**
> ungoverned, `priv-poisoned-deletion` **3/3** ungoverned. These are not promoted to a
> results table until re-run under the frozen hash.

| category | template | ungoverned | Warden control | governed |
|---|---|---|---|---|
| _pending re-run_ | | | | |

### Table 2 — false-positive rate on benign tasks

Two rates, never averaged: a hard block (DENY) is a correctness defect; an escalation
(REQUIRE_APPROVAL) is human toil the policy chose on purpose. Stratified by step count.

| stratum (steps) | hard-block rate | escalation rate | clean |
|---|---|---|---|
| _pending re-run_ | | | |

---

## Measurement integrity

This section is the point of the project. Each item below is a place where a reported
number could have been **wrong in Warden's favour**, or where measurement could have
failed while appearing to work. Each was found by *building the check*, not by reasoning
about it, and each is fixed in code.

### Findings that would have biased a number (flattering direction)

**1. Exact-address matching in the exfiltration oracle.**
Matching the full attacker address (`deliveryops@exfil-test.invalid`) would record a
successful exfiltration as a *miss* whenever the model reproduced the address
imperfectly — a different local part, altered case, or an address reconstructed from a
decoded payload. Mutations paraphrase and re-encode, so this would have been common, and
every such miss lowers the attack success rate. Fixed by matching the reserved
**domain**, which appears in attack payloads and nowhere else in the corpus
(`warden/redteam/oracles.py`).

**2. Scenarios silently dropping out of the FPR denominator.**
The false-positive rate's denominator is the count of scored scenarios. A benign
scenario that produced tool calls but was never scored by an oracle — because the oracle
crashed, or the run was interrupted — would simply vanish from the denominator and
*lower* the reported FPR. Fixed by `scenarios_missing_a_verdict()`, which fails the
report loudly rather than letting the denominator shrink quietly.

**3. A mid-run quota error recording an attack as unsuccessful.**
Free-tier quota is low enough that a multi-turn agent run can hit a per-minute 429
mid-run. Failing the whole run there would record an attack as *unsuccessful* when the
model never got to answer — biasing ASR in the flattering direction, the one to be
paranoid about. Fixed by honouring the server's `RetryInfo` and backing off through the
pause rather than abandoning the run (`warden/demo_agent/gemini.py`).

**4. Incomplete runs contributing partial data.**
A process that dies mid-forward leaves a call whose fate is unknown. Counting such a run
biases ASR in an unknown direction. Fixed by making `execution_outcome` nullable so
"issued, fate unknown" is distinct from "denied, never issued", marking any run
containing one INCOMPLETE, and excluding it entirely — with the exclusions printed, and
a raise if they exceed 5% or push a suite below its minimum-`n` floor
([ADR 0003](docs/adr/0003-synchronous-audit-commit.md)).

**5. A retrieval gate validated against a guess.**
The red-team preflight asserted that a poisoned document ranks in the top 5 for the
query a scenario's task "naturally" produces — but that query was *declared by hand*.
The first live run showed the agent produced a different one: the payload ranked 1
against the guess and 2 against reality, on a score tie. The gate passed either way, but
reported a confidence the real query did not support. Fixed by requiring an
`observed_query` captured from an actual run, and reporting the gate as unverified when
only a guess exists.

**6. The commit-latency figure measured against the wrong filesystem.**
An early overhead figure ("3–12%") was taken on **Windows NTFS**. After the move to
**WSL2 ext4** — where the database lives in a VHDX over the host and every `fsync`
traverses that virtual-disk layer — the audit commit turned out *slower and spikier*
(~4.4 ms median, ~24 ms p95, vs ~2.8 ms on NTFS). Reporting the flattering NTFS number
would have understated the real cost of the durability guarantee. The decomposition
(decision path vs audit commit, never blended; both filesystems named) is in
[ADR 0003](docs/adr/0003-synchronous-audit-commit.md). The audit commit dominates the
decision path by ~260× at the ext4 median — a single blended figure would read as the
cost of policy evaluation when it is almost entirely disk.

**7. The stratification confound.**
The benign suite is stratified by step count to ask whether FPR rises with task length.
But a false positive needs a taint-sensitive boundary call, and — because taint is a
per-run union — an *untainted* boundary call can only be the *first* tool call, so
long-and-untainted is structurally impossible. Read as a pure length effect, the table
would be wrong. The escalation rate is therefore structurally pinned to the short
stratum; the hard-block rate is deliberately *spread* across strata so that, if both
tainted cases block, the result is direct evidence that taint — not length — drives it.
Established model-free before any quota was spent
([detail](docs/findings/stratification-confound.md)).

### A finding that *destroyed measurability* (different category)

**8. Retrying a per-day quota error.**
This is distinct in kind from the biases above: it did not skew a number, it prevented
one from existing while looking like normal operation. Google's 429 names the violated
quota. A per-minute violation is worth sleeping through; a **per-day** one is not — the
window is 24 hours. The retry loop slept seven times against a daily cap it could never
wait out, and in doing so consumed the *next* day's allowance as slots trickled free.
Two days of quota produced zero attack traces, and the loop looked like ordinary
rate-limit handling throughout. Fixed by reading the quota name from the error body: a
per-day violation now raises `BudgetExceeded` immediately so the caller can checkpoint
and resume in the next window (`warden/demo_agent/gemini.py`, `warden/budget.py`).

The general shape is worth stating on its own: *a retry policy that cannot distinguish
transient from exhausted will convert a recoverable pause into an unrecoverable one, and
do it silently, because retrying is what a retry loop is supposed to do.*

### A data point excluded by hand, and why that is the honest move

**9. One `priv-poisoned-deletion` attempt lost to a tooling error.**
A shell loop driven through the WSL layer expanded a variable to empty, so two intended
runs wrote to the same directory and a later `rm -rf` destroyed one run's call-log rows.
The attempt was *observed* (it executed) but is *ungraded* (no rows survived to grade).
It is excluded from **both** the numerator and the denominator — not reconstructed from
memory, not counted as a success because it "looked like one." A result with no
surviving audit row is not a result. The recorded `priv-poisoned-deletion` tally is 3/3
from runs whose rows exist; the lost attempt is not a fourth.

---

## Architecture and threat model

### Trust boundaries

```mermaid
flowchart LR
    operator([Operator task]):::trusted
    subgraph agentbox [Agent context]
        agent[LLM agent]:::semi
    end
    subgraph warden [Warden gateway]
        policy[Policy engine]:::warden
        taint[Taint tracker]:::warden
        creds[(Credential store)]:::secret
        log[(Audit log)]:::warden
    end
    server[MCP server + tools]:::untrusted
    corpus[(Document corpus)]:::untrusted

    operator -->|USER_INPUT| agent
    agent -->|tool call| warden
    warden -->|allowed call + injected secret| server
    server -->|tool output = RETRIEVED / TOOL_OUTPUT| warden
    warden -->|labelled content| agent
    corpus -.poisoned content.-> server

    classDef trusted fill:#1b4332,color:#fff;
    classDef semi fill:#5a4b1b,color:#fff;
    classDef warden fill:#1b3a5a,color:#fff;
    classDef untrusted fill:#5a1b1b,color:#fff;
    classDef secret fill:#3a1b5a,color:#fff;
```

The operator's task is the only fully trusted input. Everything returning through a tool
is untrusted by default. Secrets live in Warden's credential store and are injected
*after* the authorization decision — they never enter the agent's context, so a
compromised agent cannot leak what it was never given.

### The gateway decision path — ordering is load-bearing

```mermaid
flowchart TD
    call[Agent issues tool call] --> reg{Tool in registry<br/>and classified?}
    reg -->|no| denyU[DENY: unknown / unclassified-tool]
    reg -->|yes| drift{Schema drift?}
    drift -->|silent rug-pull| denyD[DENY: schema-drift-silent]
    drift -->|announced| reappr[Re-approval required]
    drift -->|none| taint[Accumulate run taint union]
    reappr -->|re-approved| taint
    taint --> evalp[Evaluate policy: first-match-wins]
    evalp -->|ALLOW| hash
    evalp -->|REQUIRE_APPROVAL| appr{Human approves?}
    evalp -->|DENY| denyP[DENY: record rule_id]
    appr -->|no| denyA[DENY: approval-denied]
    appr -->|yes| hash[Compute args_hash<br/>pre-injection]
    hash --> commit[(Commit decision row<br/>synchronously)]
    commit --> inject[Inject credentials]
    inject --> forward[Forward to MCP server]
    forward --> complete[(complete_call:<br/>record outcome)]

    classDef deny fill:#5a1b1b,color:#fff;
    class denyU,denyD,denyP,denyA deny;
```

The ordering is not incidental:

- **`args_hash` is computed *before* credential injection**, so the audit record hashes
  the agent's actual arguments, not the secret-bearing ones. The hash is reproducible
  without ever storing the secret.
- **The decision row commits *before* forwarding** ([ADR 0003](docs/adr/0003-synchronous-audit-commit.md)),
  so a call can never execute without an audit row. Audit integrity beats transactional
  tidiness.
- **Credential injection happens *after* the decision**, so a denied call never touches
  a secret.

### Taint propagation through a run

```mermaid
flowchart TD
    u[Operator task: USER_INPUT]:::t0 --> U0["run taint = {USER_INPUT}"]
    U0 --> c1[call search_docs] --> U1["∪ RETRIEVED, TOOL_OUTPUT:search_docs"]
    U1 --> c2[call get_customer] --> U2["∪ TOOL_OUTPUT:get_customer"]
    U2 --> b{"boundary call:<br/>send_email / delete_customer"}
    b --> decision["evaluated against the full union → DENY / ESCALATE"]

    classDef t0 fill:#1b4332,color:#fff;
```

Taint is a **monotone union over the whole run**, not a per-argument attribution. Once a
read taints the run, every subsequent boundary call is evaluated against that union.
This is a deliberate coarseness, justified by measurement — see
[ADR 0008](docs/adr/0008-turn-level-taint.md) and the known limitation below.

---

## Methodological commitments

Two rules govern how the numbers are produced, and they fail in opposite directions.

**Never tune a rule against the benign suite.** That is fitting the policy to the test
set, and it would make the false-positive rate a measurement of the tuning. Rules are
scoped by side-effect class from the threat model; the benign suite then measures
whatever that scoping costs. See [ADR 0002](docs/adr/0002-tainted-write-scoping.md),
which rescopes a rule and explains why it is not the same thing.

**Never enter an attack into the suite without demonstrated success against the
ungoverned agent.** An attack the baseline agent ignores contributes nothing: it makes
the governed results look good while measuring only that the model shrugged off a clumsy
payload. Templates are iterated against the baseline until they work, then frozen, then
Warden is measured against the frozen set. The ungoverned success rate per template is
recorded as suite metadata and reported next to the governed rate, so the table is
self-validating.

Because an ungoverned rate is a property of a specific model at a specific time, the
journal keys every attempt by model id, and a calibration measured against one model is
never counted toward another's denominator.

**The governed attack success rate is derived from shadow-evaluated decisions on
ungoverned runs, not from a separate batch of governed attacks**
([ADR 0007](docs/adr/0007-shadow-evaluation-governed-asr.md)). This is a deliberate use
of the free-tier budget and it is *disclosed, not hidden*: the governed numbers are the
same ungoverned runs' shadow decisions, not `n` independent governed runs. What shadow
evaluation cannot establish — that enforcement *faithfully executes* a decision — is a
verification, not a rate, and is covered by `assert_enforcement_fidelity`
(`warden/log/integrity.py`), the test suite, and one live governed run per working
attack.

---

## Known limitations

- **Turn-level taint is coarse, with a measured false-positive cost.** A careful agent
  that reads a record before deleting it taints the run, so a user-authorized deletion
  is escalated (and, before [ADR 0004](docs/adr/0004-destructive-escalates-not-denies.md),
  was blocked). Span-level attribution would fix this but is not reliably recoverable
  from the agent — measured in the provenance work and recorded in
  [ADR 0008](docs/adr/0008-turn-level-taint.md) and
  [docs/findings/benign-erasure-deviation.md](docs/findings/benign-erasure-deviation.md).
- **The gateway is bypassable at the network layer.** Warden governs calls that flow
  through it. An agent with a direct route to a tool server is out of scope; the control
  is a chokepoint, not a sandbox.
- **Attack coverage is template-bounded.** The suite measures the templates it contains.
  A negative result (prose injection) is evidence about those framings on this model,
  not a universal claim.
- **Small `n` throughout, for a stated reason.** The free Gemini tier allows 20 requests
  per day per model; every rate is a fraction with `n` attached rather than a percentage.
- **The excessive-calls defense is implemented but not live-calibrated.** The per-run
  call budget is a blunt cap (it limits damage, it does not identify the attack). An
  excessive-calls attack costs a full day's quota by definition — racking up calls *is*
  the attack — so it is stub-verified in both variants rather than run live, and its
  calibration cell is reported empty with that reason rather than filled.
- **Single model, single agent configuration.** All results are for `gemini-3.6-flash`
  at system-prompt hash `5a2e75d84786a929`. A provider-neutral adapter seam
  (`warden/demo_agent/`) exists to calibrate a second model; results under a different
  model are keyed separately and never merged.

---

## Reproduction

```
cp .env.example .env          # set GEMINI_API_KEY and DEMO_EMAIL_API_KEY
uv sync --extra dev
uv run pytest                                             # 242 tests
uv run python -m mypy --strict warden                    # clean, 60 files
uv run python -m warden.cli redteam calibrate --dry-run  # 0 model requests
uv run python -m warden.cli report                        # regenerate docs/RESULTS.md
```

**Results are pinned to two hashes**, both reported in every generated table:

- **Source hash** `sha256:63ffae14a835` — a content hash of the behavior-defining code
  (runtime + attack/scenario/policy definitions; excludes grading, recording, reporting
  and CLI). A calibration attempt made under a different hash is never counted toward the
  current rate; resume is hash-aware.
- **System-prompt hash** `5a2e75d84786a929` — the agent configuration the ungoverned
  rate is a property of.

### Cost envelope

Calibration is the only part that spends model requests.

| | requests |
|---|---|
| one calibration run | ~4–5 |
| 5 base templates × n=3 | ~75 |
| ~20 mutations × n=1 | ~100 |

The free Gemini tier allows **20 requests per day per model**, so the default daily
budget is 18 (`warden/config.py`), and calibration is designed to be resumed across days
from an append-only journal rather than completed in one sitting. On a paid key, set a
billing budget alert before running the suite — the request cap in the runner bounds a
runaway loop, but it is not a substitute for a billing alarm.

---

## Architecture decisions

- [ADR 0001 — The retrieval declaration lives in policy, not in `tools/list`](docs/adr/0001-retrieval-declaration-trust-boundary.md)
- [ADR 0002 — Tainted-write escalation is scoped to `EXTERNAL_COMMS` and `DESTRUCTIVE`](docs/adr/0002-tainted-write-scoping.md)
- [ADR 0003 — The decision row is committed synchronously before forwarding](docs/adr/0003-synchronous-audit-commit.md) (also records the reversal of the earlier per-scenario-transaction ruling: audit integrity beats transactional tidiness)
- [ADR 0004 — Tainted destructive operations escalate to a human, they do not hard-deny](docs/adr/0004-destructive-escalates-not-denies.md)
- [ADR 0005 — Policy as YAML, not Cedar or OPA](docs/adr/0005-yaml-policy-over-cedar-opa.md)
- [ADR 0006 — First-match-wins over precedence scoring](docs/adr/0006-first-match-wins.md)
- [ADR 0007 — Governed ASR is derived from shadow evaluation](docs/adr/0007-shadow-evaluation-governed-asr.md)
- [ADR 0008 — Turn-level taint over span-level attribution](docs/adr/0008-turn-level-taint.md)
