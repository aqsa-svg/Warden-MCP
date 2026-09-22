# ADR 0003 — The decision row is committed synchronously before forwarding

**Status:** accepted

## Context

The enforcement wrapper writes two rows per call: a decision row committed *before*
the call is forwarded, and an update once the result returns. That first commit is a
SQLite `fsync` on the request's critical path.

This overrides an earlier design decision (component 2) that the caller owned the
transaction so a scenario's calls would land atomically.

## Decision

The decision row is committed before forwarding, with SQLite at its default
`synchronous=FULL`. The commit cost is measured and reported separately from the
decision path, never blended into one figure.

## Rationale

With a scenario-scoped transaction, a process that dies mid-forward leaves a call that
**executed with no audit record at all**. That is the worst outcome this system can
produce: worse than a denied legitimate call, worse than a missing metric. A gateway
whose audit trail is incomplete precisely when something went wrong is not an audit
trail.

Audit integrity beats transactional tidiness.

`execution_outcome` is nullable so that "issued, fate unknown" is a representable
state distinct from `NOT_RUN` ("denied, never issued"). A row still NULL after the
fact means the process died between the two commits. Such runs are marked INCOMPLETE
and excluded from every metric rather than contributing partial data: silently
including a run of unknown fate biases ASR in an unknown direction, which is worse
than a smaller denominator.

## Rejected: WAL with `synchronous=NORMAL`

The obvious mitigation is `PRAGMA journal_mode=WAL` plus
`PRAGMA synchronous=NORMAL`, which would remove most of the fsync cost.

**Rejected, because `NORMAL` does not fsync the WAL on commit.** A power loss or OS
crash can lose recently committed transactions. That reintroduces the exact gap this
ADR exists to close — a tool call that executed with no audit record — and does so in
the failure mode where the audit trail matters most. Trading the guarantee for
latency is trading away the reason the two-phase write exists.

WAL with `synchronous=FULL` remains open as a future change: it keeps the durability
guarantee and can improve concurrency. It was not adopted here because the gateway is
single-writer, so there is no concurrency to win, and the fsync cost stays either way.

## Consequences — measured, not asserted

The commit cost depends on the filesystem, so both environments the project has run in
are reported with their filesystems named. They are not comparable tool-call figures
(taken differently — a few live GOVERNED calls on Windows, 20 stub-driven calls on
WSL2) but the decomposition is the point either way.

**Windows NTFS** (early live GOVERNED run, n=1 per tool):

| tool | decision path | audit commit | tool call | overhead |
|---|---|---|---|---|
| get_customer | 144 µs | 1653 µs | 105 ms | 1.7% |
| search_docs | 6278 µs | 1923 µs | 9 ms | 47.7% |
| create_ticket | 128 µs | 4571 µs | 13 ms | 26.5% |

**WSL2 ext4** (20 stub-driven calls, after the environment move; the db is on the Linux
filesystem, not `/mnt/c`):

| path | median | p95 | max |
|---|---|---|---|
| decision | 19 µs | 70 µs | 70 µs |
| audit commit | 4.4 ms | 23.9 ms | 23.9 ms |

The move changed the commit materially and in the less obvious direction: **WSL2 ext4
is slower and spikier than Windows NTFS** (~4.4 ms median, ~24 ms p95, vs ~2.8 ms),
because WSL2's ext4 lives in a VHDX over the host and every fsync traverses that
virtual-disk layer. The decision path, by contrast, is ~5× faster on Linux (~20 µs vs
~100 µs).

Three things these say, and one they do not:

1. **The audit commit dominates the decision path** — by ~260× at the ext4 median
   (4.4 ms vs 19 µs), more than an order of magnitude on NTFS. A single blended figure
   would read as the cost of policy evaluation when it is almost entirely disk. This is
   the whole reason the two are reported in separate columns. **260× is the headline.**
2. **As a fraction of end-to-end latency the overhead is not small, and the earlier
   NTFS "3–12%" figure does not survive the move.** It is fsync-bound, so it tracks the
   storage layer far more than the policy. Recomputed honestly at the WSL2 ext4 **p95
   commit of 23.9 ms**:

   | tool latency | overhead at p95 |
   |---|---|
   | demo local tool (~4 ms, unrepresentative) | ~86% |
   | realistic remote 50 ms | ~32% |
   | realistic remote 100 ms | ~19% |
   | realistic remote 200 ms | ~11% |

   So on this virtual disk the audit commit is roughly a fifth to a third of a
   realistic remote call at p95, and dominates a fast local one. The ruling stands — an
   unlogged execution is the worse outcome — but the cost is higher than first measured
   and is stated as measured, not as the flattering NTFS number.
3. **The demo server is unrepresentatively fast** — in-process, no network, no
   database. A realistic remote MCP tool would lift the denominator and shrink the
   fraction, per the table above. The honest claim is conditional on tool latency,
   never a single percentage.

What these do **not** support is a stable p95 for the decision path from a benchmark
run; the WSL2 figures are from a stub harness, and the p95 claim proper needs the
benchmark's own sample count.

`approval_wait_us` is recorded in its own column and excluded from
`decision_latency_us`. A p95 that included human reaction time would measure nothing.
