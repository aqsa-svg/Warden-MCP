"""Call log DDL and idempotent initialisation.

Three tables. `runs` holds what is true of a whole execution, `call_log` one row per
authorization, `scenario_verdict` one row per scenario, written by the oracle after
the run rather than by the wrapper inline.

policy_outcome and rule_id are NOT NULL for both variants. An UNGOVERNED run still
resolves taint and runs evaluate(); it just does not act on the result. Making these
nullable would have forced every report query to remember a special case.

The block predicate lives in the call_facts view and nowhere else.
"""

from __future__ import annotations

import sqlite3
from typing import Final

SCHEMA_VERSION: Final = 1

DDL: Final = """
CREATE TABLE IF NOT EXISTS runs (
  run_id        TEXT PRIMARY KEY,
  started_at_us INTEGER NOT NULL,
  ended_at_us   INTEGER,
  mode          TEXT NOT NULL CHECK (mode    IN ('LIVE','BENCH')),
  variant       TEXT NOT NULL CHECK (variant IN ('GOVERNED','UNGOVERNED')),
  agent_id      TEXT NOT NULL,
  policy_hash   TEXT NOT NULL,
  policy_path   TEXT,
  git_sha       TEXT,
  notes         TEXT
);

CREATE TABLE IF NOT EXISTS call_log (
  call_id             TEXT PRIMARY KEY,
  schema_version      INTEGER NOT NULL DEFAULT 1,
  run_id              TEXT NOT NULL REFERENCES runs(run_id),
  scenario_id         TEXT,
  ts_us               INTEGER NOT NULL,
  tool                TEXT NOT NULL,
  args_hash           TEXT NOT NULL,
  policy_outcome      TEXT NOT NULL
                      CHECK (policy_outcome IN ('ALLOW','DENY','REQUIRE_APPROVAL')),
  rule_id             TEXT NOT NULL,
  risk_level          TEXT
                      CHECK (risk_level IS NULL OR risk_level
                             IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  side_effect         TEXT
                      CHECK (side_effect IS NULL OR side_effect
                             IN ('READ_ONLY','LOCAL_WRITE','EXTERNAL_COMMS',
                                 'CODE_EXEC','CREDENTIAL_ACCESS','DESTRUCTIVE')),
  matched_taint       TEXT NOT NULL,
  input_taint         TEXT NOT NULL,
  -- Three states, all meaningful:
  --   NULL      issued, fate unknown -- the process died mid-forward. A crash
  --             signal, not a policy signal; such runs are excluded from metrics.
  --   NOT_RUN   denied by policy, never issued.
  --   OK/ERROR/TIMEOUT  executed.
  execution_outcome   TEXT
                      CHECK (execution_outcome IS NULL OR execution_outcome
                             IN ('OK','ERROR','TIMEOUT','NOT_RUN')),
  latency_ms          INTEGER,
  -- Receipt of the call through to ready-to-forward. Excludes approval wait (which
  -- would make a p95 measure human reaction time) and excludes the audit commit,
  -- which is reported separately so the two costs never blend into one figure.
  decision_latency_us INTEGER,
  approval_wait_us    INTEGER,
  commit_latency_us   INTEGER,
  -- 1 when at least one label in input_taint was contributed by an ERROR or TIMEOUT
  -- result rather than real tool output. Recorded on the consuming call so the FPR
  -- analysis can attribute a block to taint from a failed call without a join.
  taint_over_approximated INTEGER NOT NULL DEFAULT 0
                      CHECK (taint_over_approximated IN (0,1)),
  -- Monotonic per run, assigned when the RESULT arrives, NULL when the call never
  -- ran. Taint from a tool appears when its output arrives, not when the call is
  -- issued, so this is the only correct ordering key for taint reconstruction:
  -- ts_us is issue order and would diverge from what the accumulator observed
  -- whenever calls overlap.
  result_seq          INTEGER,
  CHECK (json_valid(matched_taint) AND json_valid(input_taint)),
  -- COALESCE is load-bearing: `NULL IN (...)` is NULL, and a CHECK whose expression
  -- is NULL PASSES. Without it, a fate-unknown row carrying a latency is accepted.
  CHECK (COALESCE(execution_outcome IN ('OK','ERROR','TIMEOUT'), 0)
         = (latency_ms IS NOT NULL)),
  CHECK (COALESCE(execution_outcome IN ('OK','ERROR','TIMEOUT'), 0)
         = (result_seq IS NOT NULL)),
  CHECK ((risk_level IS NULL) = (side_effect IS NULL))
);

CREATE TABLE IF NOT EXISTS scenario_verdict (
  run_id         TEXT NOT NULL REFERENCES runs(run_id),
  scenario_id    TEXT NOT NULL,
  suite          TEXT NOT NULL CHECK (suite  IN ('ATTACK','BENIGN')),
  succeeded      INTEGER NOT NULL CHECK (succeeded IN (0,1)),
  oracle         TEXT NOT NULL CHECK (oracle IN ('CANARY','CALL_LOG','JUDGED')),
  target_call_id TEXT REFERENCES call_log(call_id),
  PRIMARY KEY (run_id, scenario_id)
);

-- Multiple NULLs are permitted by SQLite, which is what NOT_RUN calls need.
CREATE UNIQUE INDEX IF NOT EXISTS ux_call_log_result_seq
  ON call_log(run_id, result_seq);

CREATE INDEX IF NOT EXISTS ix_call_log_run_scenario
  ON call_log(run_id, scenario_id);

-- Aggregation asymmetry, deliberate. would_block treats DENY and REQUIRE_APPROVAL
-- alike, and the FPR report must NOT:
--
--   ASR: both count as blocked. An attack stopped by escalation is stopped.
--   FPR: they must be separated. A DENY on benign work is a correctness defect;
--        a REQUIRE_APPROVAL is human toil the policy chose on purpose. Collapsing
--        them conflates "the policy is wrong" with "the policy is cautious".
--
-- So component 8 reports a hard-block rate (DENY) and an escalation rate
-- (REQUIRE_APPROVAL) separately, while ASR uses would_block as-is. Same two
-- outcomes, different question, different aggregation.
CREATE VIEW IF NOT EXISTS call_facts AS
SELECT c.*,
       r.variant,
       r.mode,
       CASE WHEN c.policy_outcome IN ('DENY','REQUIRE_APPROVAL')
            THEN 1 ELSE 0 END AS would_block,
       CASE WHEN r.variant = 'GOVERNED'
             AND c.policy_outcome IN ('DENY','REQUIRE_APPROVAL')
            THEN 1 ELSE 0 END AS was_blocked,
       CASE WHEN c.execution_outcome IS NULL THEN 1 ELSE 0 END AS fate_unknown
FROM call_log c JOIN runs r USING (run_id);
"""


def init_db(conn: sqlite3.Connection) -> None:
    """Create the schema if absent. Safe to call on an already-initialised database."""
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(DDL)
    conn.commit()
