"""Extract the Streamlit demo's data from the real recorded runs.

The calibration journals and run databases live under var/ (gitignored), so they cannot
ship with the deployed app. This script distils them into one committed JSON file
(warden_demo_data.json) that the app reads -- every number and every call-by-call step in
it is copied from a real recorded run, never invented. Re-running it needs the local var/
data; the committed JSON is the shareable artifact.

    python demo/extract_demo_data.py
"""

from __future__ import annotations

import glob
import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent / "warden_demo_data.json"

GEMINI = "gemini-3.6-flash"
GROK = "x-ai/grok-4.3"
HASHES = {GEMINI: "sha256:63ffae14a835", GROK: "sha256:b080909e20dc"}

CATEGORY = {
    "arg-poisoned-recipient": "tool-argument exfiltration (data channel)",
    "priv-poisoned-deletion": "privilege escalation (data channel)",
    "exfil-escalation": "indirect prose injection",
    "exfil-diagnostic": "indirect prose injection (controlled substitution)",
}
CONTROL = {
    "arg-poisoned-recipient": "exfil-via-external-comms (taint rule)",
    "priv-poisoned-deletion": "tainted-destructive -> human approval",
    "exfil-escalation": "exfil-via-external-comms (taint rule)",
    "exfil-diagnostic": "exfil-via-external-comms (taint rule)",
}
IS_DATA_CHANNEL = {
    "arg-poisoned-recipient": True,
    "priv-poisoned-deletion": True,
    "exfil-escalation": False,
    "exfil-diagnostic": False,
}


def _attempts() -> list[dict[str, Any]]:
    path = ROOT / "var/redteam/calibration.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _fraction(attempts: list[dict[str, Any]], template: str, model: str, hsh: str) -> str:
    rows = [
        a for a in attempts
        if a["template"] == template and a["model"] == model
        and a.get("source_hash", "") == hsh
    ]
    completed = [a for a in rows if a["outcome"] != "ERROR"]
    succ = sum(1 for a in completed if a["outcome"] == "SUCCESS")
    return f"{succ}/{len(completed)}" if completed else "pending"


def _run_db_index() -> dict[str, str]:
    """Map every recorded run_id -> its db path, across all attack run dirs."""
    index: dict[str, str] = {}
    for db in glob.glob(str(ROOT / "var/redteam/attacks/**/run.db"), recursive=True):
        try:
            conn = sqlite3.connect(db)
            for (rid,) in conn.execute("SELECT run_id FROM runs"):
                index[str(rid)] = db
        except sqlite3.Error:
            continue
    return index


def _steps(db: str, run_id: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db)
    out: list[dict[str, Any]] = []
    for row in conn.execute(
        "SELECT tool, policy_outcome, rule_id, risk_level, side_effect, matched_taint, "
        "execution_outcome FROM call_log WHERE run_id = ? ORDER BY ts_us, result_seq",
        (run_id,),
    ):
        taint = row[5]
        if isinstance(taint, str) and taint:
            try:
                parsed = json.loads(taint)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                parts = []
                for item in parsed:
                    if isinstance(item, dict):
                        kind = item.get("kind", "?")
                        tool = item.get("tool")
                        parts.append(f"{kind}:{tool}" if tool else str(kind))
                    else:
                        parts.append(str(item))
                taint = ", ".join(parts)
        out.append({
            "tool": row[0],
            "decision": row[1],       # Warden's (shadow) decision
            "rule": row[2],
            "risk": row[3],
            "side_effect": row[4],
            "taint": taint or "",
            "executed": row[6],       # what happened ungoverned (OK = it ran)
        })
    return out


def main() -> None:
    attempts = _attempts()
    index = _run_db_index()

    # pick one representative run per (template, model): the last one in the journal under
    # the model's frozen hash -- a SUCCESS for data-channel, the FAILURE for prose.
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for a in attempts:
        model = a["model"]
        if a.get("source_hash", "") != HASHES.get(model):
            continue
        by_key[(a["template"], model)] = a  # last wins

    attacks = []
    for template in CATEGORY:
        results = {
            "Gemini": _fraction(attempts, template, GEMINI, HASHES[GEMINI]),
            "Grok 4.3": _fraction(attempts, template, GROK, HASHES[GROK]),
        }
        walkthroughs = {}
        for model, label in ((GEMINI, "Gemini"), (GROK, "Grok 4.3")):
            a = by_key.get((template, model))
            if a and a["run_id"] in index:
                walkthroughs[label] = {
                    "run_id": a["run_id"],
                    "succeeded": a["outcome"] == "SUCCESS",
                    "steps": _steps(index[a["run_id"]], a["run_id"]),
                }
        attacks.append({
            "template": template,
            "category": CATEGORY[template],
            "control": CONTROL[template],
            "data_channel": IS_DATA_CHANNEL[template],
            "results": results,
            "walkthroughs": walkthroughs,
        })

    data = {
        "models": {"Gemini": HASHES[GEMINI], "Grok 4.3": HASHES[GROK]},
        "attacks": attacks,
    }
    OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("wrote", OUT)
    for atk in attacks:
        wk = {m: len(w["steps"]) for m, w in atk["walkthroughs"].items()}
        print(f"  {atk['template']:<24} results={atk['results']} walkthrough_steps={wk}")


if __name__ == "__main__":
    main()
