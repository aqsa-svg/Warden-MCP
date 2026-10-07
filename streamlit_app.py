"""WARDEN — interactive demo.

A read-only viewer over REAL recorded calibration runs (demo/warden_demo_data.json,
distilled from the project's run logs by demo/extract_demo_data.py). Nothing here calls a
model or invents a number: every verdict and every step is replayed from a recorded run,
so the public app needs no API keys and cannot drift from the measured results.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

DATA = json.loads(
    (Path(__file__).parent / "demo" / "warden_demo_data.json").read_text(encoding="utf-8")
)
REPO = "https://github.com/aqsa-svg/Warden-MCP"

st.set_page_config(page_title="WARDEN — governed MCP gateway", page_icon="🛡️", layout="wide")

BADGE = {
    "ALLOW": "🟢 ALLOW",
    "DENY": "🔴 DENY",
    "REQUIRE_APPROVAL": "🟡 REQUIRE_APPROVAL",
}

# ---- header --------------------------------------------------------------------
st.title("🛡️ WARDEN")
st.subheader("A governed gateway that stops AI agents from acting on poisoned data")
st.markdown(
    f"Provenance-aware authorization for AI tool calls · "
    f"[source + full writeup on GitHub]({REPO})"
)

st.info(
    "**The finding:** an attack's power isn't how cleverly it's worded — it's whether it "
    "needs the agent to *disobey*. Payloads that tell the agent to misbehave mostly fail. "
    "Payloads that poison **data the agent already trusts** succeed. Confirmed on two "
    "models from different providers. That's why WARDEN tracks *data provenance*, not "
    "'bad instructions'.",
    icon="💡",
)

# ---- results table -------------------------------------------------------------
st.header("Measured results")
st.caption(
    "Ungoverned attack success rate (Warden absent). Every cell is a fraction with its "
    "denominator — real runs, never a bare percentage. Pinned to a per-model source hash."
)
rows = []
for atk in DATA["attacks"]:
    rows.append({
        "Attack": atk["template"],
        "Type": "data channel" if atk["data_channel"] else "prose injection",
        "Gemini": atk["results"].get("Gemini", "—"),
        "Grok 4.3": atk["results"].get("Grok 4.3", "—"),
        "Warden control": atk["control"],
    })
st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
st.caption(
    "Pattern: **data-channel attacks land (3/3), prose injection does not (0/3)** — on "
    "both models. (Gemini's prose re-run under its frozen hash is still in progress; its "
    "earlier runs were 0/3.)"
)

# ---- interactive walkthrough ---------------------------------------------------
st.header("Replay a real run")
st.caption("Step through an actual recorded run and watch Warden decide each tool call.")

by_template = {a["template"]: a for a in DATA["attacks"]}
col1, col2 = st.columns([2, 1])
with col1:
    choice = st.selectbox(
        "Attack scenario",
        list(by_template),
        format_func=lambda t: f"{t}  ·  {by_template[t]['category']}",
    )
atk = by_template[choice]
with col2:
    models = list(atk["walkthroughs"])
    model = st.radio("Agent model", models, horizontal=True) if models else None

if not model:
    st.warning("No recorded run available for this scenario yet.")
else:
    wk = atk["walkthroughs"][model]
    left, right = st.columns(2)
    left.metric(f"Ungoverned success ({model})", atk["results"].get(model, "—"))
    right.metric("Attack outcome (no Warden)", "SUCCEEDED" if wk["succeeded"] else "declined")

    st.markdown("#### The agent's tool calls, and Warden's decision on each")
    for i, s in enumerate(wk["steps"], 1):
        badge = BADGE.get(s["decision"], s["decision"])
        taint = f" · taint: `{s['taint']}`" if s["taint"] else " · taint: none"
        ran = " · ran anyway (ungoverned)" if s["executed"] == "OK" and s["decision"] != "ALLOW" else ""
        line = (
            f"**{i}. `{s['tool']}`** → {badge}  "
            f"<span style='color:gray'>rule `{s['rule']}` · {s['risk']}/{s['side_effect']}"
            f"{taint}{ran}</span>"
        )
        st.markdown(line, unsafe_allow_html=True)

    # story banner
    key = next((s for s in wk["steps"] if s["decision"] != "ALLOW"), None)
    if atk["data_channel"] and key:
        st.error(
            f"**Ungoverned, the agent completed the attack** — it called `{key['tool']}` on "
            f"attacker-influenced data, following no instruction. **Warden's decision on "
            f"that call was {key['decision']}** (rule `{key['rule']}`, triggered by the "
            f"untrusted taint), so *governed*, it never runs.",
            icon="🛡️",
        )
    elif not atk["data_channel"]:
        st.success(
            "**The model declined the injected instruction** — it read the poisoned "
            "document but never made the dangerous call. The attack failed at the agent, "
            "before Warden even had to act. This is the prose-injection negative result.",
            icon="✅",
        )

# ---- how it works --------------------------------------------------------------
st.header("How it works")
st.markdown(
    "WARDEN sits between the agent and its tools. It labels where every piece of content "
    "came from (the user's task = trusted; documents and tool outputs = untrusted), and "
    "**denies or escalates any tool call whose arguments trace back to untrusted content**. "
    "Secrets live in WARDEN and are injected only *after* a call is approved, so a "
    "compromised agent never sees them. Every decision is logged for audit."
)
st.components.v1.html(
    """
    <div id="d"></div>
    <script type="module">
      import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
      mermaid.initialize({ startOnLoad: false, theme: "dark" });
      const g = `flowchart LR
        O([Operator task\\nTRUSTED]) --> A[LLM agent]
        A -->|tool call| W{{WARDEN\\nprovenance + policy}}
        W -->|allowed + secret injected| S[MCP tools]
        S -->|output = UNTRUSTED| W
        W -->|labelled content| A
        C[(poisoned doc /\\nrecord)] -.-> S
        W -->|DENY / ESCALATE| X[blocked]`;
      const { svg } = await mermaid.render("m", g);
      document.getElementById("d").innerHTML = svg;
    </script>
    """,
    height=260,
)

# ---- integrity -----------------------------------------------------------------
st.header("Why the numbers are trustworthy")
st.markdown(
    "The point of the project is measurement you can believe. Every number is computed "
    "from recorded oracle verdicts (exact string / call-log checks — never an LLM judging "
    "success), and the README documents **11 cases where a bug or shortcut would have "
    "produced a wrong-but-plausible number**, and how each was caught. A few:"
)
with st.expander("Examples of measurement-integrity findings"):
    st.markdown(
        "- **Exact-address oracle** would miss an exfiltration whenever the model "
        "reproduced the address imperfectly → matched the reserved *domain* instead.\n"
        "- **A retry loop on a per-day quota error** silently burned the next day's quota "
        "→ now fast-fails and resumes.\n"
        "- **Attack rows produced ad-hoc with no runner** weren't reproducible → built a "
        "hash-aware runner; the journal now refuses an unpinned result.\n"
        "- **The benign grader read a stale run** from a reused directory → fixed to a "
        "fresh, explicitly-latest run (found by tracing one odd deviation to its log)."
    )

st.divider()
st.caption(f"Built with Python · MCP · LangGraph.  Code + writeup: {REPO}")
