"""Page 5: Findings (Prioritised findings, verified evidence vs AI explanation, score breakdown)."""
import streamlit as st
from guardian.ui.common import render_header
from guardian.ledger import Ledger


def render(data):
    render_header(data)
    if not data:
        return

    findings = data["findings"]
    rd = data["rd"]
    led = Ledger(rd / "ledger.json")

    st.subheader("Security Findings & Evidence-Backed Explanations")

    # Filters
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        risk_filter = st.multiselect("Filter by Risk", options=["critical", "high", "medium", "low"],
                                     default=["critical", "high", "medium", "low"])
    with c2:
        type_filter = st.multiselect("Finding Type", options=list({f["type"] for f in findings}))
    with c3:
        introduced_only = st.checkbox("Introduced by Change Only", value=False)
    with c4:
        kev_only = st.checkbox("CISA KEV Only", value=False)

    filtered = []
    for f in findings:
        if f["risk"] not in risk_filter:
            continue
        if type_filter and f["type"] not in type_filter:
            continue
        fl = f.get("flags") or {}
        if introduced_only and not fl.get("introduced"):
            continue
        if kev_only and not any("cisa" in note.lower() for note in f.get("risk_notes", [])):
            continue
        filtered.append(f)

    st.write(f"Showing **{len(filtered)}** of **{len(findings)}** findings (sorted by Priority Score 0-100):")

    for f in filtered:
        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f["risk"], "⚪")
        score = f.get("score", 0)

        with st.expander(f"{risk_emoji} [{f['risk'].upper()}] {f['id']}: {f['title']} — Score: {score}/100", expanded=False):
            # Chips row
            chips = []
            fl = f.get("flags") or {}
            if fl.get("introduced"):
                chips.append("🚨 Introduced by Change")
            if fl.get("reach") == "imported":
                chips.append("⚡ Reachability: Imported")
            elif fl.get("reach") == "not found":
                chips.append("🛡️ Reachability: Not Found (Heuristic)")
            if fl.get("dev"):
                chips.append("📦 Dev-only (-20 pts)")
            if fl.get("direct"):
                chips.append("🔗 Direct Dependency (+5 pts)")
            if any("cisa" in n.lower() for n in f.get("risk_notes", [])):
                chips.append("🔥 Listed in CISA KEV (+25 pts)")

            if chips:
                st.write(" ".join(f"`{c}`" for c in chips))

            st.write(f"**Component:** `{f.get('component') or 'N/A'}`")
            st.write(f"**Path:** `{' -> '.join(f.get('path', []))}`")

            # Score breakdown table
            sb = f.get("score_breakdown", {})
            if sb:
                st.caption("**Why it is ranked here (Score breakdown):**")
                cols = st.columns(len(sb))
                for idx, (factor, pts) in enumerate(sb.items()):
                    cols[idx].metric(factor.replace("_", " ").title(), f"{pts:+d}")

            # Green verified evidence box
            with st.container():
                st.success(f"**Verified Evidence Ledger Facts** (Evidence IDs: `{', '.join(f.get('evidence_ids', []))}`):")
                for note in f.get("risk_notes", []):
                    st.write(f"- {note}")
                if f.get("detail"):
                    st.write(f"- Details: `{f['detail']}`")

            # Nested raw evidence expander
            with st.expander("Inspect Raw Ledger Evidence Records"):
                for eid in f.get("evidence_ids", []):
                    ev_item = led.get(eid)
                    if ev_item:
                        st.json(ev_item)

            # Blue AI explanation box (strictly separated)
            if f.get("explanation"):
                ai_stat = f.get("ai_status", "verified")
                box = st.info if "verified" in ai_stat else st.warning
                box(f"**AI Analyst Explanation ({ai_stat}):**\n\n{f['explanation']}")

            # Skeptic opinion
            sk = f.get("skeptic")
            if sk and sk.get("opinion") != "none":
                st.caption(f"🧐 **Skeptic Second Opinion:** `{sk.get('opinion')}` ({sk.get('status')})")

            # Copyable CLI verify command
            st.code(f"guardian verify {f['id']} --run out/{rd.name}", language="bash")
