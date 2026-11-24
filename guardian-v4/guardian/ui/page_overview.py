"""Page 2: Overview (KPIs, Coverage Box, Top 5 Findings)."""
import streamlit as st
from guardian.ui.common import render_header


def render(data):
    render_header(data)
    if not data:
        return

    summary = data["summary"]
    findings = data["findings"]

    # 1. KPI cards
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Components", summary.get("components_total", 0),
              f"Direct: {summary.get('components_direct', 0)} | Trans: {summary.get('components_transitive', 0)}")
    c2.metric("Vulnerabilities", summary.get("vulns_total", 0),
              f"Crit: {summary.get('vulns_critical', 0)} | High: {summary.get('vulns_high', 0)}")
    c3.metric("New Risks Introduced", summary.get("new_risks", 0),
              f"Changes: {summary.get('changes_count', 0)}")
    c4.metric("Scan Duration", f"{summary.get('total_duration', 0)}s",
              f"Cost: ${summary.get('total_cost', 0.0):.4f}")

    st.divider()

    # 2. Coverage Box
    st.subheader("1. Ecosystem Coverage")
    cov = data.get("coverage", {})
    t1, t2, t3, t4 = st.columns(4)
    t1.metric("Detected", cov.get("detected", "npm lockfile"))
    t2.metric("Fully Analysed", f"{summary.get('components_total', 0)} components")
    t3.metric("Partial Checks", "Dockerfile / Workflows")
    t4.metric("Skipped (Roadmap)", "PyPI, Maven, Go")

    st.divider()

    # 3. Top 5 Findings
    st.subheader("2. Top 5 Prioritised Findings")
    if not findings:
        st.success("No security findings discovered.")
        return

    top5 = findings[:5]
    for f in top5:
        risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f["risk"], "⚪")
        with st.expander(f"{risk_emoji} {f['id']}: {f['title']} (Score: {f.get('score', 0)}/100)", expanded=True):
            r1, r2 = st.columns([3, 1])
            with r1:
                st.write(f"**Component:** `{f.get('component') or 'N/A'}`")
                st.write(f"**Path:** `{' -> '.join(f.get('path', []))}`")
                if f.get("explanation"):
                    st.info(f"**AI Explanation (Verified):** {f['explanation']}")
            with r2:
                st.write(f"**Risk Level:** `{f['risk'].upper()}`")
                st.write(f"**Confidence:** `{f.get('confidence', 'medium').upper()}`")
                st.write(f"**Status:** `{f.get('status', 'open')}`")
