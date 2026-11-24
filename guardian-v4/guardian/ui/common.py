"""Shared UI components, styles, and data loaders for Streamlit."""
from pathlib import Path
import streamlit as st
from guardian import config

COLOR_MAP = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "ok": "#22c55e",
}


def get_active_run_id():
    if "run_id" not in st.session_state:
        runs = list_recent_runs()
        st.session_state["run_id"] = runs[0] if runs else None
    return st.session_state["run_id"]


def list_recent_runs():
    if not config.OUT_DIR.exists():
        return []
    runs = [d.name for d in config.OUT_DIR.iterdir() if d.is_dir() and (d / "run.json").exists()]
    return sorted(runs, reverse=True)


def load_run_data(run_id):
    if not run_id:
        return None
    rd = config.run_dir(run_id)
    return {
        "rd": rd,
        "run": config.load_run(rd),
        "summary": config.read_json(rd / "run_summary.json", {}),
        "findings": config.read_json(rd / "findings.json", []),
        "model": config.read_json(rd / "model.json", {"components": {}}),
        "scout": config.read_json(rd / "scout.json", {}),
        "coverage": config.read_json(rd / "coverage.json", {}),
        "validation": config.read_json(rd / "validation.json"),
        "plans": config.read_json(rd / "remediation_plans.json", {}),
        "changes": config.read_json(rd / "parts" / "changes.json", {}),
        "osv": config.read_json(rd / "parts" / "osv.json", {}),
        "kev": config.read_json(rd / "parts" / "kev.json", {}),
        "canary": config.read_json(rd / "parts" / "canary.json", {}),
    }


def render_header(data):
    if not data:
        st.title("Software Supply Chain Guardian")
        st.info("No active scan. Start a scan from the Scan page or select a recent run.")
        return

    run, summary = data["run"], data["summary"]
    status = summary.get("status", "COMPLETE")
    stat_emoji = "🟢" if status == "COMPLETE" else ("🔴" if status == "UNTRUSTED" else "🟡")

    c1, c2 = st.columns([3, 1])
    with c1:
        st.markdown(f"### Software Supply Chain Guardian")
        src = run.get("source", "N/A")
        st.caption(f"Run: `{run.get('run_id')}` | Source: `{src}`")
        ai_info = f"AI: **{'ON' if run.get('ai') else 'OFF'}** ({run.get('cheap_model', 'haiku')})"
        osv_snap = data["osv"].get("snapshot") or "offline"
        kev_snap = data["kev"].get("snapshot") or "offline"
        st.caption(f"{ai_info} | OSV: `{osv_snap}` | KEV: `{kev_snap}`")
    with c2:
        st.metric("Run Status", f"{stat_emoji} {status}")
    st.divider()
