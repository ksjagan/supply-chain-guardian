"""Streamlit entrypoint for Software Supply Chain Guardian (spec section 14)."""
import streamlit as st
from guardian.ui import (
    common,
    page_changes,
    page_findings,
    page_graph,
    page_overview,
    page_remediation,
    page_scan,
    page_trust,
)

st.set_page_config(
    page_title="Software Supply Chain Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom styles for clean modern contrast
st.markdown("""
<style>
  .stMetric { background-color: #1e293b; padding: 10px; border-radius: 6px; border: 1px solid #334155; }
  .stExpander { border: 1px solid #334155 !important; border-radius: 6px !important; }
</style>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🛡️ Guardian")
st.sidebar.caption("Evidence-First Supply Chain Defense")

run_id = common.get_active_run_id()
data = common.load_run_data(run_id)

PAGES = [
    "🚀 Scan Target",
    "📊 Overview",
    "🕸️ Inventory & Graph",
    "🔄 What Changed",
    "🔎 Findings & Evidence",
    "🛠️ Remediation & Approval",
    "🛡️ Trust & Quality",
]

page = st.sidebar.radio("Navigate", PAGES, index=0)

st.sidebar.divider()
if data and data.get("run"):
    st.sidebar.markdown(f"**Current Run:**\n`{data['run'].get('run_id')}`")
    stat = data["summary"].get("status", "N/A")
    st.sidebar.markdown(f"**Status:** `{stat}`")
    st.sidebar.markdown(f"**Source:** `{data['run'].get('source', '')}`")

if page == "🚀 Scan Target":
    page_scan.render()
elif page == "📊 Overview":
    page_overview.render(data)
elif page == "🕸️ Inventory & Graph":
    page_graph.render(data)
elif page == "🔄 What Changed":
    page_changes.render(data)
elif page == "🔎 Findings & Evidence":
    page_findings.render(data)
elif page == "🛠️ Remediation & Approval":
    page_remediation.render(data)
elif page == "🛡️ Trust & Quality":
    page_trust.render(data)
