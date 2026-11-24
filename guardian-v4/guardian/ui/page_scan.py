"""Page 1: Scan (Launch scan, choose GitHub URL or local path, demo buttons)."""
import time
import streamlit as st
from guardian import config
from guardian.graph import run_pipeline
from guardian.ui.common import list_recent_runs


def render():
    st.header("Start a New Scan")
    st.write("Scan a public GitHub repository or a local application folder for supply chain risks.")

    col1, col2 = st.columns([2, 1])
    with col1:
        source_input = st.text_input("Repository Target", value="",
                                     placeholder="https://github.com/owner/repo or fixtures/demo-app")
    with col2:
        st.write("One-Click Demo Targets:")
        b1, b2 = st.columns(2)
        with b1:
            if st.button("Demo App"):
                source_input = "fixtures/demo-app"
                st.session_state["target_input"] = source_input
        with b2:
            if st.button("Attack Demo"):
                source_input = "fixtures/attack-demo"
                st.session_state["target_input"] = source_input

    if "target_input" in st.session_state:
        source_input = st.session_state["target_input"]

    st.subheader("Scan Configuration")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        ai_enabled = st.checkbox("AI Layer (Reader/Analyst/Skeptic)", value=True)
    with c2:
        compare_changes = st.checkbox("Compare with baseline", value=False)
    with c3:
        remediate_enabled = st.checkbox("Remediation Options", value=True)
    with c4:
        demo_cache = st.checkbox("Offline Demo Cache", value=True)

    since_ref = None
    if compare_changes:
        since_ref = st.text_input("Git ref to compare against (e.g. HEAD~1 or 'last')", value="HEAD~1")

    if st.button("🚀 Start Guardian Scan", type="primary", use_container_width=True):
        if not source_input:
            st.error("Please enter a GitHub URL or a folder path.")
            return

        run_id = config.new_run_id()
        rd = config.run_dir(run_id)
        rd.mkdir(parents=True, exist_ok=True)

        run_config = {
            "run_id": run_id,
            "source": source_input,
            "ai": ai_enabled,
            "remediate": remediate_enabled,
            "offline": demo_cache,
            "since": since_ref,
            "since_dir": None,
            "cheap_model": config.model_cheap(),
            "big_model": config.model_big(),
            "created_ts": time.time(),
        }
        config.write_json(rd / "run.json", run_config)
        st.session_state["run_id"] = run_id

        with st.status(f"Scanning target: {source_input}...", expanded=True) as status_box:
            st.write("1. Scout: discovering manifests & cloning...")
            res = run_pipeline(run_id)
            st.write("2. Mapper: building dependency graph & SBOM...")
            st.write("3. Hunter: querying OSV, KEV, EPSS, typosquat & Docker...")
            st.write("4. Quarantined Reader: analyzing untrusted script text...")
            st.write("5. Rules & Verifier: ranking findings with priority scores...")
            st.write("6. Hands: generating options and report artifacts...")
            status_box.update(label="Guardian Scan Complete!", state="complete", expanded=False)

        st.success(f"Scan completed successfully! Run ID: `{run_id}`")
        st.info("Navigate to the **Overview** or **Inventory and Graph** page to explore results.")

    st.divider()
    st.subheader("Recent Runs")
    runs = list_recent_runs()
    if runs:
        sel = st.selectbox("Select a previous run to inspect", options=runs,
                           index=runs.index(st.session_state.get("run_id")) if st.session_state.get("run_id") in runs else 0)
        if st.button("Load Run"):
            st.session_state["run_id"] = sel
            st.rerun()
    else:
        st.caption("No previous runs recorded yet.")
