"""Page 4: What Changed (Supply Chain Diff & Newly Introduced Risks)."""
import streamlit as st
from guardian.ui.common import render_header


def render(data):
    render_header(data)
    if not data:
        return

    changes = data["changes"]
    items = changes.get("items", [])
    new_risks = changes.get("new_risks", [])

    st.subheader("What Changed: Supply Chain Diff")

    status = changes.get("status")
    if status == "none":
        st.info("No baseline comparison requested for this scan. Provide `--since <ref>` or select compare in Scan.")
        return
    elif status == "unavailable":
        st.warning(changes.get("error", "Baseline unavailable."))
        return

    # Counts
    ct_counts = {}
    for it in items:
        ct = it.get("change_type", "other")
        ct_counts[ct] = ct_counts.get(ct, 0) + 1

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Added Dependencies", ct_counts.get("added", 0))
    c2.metric("Upgraded / Downgraded", ct_counts.get("upgraded", 0) + ct_counts.get("downgraded", 0))
    c3.metric("Modified / Integrity", ct_counts.get("modified", 0) + ct_counts.get("source_changed", 0))
    c4.metric("New Install Scripts", ct_counts.get("install_script_gained", 0) + ct_counts.get("new_install_script", 0))

    # Red box for newly introduced risks
    if new_risks:
        st.error(f"⚠️ **{len(new_risks)} New Vulnerabilities Introduced by This Change!**")
        for nr in new_risks:
            st.write(f"- **{nr.get('component')}**: `{nr.get('vuln_id')}` ({nr.get('severity')})")

    st.divider()

    # Detailed changes table
    st.subheader("Changed Components & Configs")
    if not items:
        st.info("No differences detected between baseline and current repository state.")
        return

    rows = []
    for it in items:
        rows.append({
            "Package": it.get("package"),
            "Change Type": it.get("change_type"),
            "Old Version": it.get("old") or "-",
            "New Version": it.get("new") or "-",
            "Evidence ID": it.get("evidence_id") or "E-DIFF",
            "Flags": str(it.get("flags", {})),
        })
    st.dataframe(rows, use_container_width=True)
