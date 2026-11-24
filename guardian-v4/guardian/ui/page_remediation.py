"""Page 6: Remediation & Human Approval (Options O-1..O-4, approval, validation & rescan)."""
import streamlit as st
from pathlib import Path
from guardian import config, pipeline, validator
from guardian.ledger import Ledger
from guardian.ui.common import render_header


def render(data):
    render_header(data)
    if not data:
        return

    plans = data.get("plans", {})
    findings = data["findings"]
    rd = data["rd"]
    led = Ledger(rd / "ledger.json")

    st.subheader("Remediation Options & Human Approval")

    if not plans:
        st.info("No remediation plans available for this run. Run scan with `--remediate` enabled.")
        return

    f_map = {f["id"]: f for f in findings}

    for fid, plan in plans.items():
        f = f_map.get(fid)
        if not f:
            continue

        with st.expander(f"Fix for {fid}: {f['title']} ({f.get('component')})", expanded=True):
            st.write(f"**Vulnerability ID:** `{f.get('vuln_id', 'N/A')}` | **Target Component:** `{f.get('component')}`")

            # AI Chooser Recommendation
            ai_stat = plan.get("ai_status", "not run")
            rec = plan.get("ai_choice") or plan.get("recommended")
            st.info(f"💡 **Recommended Option: `{rec}`** (AI Status: {ai_stat})\n\n"
                    f"**Trade-off Explanation:** {plan.get('ai_explanation') or 'Selected by deterministic code preference order.'}")

            # Options table / cards
            st.write("### Generated Options (Code Built):")
            for opt in plan.get("options", []):
                is_selected = (opt["id"] == rec)
                prefix = "👉 **[RECOMMENDED]** " if is_selected else ""
                st.markdown(f"#### {prefix}Option {opt['id']}: {opt['summary']}")
                st.write(f"- **Expected Risk Reduction:** {opt['risk_reduction']}")
                st.write(f"- **Compatibility:** {opt['compatibility']}")
                st.write(f"- **Rollback Command:** `{'; '.join(opt.get('rollback', []))}`")

                # Approval status
                appr = validator.approval_for(led, fid)
                has_approved_this = appr and appr["data"]["option_id"] == opt["id"]

                col_btn1, col_btn2 = st.columns([1, 4])
                with col_btn1:
                    if not appr:
                        if st.button(f"Approve {opt['id']}", key=f"appr_{fid}_{opt['id']}", type="primary" if is_selected else "secondary"):
                            validator.record_decision(rd, fid, opt["id"], "approved")
                            st.success(f"Approved {opt['id']}! Approval record added to Evidence Ledger.")
                            st.rerun()
                    elif has_approved_this:
                        st.success("✅ APPROVED")
                with col_btn2:
                    if not appr:
                        if st.button(f"Reject {opt['id']}", key=f"rej_{fid}_{opt['id']}"):
                            validator.record_decision(rd, fid, opt["id"], "rejected")
                            st.warning(f"Rejected {opt['id']}.")
                            st.rerun()

            st.divider()

            # Validation & Rescan (Day 2 3 pm checkpoint)
            st.write("### Validation & Rescan Sandbox")
            appr = validator.approval_for(led, fid)
            if not appr:
                st.warning("⚠️ Human approval is required before a fix can be validated or applied to a sandbox copy.")
            else:
                st.success(f"Fix approved under evidence `{appr['id']}`. Ready to validate on isolated temporary copy.")
                if st.button("🔬 Validate Fix on Sandbox Copy", key=f"val_{fid}", type="primary"):
                    scout = data["scout"]
                    chosen_opt = next((o for o in plan["options"] if o["id"] == appr["data"]["option_id"]), None)
                    with st.spinner("Creating sandbox copy, applying patch, running lockfile rebuild and rescan..."):
                        before = pipeline.analyze_tree(rd / "before_tmp", scout["repo_dir"], data["run"]["offline"])
                        val_res = validator.validate(rd, scout["repo_dir"], f, chosen_opt, before, data["run"]["offline"])
                        config.write_json(rd / "validation.json", val_res)
                        if val_res.get("patch"):
                            (rd / "remediation.patch").write_text(val_res["patch"], encoding="utf-8")
                    st.rerun()

                val = data.get("validation")
                if val and val.get("finding_id") == fid:
                    st.write(f"Validation Status: **`{val.get('status').upper()}`**")
                    v1, v2, v3 = st.columns(3)
                    v1.metric("Fixed Issues", len(val.get("fixed", [])))
                    v2.metric("Still Open Issues", len(val.get("still_open", [])))
                    v3.metric("Newly Introduced", len(val.get("newly_introduced", [])))

                    if val.get("patch"):
                        st.write("#### Generated Remediation Patch:")
                        st.code(val["patch"], language="diff")
                        st.download_button("📥 Download remediation.patch", data=val["patch"],
                                           file_name="remediation.patch", mime="text/x-diff")
