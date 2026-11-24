"""Page 3: Inventory and Graph (Interactive Pyvis Dependency Graph & CycloneDX SBOM)."""
import json
import streamlit as st
import streamlit.components.v1 as components
from pyvis.network import Network
from guardian.ui.common import COLOR_MAP, render_header


def render(data):
    render_header(data)
    if not data:
        return

    model = data["model"]
    comps = model.get("components", {})
    findings = data["findings"]
    rd = data["rd"]

    st.subheader("Component Inventory & Dependency Graph")

    # Risk mapping for components
    comp_risks = {}
    comp_vuln_count = {}
    order = ["low", "medium", "high", "critical"]
    for f in findings:
        cid = f.get("component")
        if not cid:
            continue
        cur_r = comp_risks.get(cid, "low")
        if order.index(f["risk"]) > order.index(cur_r):
            comp_risks[cid] = f["risk"]
        comp_vuln_count[cid] = comp_vuln_count.get(cid, 0) + (1 if f["type"] == "vulnerability" else 0)

    # Filters
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        vuln_only = st.checkbox("Vulnerable Only", value=len(comps) > 40)
    with c2:
        direct_only = st.checkbox("Direct Dependencies Only", value=False)
    with c3:
        hide_dev = st.checkbox("Hide Dev Dependencies", value=False)
    with c4:
        all_cids = sorted(comps.keys())
        selected_comp = st.selectbox("Highlight Component Path", options=["(None)"] + all_cids)

    # Filtered components
    filtered = {}
    for cid, c in comps.items():
        if direct_only and not c.get("direct"):
            continue
        if hide_dev and c.get("dev"):
            continue
        if vuln_only and cid not in comp_risks:
            continue
        filtered[cid] = c

    # Path display
    if selected_comp != "(None)" and selected_comp in comps:
        comp_data = comps[selected_comp]
        path = comp_data.get("path", [selected_comp])
        st.markdown(f"**Shortest Path from Root:** `{' -> '.join(path)}`")
        col_a, col_b, col_c = st.columns(3)
        col_a.write(f"**Origin Direct Dep:** `{comp_data.get('origin_direct') or selected_comp}`")
        col_b.write(f"**Version:** `{comp_data.get('version')}`")
        vuln_cves = [f.get("vuln_id") for f in findings if f.get("component") == selected_comp]
        col_c.write(f"**Vulnerabilities:** `{', '.join(vuln_cves) or 'None'}`")

    # Pyvis Graph rendering
    net = Network(height="480px", width="100%", bgcolor="#0f172a", font_color="#f8fafc", directed=True)
    net.set_options('{"physics": {"barnesHut": {"springLength": 80, "springConstant": 0.04}}}')

    net.add_node("ROOT", label="Application", color="#10b981", size=25, title="Root Application")
    for cid, c in filtered.items():
        risk = comp_risks.get(cid, "ok")
        color = COLOR_MAP.get(risk, "#3b82f6")
        size = 14 + (comp_vuln_count.get(cid, 0) * 4)
        net.add_node(cid, label=c["name"], color=color, size=size,
                     title=f"{cid} | Risk: {risk.upper()} | Vulns: {comp_vuln_count.get(cid, 0)}")

    for src, dst in model.get("edges", []):
        if src == "" or src == "ROOT":
            if dst in filtered:
                net.add_edge("ROOT", dst, color="#64748b")
        elif src in filtered and dst in filtered:
            is_highlight = False
            if selected_comp != "(None)" and selected_comp in comps:
                path = comps[selected_comp].get("path", [])
                for i in range(len(path) - 1):
                    if path[i] == src and path[i+1] == dst:
                        is_highlight = True
                        break
            edge_color = "#ef4444" if is_highlight else "#475569"
            width = 3 if is_highlight else 1
            net.add_edge(src, dst, color=edge_color, width=width)

    html_str = net.generate_html()
    components.html(html_str, height=500, scrolling=True)

    # Download SBOM
    sbom_path = rd / "sbom.cdx.json"
    if sbom_path.exists():
        st.download_button("📥 Download CycloneDX 1.5 SBOM", data=sbom_path.read_text(encoding="utf-8"),
                           file_name="sbom.cdx.json", mime="application/json")

    # Component Table
    st.subheader("Component Inventory Table")
    table_rows = []
    for cid, c in filtered.items():
        table_rows.append({
            "Package": c["name"],
            "Version": c["version"],
            "Direct": "Yes" if c.get("direct") else "No",
            "Dev": "Yes" if c.get("dev") else "No",
            "Highest Risk": comp_risks.get(cid, "none").upper(),
            "Vulnerabilities": comp_vuln_count.get(cid, 0),
        })
    st.dataframe(table_rows, use_container_width=True)
