"""
Mapper agent – takes components + edges from ecosystem plugins,
writes the CycloneDX SBOM, builds a dependency graph,
computes shortest paths from root, exports graph.html, and
records all data as evidence.

Checkpoint 1 output:
  sbom.cdx.json   – CycloneDX 1.5 JSON
  graph.json      – raw node/edge list
  graph.html      – interactive browser visualisation (pyvis)
  Coverage box data inside ledger
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx

from guardian.config import MAX_COMPONENTS
from guardian.ecosystems import ECOSYSTEM_PLUGINS
from guardian.ledger import Ledger
from guardian.models import Component, Edge


ROOT_BOM_REF = "root"


class Mapper:
    """
    Runs every ecosystem plugin against the repo, merges results,
    builds the graph, and writes all outputs.
    """

    def __init__(self, ledger: Ledger, out_dir: Path):
        self.ledger = ledger
        self.out_dir = out_dir
        self.components: List[Component] = []
        self.edges: List[Edge] = []
        self.graph: nx.DiGraph = nx.DiGraph()
        self.coverage: List[dict] = []  # one entry per plugin run
        self._comp_by_bref: Dict[str, Component] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, repo_dir: Path) -> None:
        """Run all plugins, build graph, write outputs."""
        self._run_plugins(repo_dir)
        self._enforce_cap()
        self._build_graph()
        self._compute_paths()
        self._write_sbom()
        self._write_graph_json()
        self._write_graph_html()
        self._write_coverage_evidence()
        self.ledger.save()

        total = len(self.components)
        direct = sum(1 for c in self.components if c.is_direct)
        print(
            f"[mapper] {total} components ({direct} direct, "
            f"{total - direct} transitive) · "
            f"graph: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    # ------------------------------------------------------------------
    # Plugin runner
    # ------------------------------------------------------------------

    def _run_plugins(self, repo_dir: Path) -> None:
        for plugin in ECOSYSTEM_PLUGINS:
            name = type(plugin).__name__
            print(f"[mapper] Running plugin {name} …")
            try:
                comps, edges, note = plugin.parse(repo_dir)
            except Exception as exc:
                print(f"[mapper] Plugin {name} failed: {exc}")
                self.coverage.append({
                    "plugin": name,
                    "status": "error",
                    "note": str(exc),
                    "components": 0,
                })
                continue

            # Enforce cap
            remaining = MAX_COMPONENTS - len(self.components)
            skipped = 0
            if len(comps) > remaining:
                skipped = len(comps) - remaining
                comps = comps[:remaining]

            # Record coverage
            status = "full" if note == "full" else ("partial" if "partial" in note else "skipped")
            self.coverage.append({
                "plugin": name,
                "status": status,
                "note": note,
                "components": len(comps),
                "skipped_cap": skipped,
            })

            # Store components and record evidence
            for comp in comps:
                ev = self.ledger.add_evidence(
                    kind="component",
                    source="mapper",
                    component=comp.name,
                    data={
                        "name": comp.name,
                        "version": comp.version,
                        "ecosystem": comp.ecosystem,
                        "purl": comp.purl,
                        "bom_ref": comp.bom_ref,
                        "is_direct": comp.is_direct,
                        "is_dev": comp.is_dev,
                        "is_optional": comp.is_optional,
                        "has_install_script": comp.has_install_script,
                        "resolved_url": comp.resolved_url,
                        "integrity": comp.integrity,
                        "manifest_path": comp.manifest_path,
                    },
                )
                comp.evidence_id = ev.id
                self.components.append(comp)
                self._comp_by_bref[comp.bom_ref] = comp
                self.ledger.add_component(comp)

            # Store edges
            for edge in edges:
                ev = self.ledger.add_evidence(
                    kind="edge",
                    source="mapper",
                    component="",
                    data={"parent": edge.parent, "child": edge.child},
                )
                edge.evidence_id = ev.id
                self.edges.append(edge)
                self.ledger.add_edge(edge)

    # ------------------------------------------------------------------
    # Component cap
    # ------------------------------------------------------------------

    def _enforce_cap(self) -> None:
        if len(self.components) >= MAX_COMPONENTS:
            self.ledger.add_evidence(
                kind="file_skipped",
                source="mapper",
                component="",
                data={
                    "reason": f"component cap ({MAX_COMPONENTS}) reached; some components omitted",
                },
            )

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graph(self) -> None:
        """Build a networkx DiGraph from components and edges."""
        # Add root node
        self.graph.add_node(ROOT_BOM_REF, label="[root app]", is_direct=False, is_dev=False)

        # Add component nodes
        for comp in self.components:
            self.graph.add_node(
                comp.bom_ref,
                label=f"{comp.name}@{comp.version}",
                name=comp.name,
                version=comp.version,
                is_direct=comp.is_direct,
                is_dev=comp.is_dev,
                has_install_script=comp.has_install_script,
            )

        # Add edges
        for edge in self.edges:
            if edge.parent in self.graph and edge.child in self.graph:
                self.graph.add_edge(edge.parent, edge.child)
            elif edge.parent == ROOT_BOM_REF:
                if edge.child in self.graph:
                    self.graph.add_edge(ROOT_BOM_REF, edge.child)

    # ------------------------------------------------------------------
    # Shortest path from root
    # ------------------------------------------------------------------

    def _compute_paths(self) -> None:
        """
        Compute BFS shortest path from root to every component.
        Records path as evidence for each component.
        Also annotates the 'origin' direct dependency for transitive components.
        """
        for comp in self.components:
            try:
                path = nx.shortest_path(self.graph, source=ROOT_BOM_REF, target=comp.bom_ref)
                # Convert bom_refs back to human-readable labels
                readable = []
                for bref in path:
                    if bref == ROOT_BOM_REF:
                        readable.append("[root]")
                    elif bref in self._comp_by_bref:
                        c = self._comp_by_bref[bref]
                        readable.append(f"{c.name}@{c.version}")
                    else:
                        readable.append(bref)

                # The direct parent is the second element (index 1) in the path
                origin_bref = path[1] if len(path) > 1 else ROOT_BOM_REF
                origin_label = readable[1] if len(readable) > 1 else "[root]"
                comp.direct_parent = origin_label

                # Origin dictionary: {ecosystem, registry_host, manifest_file, direct_parent}
                reg_host = "registry.npmjs.org"
                if comp.resolved_url:
                    try:
                        from urllib.parse import urlparse
                        p_host = urlparse(comp.resolved_url).netloc
                        if p_host:
                            reg_host = p_host
                    except Exception:
                        pass
                comp.origin = {
                    "ecosystem": comp.ecosystem,
                    "registry_host": reg_host,
                    "manifest_file": comp.manifest_path,
                    "direct_parent": origin_label,
                }

                self.ledger.add_evidence(
                    kind="dependency_path",
                    source="mapper",
                    component=comp.name,
                    data={
                        "component": comp.name,
                        "version": comp.version,
                        "bom_ref": comp.bom_ref,
                        "path_bom_refs": path,
                        "path_readable": readable,
                        "depth": len(path) - 1,
                        "origin_direct_dep": origin_label,
                        "origin": comp.origin,
                    },
                )
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                # Component exists in lockfile but is not reachable from root
                self.ledger.add_evidence(
                    kind="dependency_path",
                    source="mapper",
                    component=comp.name,
                    data={
                        "component": comp.name,
                        "version": comp.version,
                        "bom_ref": comp.bom_ref,
                        "path_bom_refs": [],
                        "path_readable": ["[unreachable]"],
                        "depth": -1,
                        "origin_direct_dep": "",
                    },
                )

    # ------------------------------------------------------------------
    # CycloneDX SBOM
    # ------------------------------------------------------------------

    def _write_sbom(self) -> None:
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{self._uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"name": "guardian", "version": "0.1.0"}],
            },
            "components": [],
            "dependencies": [],
        }

        for comp in self.components:
            sbom["components"].append({
                "type": "library",
                "bom-ref": comp.bom_ref,
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
            })

        # Build dependency entries
        dep_map: Dict[str, List[str]] = {}
        for edge in self.edges:
            dep_map.setdefault(edge.parent, []).append(edge.child)

        for bref, children in dep_map.items():
            sbom["dependencies"].append({
                "ref": bref,
                "dependsOn": children,
            })

        path = self.out_dir / "sbom.cdx.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sbom, fh, indent=2)
        print(f"[mapper] SBOM → {path}")

    # ------------------------------------------------------------------
    # Graph JSON
    # ------------------------------------------------------------------

    def _write_graph_json(self) -> None:
        nodes = [
            {"id": n, **self.graph.nodes[n]}
            for n in self.graph.nodes
        ]
        edges = [
            {"source": u, "target": v}
            for u, v in self.graph.edges
        ]
        path = self.out_dir / "graph.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"nodes": nodes, "edges": edges}, fh, indent=2)
        print(f"[mapper] Graph JSON → {path}")

    # ------------------------------------------------------------------
    # Interactive graph HTML  (custom, fully self-contained)
    # ------------------------------------------------------------------

    def _write_graph_html(self) -> None:
        """
        Build a readable, self-contained dependency-graph page.
        Features:
          • Hierarchical layout (root at top, direct deps below, transitives below that)
          • Legend panel
          • Search/highlight box  – type a package name, matching nodes glow
          • Sidebar that shows the full dep-path when you click a node
          • Stats bar: total / direct / transitive counts
          • 'Focus on direct deps only' toggle to cut the noise
          • No external CDN needed  (vis-network is embedded via pyvis)
        """
        # ── 1. Collect node/edge data as plain Python dicts ──────────────
        nodes_data = []
        for node_id in self.graph.nodes:
            attrs = self.graph.nodes[node_id]
            is_root    = node_id == ROOT_BOM_REF
            is_direct  = bool(attrs.get("is_direct"))
            is_dev     = bool(attrs.get("is_dev"))
            has_script = bool(attrs.get("has_install_script"))
            label      = attrs.get("label", node_id)

            if is_root:
                color, group, size = "#e94560", "root",    35
            elif has_script:
                color, group, size = "#ff6b35", "install", 22
            elif is_dev:
                color, group, size = "#a855f7", "dev",     16
            elif is_direct:
                color, group, size = "#3b82f6", "direct",  22
            else:
                color, group, size = "#374151", "trans",   11

            # Tooltip shown on hover
            tooltip = label
            if is_dev:     tooltip += " [dev]"
            if has_script: tooltip += " ⚠ install script"

            nodes_data.append({
                "id":    node_id,
                "label": label,
                "title": tooltip,
                "color": {"background": color,
                          "border":     color,
                          "highlight":  {"background": "#facc15", "border": "#facc15"}},
                "size":  size,
                "group": group,
                "font":  {"color": "#f9fafb", "size": 11},
            })

        edges_data = [
            {"from": u, "to": v, "arrows": "to",
             "color": {"color": "#4b5563", "highlight": "#facc15"},
             "width": 1}
            for u, v in self.graph.edges
        ]

        # ── 2. Build path lookup for sidebar (bom_ref -> readable path) ──
        path_lookup = {}   # bom_ref -> "root → a@1.0 → b@2.0"
        for ev in self.ledger.evidence:
            if ev.kind == "dependency_path":
                bref = ev.data.get("bom_ref", "")
                readable = ev.data.get("path_readable", [])
                if bref and readable:
                    path_lookup[bref] = " → ".join(readable)

        # Coverage numbers
        total  = len(self.components)
        direct = sum(1 for c in self.components if c.is_direct)
        trans  = total - direct

        nodes_json  = json.dumps(nodes_data,  ensure_ascii=False)
        edges_json  = json.dumps(edges_data,  ensure_ascii=False)
        paths_json  = json.dumps(path_lookup, ensure_ascii=False)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Dependency Graph – Guardian</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#f1f5f9;height:100vh;display:flex;flex-direction:column}}

  /* ── top bar ── */
  #topbar{{background:#1e293b;padding:10px 16px;display:flex;align-items:center;gap:14px;border-bottom:1px solid #334155;flex-shrink:0}}
  #topbar h1{{font-size:15px;font-weight:700;color:#f8fafc;white-space:nowrap}}
  #stats{{display:flex;gap:10px;font-size:12px}}
  .stat{{background:#0f172a;border-radius:6px;padding:3px 10px;color:#94a3b8}}
  .stat b{{color:#f1f5f9}}
  #searchbox{{margin-left:auto;display:flex;align-items:center;gap:6px}}
  #searchbox input{{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:5px 10px;color:#f1f5f9;font-size:12px;width:200px;outline:none}}
  #searchbox input:focus{{border-color:#3b82f6}}
  #searchbox button{{background:#3b82f6;border:none;border-radius:6px;padding:5px 10px;color:#fff;font-size:12px;cursor:pointer}}
  #toggleDirect{{background:#1d4ed8;border:none;border-radius:6px;padding:5px 10px;color:#fff;font-size:12px;cursor:pointer;white-space:nowrap}}
  #toggleDirect.active{{background:#dc2626}}

  /* ── main layout ── */
  #main{{display:flex;flex:1;overflow:hidden}}
  #graph-container{{flex:1;position:relative}}
  #mynetwork{{width:100%;height:100%}}

  /* ── legend panel (left) ── */
  #legend{{width:170px;background:#1e293b;border-right:1px solid #334155;padding:14px 12px;flex-shrink:0;font-size:12px}}
  #legend h3{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin-bottom:10px}}
  .leg{{display:flex;align-items:center;gap:8px;margin-bottom:8px;color:#cbd5e1}}
  .dot{{width:13px;height:13px;border-radius:50%;flex-shrink:0}}
  .dot.root   {{background:#e94560}}
  .dot.direct {{background:#3b82f6}}
  .dot.trans  {{background:#374151;border:1px solid #6b7280}}
  .dot.dev    {{background:#a855f7}}
  .dot.install{{background:#ff6b35}}

  /* ── sidebar (right) ── */
  #sidebar{{width:280px;background:#1e293b;border-left:1px solid #334155;padding:16px;flex-shrink:0;overflow-y:auto;display:flex;flex-direction:column;gap:12px}}
  #sidebar h3{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#64748b}}
  #pkg-name{{font-size:14px;font-weight:700;color:#f8fafc;word-break:break-all}}
  #pkg-path{{font-size:11px;color:#94a3b8;line-height:1.6;word-break:break-all}}
  #pkg-badges{{display:flex;flex-wrap:wrap;gap:6px}}
  .badge{{border-radius:4px;padding:2px 7px;font-size:11px;font-weight:600}}
  .badge.direct {{background:#1d4ed8;color:#bfdbfe}}
  .badge.dev    {{background:#6b21a8;color:#e9d5ff}}
  .badge.install{{background:#9a3412;color:#fed7aa}}
  .badge.trans  {{background:#374151;color:#9ca3af}}
  #empty-hint{{color:#475569;font-size:12px;line-height:1.6}}

  /* ── stabilised notice ── */
  #notice{{position:absolute;bottom:12px;left:50%;transform:translateX(-50%);
           background:#1e293bdd;border:1px solid #334155;border-radius:8px;
           padding:6px 14px;font-size:11px;color:#94a3b8;pointer-events:none;
           transition:opacity .5s}}
</style>
</head>
<body>

<!-- TOP BAR -->
<div id="topbar">
  <h1>&#128274; Guardian · Dependency Graph</h1>
  <div id="stats">
    <span class="stat">Total <b>{total}</b></span>
    <span class="stat">Direct <b>{direct}</b></span>
    <span class="stat">Transitive <b>{trans}</b></span>
  </div>
  <button id="toggleDirect" onclick="toggleDirectOnly()">Show direct deps only</button>
  <div id="searchbox">
    <input id="searchInput" placeholder="Search package…" oninput="searchNodes(this.value)" />
    <button onclick="searchNodes(document.getElementById('searchInput').value)">Go</button>
  </div>
</div>

<!-- MAIN AREA -->
<div id="main">

  <!-- LEGEND -->
  <div id="legend">
    <h3>Legend</h3>
    <div class="leg"><span class="dot root"></span>Root app</div>
    <div class="leg"><span class="dot direct"></span>Direct dep</div>
    <div class="leg"><span class="dot trans"></span>Transitive</div>
    <div class="leg"><span class="dot dev"></span>Dev-only</div>
    <div class="leg"><span class="dot install"></span>Install script ⚠</div>
    <hr style="border-color:#334155;margin:12px 0"/>
    <h3 style="margin-bottom:8px">Tips</h3>
    <p style="font-size:11px;color:#64748b;line-height:1.6">
      • Click a node to see its full path<br>
      • Scroll to zoom<br>
      • Drag canvas to pan<br>
      • Use search to highlight packages<br>
      • "Direct only" hides noise
    </p>
  </div>

  <!-- GRAPH -->
  <div id="graph-container">
    <div id="mynetwork"></div>
    <div id="notice">Stabilising layout…</div>
  </div>

  <!-- SIDEBAR -->
  <div id="sidebar">
    <h3>Package Details</h3>
    <div id="empty-hint">Click any node in the graph to see its dependency path here.</div>
    <div id="pkg-name" style="display:none"></div>
    <div id="pkg-badges" style="display:none"></div>
    <div style="display:none" id="path-label"><h3>Dependency Path</h3></div>
    <div id="pkg-path" style="display:none"></div>
  </div>

</div>

<!-- vis-network inline (via pyvis extraction) -->
<script>
// ── INLINE VIS-NETWORK ── we load it from pyvis's bundled copy
// (pyvis always embeds the full vis JS when cdn_resources="in_line")
</script>
<script>
var allNodes = {nodes_json};
var allEdges = {edges_json};
var pathLookup = {paths_json};

var directOnly = false;
var currentNodes, currentEdges;

function buildDatasets(filterDirect) {{
  var nodes, edges;
  if (filterDirect) {{
    var keep = new Set();
    allNodes.forEach(function(n) {{
      if (n.group === 'root' || n.group === 'direct' || n.group === 'dev' || n.group === 'install') keep.add(n.id);
    }});
    nodes = allNodes.filter(function(n) {{ return keep.has(n.id); }});
    edges = allEdges.filter(function(e) {{ return keep.has(e.from) && keep.has(e.to); }});
  }} else {{
    nodes = allNodes;
    edges = allEdges;
  }}
  return {{ nodes: nodes, edges: edges }};
}}

var container = document.getElementById('mynetwork');
var ds = buildDatasets(false);
currentNodes = new vis.DataSet(ds.nodes);
currentEdges = new vis.DataSet(ds.edges);

var options = {{
  physics: {{
    enabled: true,
    hierarchicalRepulsion: {{ nodeDistance: 160 }},
    stabilization: {{ iterations: 300, updateInterval: 25 }}
  }},
  layout: {{
    hierarchical: {{
      enabled: true,
      direction: 'UD',
      sortMethod: 'directed',
      nodeSpacing: 130,
      levelSeparation: 100,
      treeSpacing: 180
    }}
  }},
  interaction: {{
    hover: true,
    navigationButtons: true,
    tooltipDelay: 100
  }},
  edges: {{ smooth: {{ type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.4 }} }},
  nodes: {{ borderWidth: 0, chosen: true }}
}};

var network = new vis.Network(container, {{ nodes: currentNodes, edges: currentEdges }}, options);

network.on('stabilizationIterationsDone', function() {{
  document.getElementById('notice').style.opacity = '0';
  network.setOptions({{ physics: {{ enabled: false }} }});
}});

// Click: show sidebar details
network.on('click', function(params) {{
  if (!params.nodes.length) return;
  var id = params.nodes[0];
  var node = allNodes.find(function(n) {{ return n.id === id; }});
  if (!node) return;

  document.getElementById('empty-hint').style.display = 'none';
  document.getElementById('pkg-name').style.display = 'block';
  document.getElementById('pkg-badges').style.display = 'flex';
  document.getElementById('path-label').style.display = 'block';
  document.getElementById('pkg-path').style.display = 'block';

  document.getElementById('pkg-name').textContent = node.label;

  var badges = '';
  if (node.group === 'root')    badges += '<span class="badge direct">root</span>';
  if (node.group === 'direct')  badges += '<span class="badge direct">direct</span>';
  if (node.group === 'trans')   badges += '<span class="badge trans">transitive</span>';
  if (node.group === 'dev')     badges += '<span class="badge dev">dev-only</span>';
  if (node.group === 'install') badges += '<span class="badge install">⚠ install script</span>';
  document.getElementById('pkg-badges').innerHTML = badges;

  var path = pathLookup[id] || '(path not available)';
  // Replace → with styled arrows
  document.getElementById('pkg-path').innerHTML = path.split(' → ').map(function(p,i,arr) {{
    var style = i === arr.length-1 ? 'color:#facc15;font-weight:700' : 'color:#94a3b8';
    return '<span style="' + style + '">' + p + '</span>';
  }}).join('<br/>↓ ');
}});

// Search: highlight matching nodes yellow
function searchNodes(term) {{
  term = term.trim().toLowerCase();
  var updated = allNodes.map(function(n) {{
    var copy = Object.assign({{}}, n, {{ color: Object.assign({{}}, n.color) }});
    if (term && n.label.toLowerCase().includes(term)) {{
      copy.color = {{ background: '#facc15', border: '#f59e0b',
                      highlight: {{ background: '#facc15', border: '#f59e0b' }} }};
      copy.size = (n.size || 12) * 1.6;
    }}
    return copy;
  }});
  currentNodes.update(updated);
}}

// Toggle direct-only view
function toggleDirectOnly() {{
  directOnly = !directOnly;
  var btn = document.getElementById('toggleDirect');
  btn.classList.toggle('active', directOnly);
  btn.textContent = directOnly ? 'Show all packages' : 'Show direct deps only';

  document.getElementById('notice').style.opacity = '1';
  document.getElementById('notice').textContent = 'Rebuilding layout…';

  var ds = buildDatasets(directOnly);
  currentNodes = new vis.DataSet(ds.nodes);
  currentEdges = new vis.DataSet(ds.edges);
  network.setData({{ nodes: currentNodes, edges: currentEdges }});
  network.setOptions({{ physics: {{ enabled: true }} }});
}}
</script>
</body>
</html>"""

        # ── 3. We need vis-network JS. Grab it from pyvis's bundled copy. ──
        # pyvis ships the full vis-network JS as a local file we can read.
        try:
            import pyvis, os as _os
            pyvis_dir = _os.path.dirname(pyvis.__file__)
            vis_js_path = _os.path.join(pyvis_dir, "templates", "lib", "bindings", "utils.js")
            # The main vis JS is at a different path depending on pyvis version
            for candidate in [
                _os.path.join(pyvis_dir, "templates", "lib", "vis-network.min.js"),
                _os.path.join(pyvis_dir, "templates", "lib", "vis", "vis-network.min.js"),
            ]:
                if _os.path.exists(candidate):
                    vis_js_path = candidate
                    break

            if _os.path.exists(vis_js_path):
                with open(vis_js_path, "r", encoding="utf-8", errors="replace") as fvis:
                    vis_js = fvis.read()
                # Insert the vis JS before our script block
                vis_tag = f"<script>\n{vis_js}\n</script>"
                html = html.replace(
                    "<!-- vis-network inline (via pyvis extraction) -->",
                    vis_tag
                )
            else:
                # Fall back to CDN (requires internet)
                cdn_tag = '<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>'
                html = html.replace(
                    "<!-- vis-network inline (via pyvis extraction) -->",
                    cdn_tag
                )
                print("[mapper] vis-network JS not found locally; graph.html will need internet for the CDN fallback")
        except Exception as _exc:
            cdn_tag = '<script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>'
            html = html.replace(
                "<!-- vis-network inline (via pyvis extraction) -->",
                cdn_tag
            )

        path = self.out_dir / "graph.html"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[mapper] Dependency graph → {path}")

    def _write_graph_html_fallback(self) -> None:
        """Simple HTML fallback when pyvis is not installed."""
        nodes_json = json.dumps([
            {"id": n, "label": self.graph.nodes[n].get("label", n)}
            for n in self.graph.nodes
        ])
        edges_json = json.dumps([
            {"from": u, "to": v}
            for u, v in self.graph.edges
        ])

        # We embed vis-network from CDN so the graph still works offline-ish
        html = f"""<!DOCTYPE html>
<html>
<head>
  <title>Dependency Graph – Guardian</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ background: #1a1a2e; color: #e0e0e0; font-family: sans-serif; margin:0; }}
    #graph {{ width: 100vw; height: 100vh; }}
  </style>
</head>
<body>
  <div id="graph"></div>
  <script>
    var nodes = new vis.DataSet({nodes_json});
    var edges = new vis.DataSet({edges_json});
    var container = document.getElementById('graph');
    var data = {{ nodes: nodes, edges: edges }};
    var options = {{
      physics: {{ barnesHut: {{ gravitationalConstant: -8000 }} }},
      edges: {{ arrows: 'to' }},
      nodes: {{ shape: 'dot', size: 10 }}
    }};
    var network = new vis.Network(container, data, options);
  </script>
</body>
</html>"""
        path = self.out_dir / "graph.html"
        path.write_text(html, encoding="utf-8")
        print(f"[mapper] Dependency graph (CDN fallback) → {path}")

    # ------------------------------------------------------------------
    # Coverage evidence
    # ------------------------------------------------------------------

    def _write_coverage_evidence(self) -> None:
        total = len(self.components)
        direct = sum(1 for c in self.components if c.is_direct)
        self.ledger.add_evidence(
            kind="coverage",
            source="mapper",
            component="",
            data={
                "total_components": total,
                "direct": direct,
                "transitive": total - direct,
                "plugin_coverage": self.coverage,
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _uuid() -> str:
        import uuid
        return str(uuid.uuid4())
