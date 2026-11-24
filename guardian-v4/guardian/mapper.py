"""Mapper: lockfile text -> components + edges, CycloneDX SBOM, networkx graph, paths.
The SAME functions parse the old and the new side when we compare (changes.py)."""
import networkx as nx

from guardian import config
from guardian.ecosystems import npm
from guardian.ecosystems.npm import ROOT_ID


def build_model(lock_texts):
    """lock_texts: {relative_path: text}. Several lockfiles are merged into one graph."""
    comps, edges, errors, root_deps = {}, set(), [], {}
    for path, text in sorted(lock_texts.items()):
        res = npm.parse_lock(text)
        if not res["ok"]:
            errors.append(f"{path}: {res['error']}")
            continue
        root_deps.update(res["root_deps"])
        for cid, c in res["components"].items():
            if cid in comps:
                m = comps[cid]
                m["dev"] = m["dev"] and c["dev"]
                m["install_script"] = m["install_script"] or c["install_script"]
                m["lockfiles"] = sorted(set(m["lockfiles"] + [path]))
            else:
                comps[cid] = dict(c, lockfiles=[path])
        edges |= set(res["edges"])
    truncated = len(comps) > config.MAX_COMPONENTS
    if truncated:
        keep = set(sorted(comps)[:config.MAX_COMPONENTS])
        comps = {k: v for k, v in comps.items() if k in keep}
        edges = {e for e in edges if e[1] in keep and (e[0] in keep or e[0] == ROOT_ID)}
        errors.append(f"more than {config.MAX_COMPONENTS} components; extra ones skipped")
    model = {"components": comps, "edges": sorted(edges), "errors": errors,
             "root_deps": root_deps, "truncated": truncated}
    annotate(model)
    return model


def to_graph(model):
    g = nx.DiGraph()
    g.add_node(ROOT_ID)
    g.add_nodes_from(model["components"])
    g.add_edges_from(model["edges"])
    return g


def annotate(model):
    """Add direct/transitive, shortest path from root, and the origin direct dependency."""
    g = to_graph(model)
    try:
        paths = nx.single_source_shortest_path(g, ROOT_ID)
    except nx.NetworkXError:
        paths = {}
    for cid, c in model["components"].items():
        p = paths.get(cid)
        c["path"] = p or []
        c["direct"] = bool(p) and len(p) == 2
        c["origin"] = p[1] if p and len(p) > 1 else ""
        c["origin_direct"] = c["origin"]
        c["reachable_from_root"] = bool(p)


def path_to(model, cid):
    """Shortest path app -> ... -> component. Empty list if the component is unknown."""
    c = model["components"].get(cid)
    return list(c["path"]) if c else []


def path_text(model, cid):
    return " -> ".join(path_to(model, cid))


def sbom(model, app_name="app"):
    """CycloneDX 1.5 JSON as a dict."""
    comps = []
    for cid in sorted(model["components"]):
        c = model["components"][cid]
        item = {"type": "library", "bom-ref": npm.purl(c["name"], c["version"]),
                "name": c["name"], "version": c["version"],
                "purl": npm.purl(c["name"], c["version"])}
        if c["integrity"]:
            alg, _, val = c["integrity"].partition("-")
            item["hashes"] = [{"alg": alg.upper().replace("SHA", "SHA-"), "content": val}]
        if c["dev"]:
            item["scope"] = "excluded"
        comps.append(item)
    ref = lambda cid: npm.purl(*cid.rsplit("@", 1)) if cid != ROOT_ID else "app-root"
    deps = {}
    for a, b in model["edges"]:
        deps.setdefault(ref(a), []).append(ref(b))
    dep_list = [{"ref": k, "dependsOn": sorted(set(v))} for k, v in sorted(deps.items())]
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "bom-ref": "app-root", "name": app_name}},
            "components": comps, "dependencies": dep_list}


def graph_json(model, risk_by_comp=None):
    """Nodes and edges for the UI. risk_by_comp: {component_id: (risk, vuln_count)}."""
    risk_by_comp = risk_by_comp or {}
    nodes = [{"id": ROOT_ID, "label": "app", "direct": False, "risk": "ok", "vulns": 0}]
    for cid, c in sorted(model["components"].items()):
        risk, n = risk_by_comp.get(cid, ("ok", 0))
        nodes.append({"id": cid, "label": cid, "direct": c["direct"], "dev": c["dev"],
                      "origin": c["origin"], "risk": risk, "vulns": n})
    return {"nodes": nodes, "edges": [{"from": a, "to": b} for a, b in model["edges"]]}


def coverage(model, scout, analysed_ok=True):
    """The Coverage box: detected / fully analysed / partial / skipped."""
    detected = [{"path": p, "kind": "npm lockfile"} for p in scout["lockfiles"]]
    detected += [{"path": p, "kind": "Dockerfile"} for p in scout["dockerfiles"]]
    detected += [{"path": p, "kind": "GitHub workflow"} for p in scout["workflows"]]
    detected += [{"path": o["path"], "kind": o["ecosystem"]} for o in scout["other"]]
    full, partial = [], []
    bad = {e.split(":", 1)[0] for e in model["errors"]}
    for p in scout["lockfiles"]:
        (partial if p in bad or not analysed_ok else full).append(p)
    full += scout["dockerfiles"] + scout["workflows"]
    return {"detected": detected, "fully_analysed": full, "partial": partial,
            "skipped": scout["skipped"],
            "not_supported_yet": ["PyPI", "Maven", "Go"]}
