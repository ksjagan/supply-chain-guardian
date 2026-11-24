"""pipeline.py: the deterministic scan steps in one place (no AI).
The LangGraph nodes call the same pieces; the Validator and eval reuse analyze_tree()."""
import time
from pathlib import Path

from guardian import baseline, changes, collect, config, hunter, mapper
from guardian.rules_build import build_findings


def hunt_all(rd, model, scout, repo_dir, offline):
    """Run every Hunter check one after another (the graph does the same work in parallel)."""
    return {"osv": hunter.hunt_osv(model, offline), "kev": hunter.hunt_kev(offline),
            "static": hunter.static_checks(model, repo_dir),
            "docker": hunter.docker_workflow(repo_dir, scout),
            "canary": hunter.sentinel(offline)}


def analyze_tree(rd, repo_dir, offline=True):
    """Scan a folder end to end without AI. Returns dict(model, scout, parts, ledger, findings)."""
    from guardian import scout as scout_mod
    rd = Path(rd)
    rd.mkdir(parents=True, exist_ok=True)
    scout = scout_mod.run_scout(str(repo_dir), rd)
    texts = baseline.read_tree(repo_dir)
    model = mapper.build_model(texts["npm_lock"])
    parts = hunt_all(rd, model, scout, repo_dir, offline)
    led = collect.build_ledger(rd, model, parts)
    findings = build_findings(led, model, None, None)
    return {"model": model, "scout": scout, "parts": parts, "ledger": led, "findings": findings,
            "texts": texts}


def risk_by_component(findings):
    """{component_id: (highest risk, number of vulnerability findings)} for the graph colours."""
    order = ["low", "medium", "high", "critical"]
    out = {}
    for f in findings:
        cid = f["component"]
        if not cid:
            continue
        risk, n = out.get(cid, ("low", 0))
        out[cid] = (f["risk"] if order.index(f["risk"]) > order.index(risk) else risk,
                    n + (1 if f["type"] == "vulnerability" else 0))
    return out


def stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
