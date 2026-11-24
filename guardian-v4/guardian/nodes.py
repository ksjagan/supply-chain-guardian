"""Graph nodes, part 1: Scout, Mapper and the parallel Hunter lookups (all deterministic)."""
from pathlib import Path

from guardian import baseline, changes, collect, config, hunter, mapper, reader
from guardian.ledger import Ledger
from guardian.scout import run_scout
from guardian.tracing import rd_of, traced


def run_of(state):
    rd = rd_of(state)
    return rd, config.load_run(rd)


def load_model(rd):
    return config.read_json(rd / "model.json")


@traced("scout")
def scout_node(state):
    rd, run = run_of(state)
    rec = run_scout(run["source"], rd)
    config.write_json(rd / "scout.json", rec)
    if rec["error"]:
        return {"errors": ["scout: " + rec["error"]], "status": "INCOMPLETE"}


def after_scout(state):
    rec = config.read_json(rd_of(state) / "scout.json", {})
    return "reporter" if rec.get("error") else "mapper"


@traced("mapper")
def mapper_node(state):
    rd, run = run_of(state)
    scout = config.read_json(rd / "scout.json")
    texts = baseline.read_tree(scout["repo_dir"])
    model = mapper.build_model(texts["npm_lock"])
    if not scout["lockfiles"]:
        model["errors"].append("no package-lock.json found: nothing to analyse")
    config.write_json(rd / "model.json", model)
    config.write_json(rd / "sbom.cdx.json", mapper.sbom(model, run.get("name", "app")))
    config.write_json(rd / "graph.json", mapper.graph_json(model))
    config.write_json(rd / "coverage.json", mapper.coverage(model, scout, not model["errors"]))
    return {"errors": ["mapper: " + e for e in model["errors"]]}


@traced("hunt_osv")
def hunt_osv_node(state):
    rd, run = run_of(state)
    part = hunter.hunt_osv(load_model(rd), run["offline"])
    hunter.save_part(rd, "osv", part)
    return {"errors": [part["error"]] if not part["ok"] else []}


@traced("hunt_kev")
def hunt_kev_node(state):
    rd, run = run_of(state)
    part = hunter.hunt_kev(run["offline"])
    hunter.save_part(rd, "kev", part)
    return {"errors": [part["note"]] if part["note"] else []}


@traced("hunt_static")
def hunt_static_node(state):
    rd, _ = run_of(state)
    scout = config.read_json(rd / "scout.json")
    hunter.save_part(rd, "static", hunter.static_checks(load_model(rd), scout["repo_dir"]))


@traced("hunt_files")
def hunt_files_node(state):
    rd, _ = run_of(state)
    scout = config.read_json(rd / "scout.json")
    hunter.save_part(rd, "docker", hunter.docker_workflow(scout["repo_dir"], scout))


@traced("hunt_canary")
def hunt_canary_node(state):
    rd, run = run_of(state)
    hunter.save_part(rd, "canary", hunter.sentinel(run["offline"]))


def _baseline(run, repo_dir):
    since = run.get("since")
    if run.get("since_dir"):
        return baseline.read_dir(run["since_dir"])
    if since == "last":
        return baseline.read_last(run["source"])
    return baseline.read_git(repo_dir, since)


@traced("hunt_changes")
def hunt_changes_node(state):
    rd, run = run_of(state)
    if not (run.get("since") or run.get("since_dir")):
        hunter.save_part(rd, "changes", {"status": "none", "items": [], "evidence": []})
        return
    scout = config.read_json(rd / "scout.json")
    try:
        old, meta = _baseline(run, scout["repo_dir"])
    except baseline.BaselineError as e:
        hunter.save_part(rd, "changes", {"status": "unavailable", "error": f"baseline unavailable: {e}",
                                         "items": [], "evidence": []})
        return
    new = baseline.read_tree(scout["repo_dir"])
    res = changes.compare(old, new, meta, run["offline"], load_model(rd))
    hunter.save_part(rd, "changes", res)
    return {"errors": [res["error"]] if res["status"] == "incomplete" else []}


@traced("hunt_join")
def hunt_join_node(state):
    """Wait for all parallel lookups, then write the ledger in ONE fixed order."""
    rd, run = run_of(state)
    model = load_model(rd)
    parts = {k: hunter.load_part(rd, k) for k in ("osv", "kev", "static", "docker", "canary", "changes")}
    led = collect.build_ledger(rd, model, parts)
    hunter.save_part(rd, "changes", parts["changes"])         # now carries evidence IDs
    items = reader.gather(led, run["offline"], model)
    for it in items:                                          # code-side phrase check (AI-free)
        if it["cid"] and reader.INJECTION_RE.search(it["text"]):
            name, ver = it["cid"].rsplit("@", 1)
            led.add("injection_text", "text-pattern", {"name": name, "version": ver,
                                                       "rule": "text addresses an AI"})
    led.save()
    hunter.save_part(rd, "reader_items", items)
