"""Graph nodes, part 2: Reader, Rules, Analyst, Verifier, Skeptic, Remediator, Validator, Reporter."""
from pathlib import Path

from guardian import (
    analyst,
    chooser,
    config,
    hunter,
    pipeline,
    reader,
    remediator,
    rules_build,
    skeptic,
    validator,
    verifier,
)
from guardian.ledger import Ledger
from guardian.llm import client
from guardian.tracing import rd_of, traced


def run_of(state):
    rd = rd_of(state)
    return rd, config.load_run(rd)


@traced("reader")
def reader_node(state):
    rd, run = run_of(state)
    items = hunter.load_part(rd, "reader_items", [])
    if not run.get("ai", True) or not client.ai_available():
        res = {"flags": {}, "status": "AI layer off", "injection_ids": [], "raw_items": len(items)}
    else:
        res = reader.run_reader(rd, config.model_cheap(), items)
    config.write_json(rd / "reader.json", res)
    return {}


@traced("rules")
def rules_node(state):
    rd, run = run_of(state)
    model = config.read_json(rd / "model.json", {})
    led = Ledger(rd / "ledger.json")
    ch = hunter.load_part(rd, "changes", {})
    r_res = config.read_json(rd / "reader.json", {})
    findings = rules_build.build_findings(led, model, ch, r_res)
    config.write_json(rd / "findings.json", findings)
    status = state.get("status", "running")
    canary = hunter.load_part(rd, "canary", {})
    if canary and not canary.get("ok"):
        status = "UNTRUSTED"
    osv = hunter.load_part(rd, "osv", {})
    if osv and not osv.get("ok"):
        status = "INCOMPLETE"
    pending = [f["id"] for f in analyst.targets(findings)]
    return {"status": status, "repairs": 0, "pending": pending, "fix_errors": {}}


@traced("analyst")
def analyst_node(state):
    rd, run = run_of(state)
    if not run.get("ai", True) or not client.ai_available():
        return {}
    findings = config.read_json(rd / "findings.json", [])
    led = Ledger(rd / "ledger.json")
    pending = state.get("pending") or [f["id"] for f in analyst.targets(findings)]
    fix_errors = state.get("fix_errors", {})
    items, err = analyst.analyst_round(rd, config.model_cheap(), findings, led, pending, fix_errors)
    config.write_json(rd / "analyst_pending.json", items)
    return {"errors": [f"analyst: {err}"] if err else []}


@traced("verifier_analyst")
def verifier_analyst_node(state):
    rd, run = run_of(state)
    findings = config.read_json(rd / "findings.json", [])
    if not run.get("ai", True) or not client.ai_available():
        for f in findings:
            f["ai_status"] = "AI layer off"
        config.write_json(rd / "findings.json", findings)
        return {"pending": [], "fix_errors": {}}
    items = config.read_json(rd / "analyst_pending.json", [])
    led = Ledger(rd / "ledger.json")
    f_by_id = {f["id"]: f for f in findings}
    ok_map, bad_map = verifier.verify_explanations(items, led, f_by_id)
    for fid, it in ok_map.items():
        if fid in f_by_id:
            f_by_id[fid].update(explanation=it["explanation"], ai_status="verified",
                                evidence_ids_used=it["evidence_ids_used"])
    repairs = state.get("repairs", 0)
    if bad_map and repairs < config.MAX_REPAIRS:
        return {"repairs": repairs + 1, "pending": list(bad_map.keys()), "fix_errors": bad_map}
    for fid, errs in bad_map.items():
        if fid in f_by_id:
            f_by_id[fid].update(ai_status=f"unverified: {errs[0]}",
                                explanation=f"Finding {fid} involving {f_by_id[fid].get('component', '')}. (Unverified claim rejected)")
    config.write_json(rd / "findings.json", list(f_by_id.values()))
    return {"pending": [], "fix_errors": {}}


@traced("skeptic")
def skeptic_node(state):
    rd, run = run_of(state)
    findings = config.read_json(rd / "findings.json", [])
    if not run.get("ai", True) or not client.ai_available():
        return {}
    led = Ledger(rd / "ledger.json")
    msg = skeptic.run_skeptic(rd, config.model_big(), findings, led)
    config.write_json(rd / "findings.json", findings)
    return {}


@traced("remediator")
def remediator_node(state):
    rd, run = run_of(state)
    findings = config.read_json(rd / "findings.json", [])
    model = config.read_json(rd / "model.json", {})
    plans = remediator.build_all(findings, model)
    if run.get("ai", True) and client.ai_available():
        led = Ledger(rd / "ledger.json")
        chooser.run_chooser(rd, config.model_cheap(), plans, findings, led)
    config.write_json(rd / "remediation_plans.json", plans)
    return {}


@traced("human_approval")
def human_approval_node(state):
    rd, run = run_of(state)
    if not run.get("remediate"):
        return {}
    led = Ledger(rd / "ledger.json")
    findings = config.read_json(rd / "findings.json", [])
    vulns = [f for f in findings if f["type"] == "vulnerability"]
    if not vulns:
        return {}
    target_f = vulns[0]
    appr = validator.approval_for(led, target_f["id"])
    if not appr:
        try:
            from langgraph.types import interrupt
            interrupt({"action": "approval_required", "finding_id": target_f["id"]})
        except ImportError:
            pass
    return {}


@traced("validator")
def validator_node(state):
    rd, run = run_of(state)
    if not run.get("remediate"):
        return {}
    led = Ledger(rd / "ledger.json")
    findings = config.read_json(rd / "findings.json", [])
    plans = config.read_json(rd / "remediation_plans.json", {})
    vulns = [f for f in findings if f["type"] == "vulnerability"]
    if not vulns:
        return {}
    target_f = vulns[0]
    plan = plans.get(target_f["id"])
    if not plan:
        return {}
    appr = validator.approval_for(led, target_f["id"])
    if not appr:
        return {}
    chosen_opt = next((o for o in plan["options"] if o["id"] == appr["data"]["option_id"]), None)
    if not chosen_opt:
        return {}
    scout = config.read_json(rd / "scout.json")
    before = pipeline.analyze_tree(rd / "before_tmp", scout["repo_dir"], run["offline"])
    try:
        val_res = validator.validate(rd, scout["repo_dir"], target_f, chosen_opt, before, run["offline"])
        config.write_json(rd / "validation.json", val_res)
        if val_res.get("patch"):
            (rd / "remediation.patch").write_text(val_res["patch"], encoding="utf-8")
    except validator.NotApproved as e:
        config.write_json(rd / "validation.json", {"status": "unvalidated suggestion", "reason": str(e)})
    return {}


@traced("reporter")
def reporter_node(state):
    from guardian import reporter
    rd, run = run_of(state)
    reporter.generate_all(rd)
    cur_status = state.get("status")
    if cur_status in ("INCOMPLETE", "UNTRUSTED"):
        final_status = cur_status
    elif state.get("errors"):
        final_status = "INCOMPLETE"
    else:
        final_status = "COMPLETE"
    return {"status": final_status}
