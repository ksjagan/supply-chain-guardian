"""The LLM part of remediation: pick ONE code-made option and explain. Verified by code."""
from guardian import verifier
from guardian.llm import client, prompts, schemas
from guardian.security.sanitize import llm_view


def _opt_context(opts):
    return " ".join(f"{o['id']} {o['summary']} {o['risk_reduction']} {o['compatibility']}"
                    for o in opts)


def run_chooser(rd, model, plans, findings, led, limit=5):
    """On any failure the code default stays and the status says why."""
    by_id = {f["id"]: f for f in findings}
    top = [by_id[k] for k in plans if k in by_id and by_id[k]["risk"] in ("high", "critical")]
    top = (top or [by_id[k] for k in plans if k in by_id])[:limit]
    if not top:
        return "no remediation targets"
    keep = ("id", "kind", "package", "to_version", "summary", "risk_reduction", "compatibility")
    payload = {"findings": [{"id": f["id"], "title": f["title"],
                             "options": [{k: o[k] for k in keep} for o in plans[f["id"]]["options"]],
                             "evidence": [llm_view(led.get(e)) for e in f["evidence_ids"]
                                          if led.get(e)]} for f in top]}
    parsed, info = client.call_json(rd, "remediator", model, prompts.REMEDIATOR, payload,
                                    schemas.REMEDIATOR)
    if not parsed:
        for f in top:
            plans[f["id"]]["ai_status"] = "unavailable: " + info["error"]
        return "chooser unavailable: " + info["error"]
    allowed = {f["id"] for f in top}
    for ch in parsed["choices"]:
        plan = plans.get(ch["finding_id"])
        if not plan or ch["finding_id"] not in allowed:
            continue
        f = by_id[ch["finding_id"]]
        oids = [o["id"] for o in plan["options"]]
        if ch["option_id"] not in oids:
            plan["ai_status"] = f"unverified: {ch['option_id']} is not an offered option"
            continue
        context = f["title"] + " " + f.get("detail", "") + " " + _opt_context(plan["options"])
        errs = verifier.verify_claim(ch["explanation"], ch["evidence_ids_used"], led, oids, context)
        if errs:
            plan["ai_status"] = "unverified: " + errs[0]
        else:
            plan.update(ai_choice=ch["option_id"], ai_explanation=ch["explanation"],
                        ai_status="verified")
    return "chooser done"
