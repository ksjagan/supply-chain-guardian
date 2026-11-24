"""Skeptic: a bigger model with a different prompt gives a blind second opinion on
high/critical findings. Differs by 1+ level -> needs-review. Risk is NEVER changed by it."""
from guardian import verifier
from guardian.llm import client, prompts, schemas
from guardian.models import SEV, sev_index

TOP_N = 5


def skeptic_view(f, led):
    from guardian.security.sanitize import llm_view
    # No Analyst text, no code-computed risk: a blind opinion from evidence only.
    return {"id": f["id"], "type": f["type"], "title": f["title"],
            "evidence": [llm_view(led.get(e)) for e in f["evidence_ids"] if led.get(e)]}


def run_skeptic(rd, model, findings, led):
    top = [f for f in findings if f["risk"] in ("high", "critical")][:TOP_N]
    if not top:
        return "skipped: no high/critical findings"
    by_id = {f["id"]: f for f in top}
    payload = {"findings": [skeptic_view(f, led) for f in top]}
    parsed, info = client.call_json(rd, "skeptic", model, prompts.SKEPTIC, payload, schemas.SKEPTIC)
    if not parsed:
        for f in top:
            f["skeptic"] = {"opinion": "unavailable", "status": info["error"]}
        return "skeptic unavailable: " + info["error"]
    got = set()
    for op in parsed["opinions"]:
        f = by_id.get(op["id"])
        if not f or any(not led.exists(e) for e in op["evidence_ids_used"]):
            continue                                     # unknown ID or evidence: ignore claim
        got.add(f["id"])
        gap = 99 if op["risk_opinion"] == "needs-review" else \
            abs(sev_index(op["risk_opinion"]) - sev_index(f["risk"]))
        status = "agrees" if gap == 0 else "needs-review"
        f["skeptic"] = {"opinion": op["risk_opinion"], "status": status,
                        "evidence_ids_used": op["evidence_ids_used"]}
        if status == "needs-review":
            f["status"] = "needs-review"                 # label only; risk stays as code computed
    for f in top:
        if f["id"] not in got:
            f["skeptic"] = {"opinion": "none", "status": "no valid opinion returned"}
    return f"skeptic reviewed {len(got)} of {len(top)}"
