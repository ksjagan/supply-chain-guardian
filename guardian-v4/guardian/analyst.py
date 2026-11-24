"""Analyst: ranks top findings and explains them, citing evidence IDs. Claims only.
One call per round. The graph sends the result to the Verifier and loops (max 2 repairs)."""
from guardian.llm import client, prompts, schemas
from guardian.security.sanitize import llm_view

TOP_N = 10


def finding_view(f, led):
    """Sanitised view of a finding: titles built by code + safe evidence fields. No raw text."""
    return {"id": f["id"], "type": f["type"], "risk": f["risk"], "title": f["title"],
            "detail": f.get("detail", "")[:200] if f["type"] in ("vulnerability", "typosquat") else "",
            "evidence": [llm_view(led.get(e)) for e in f["evidence_ids"] if led.get(e)]}


def targets(findings):
    return [f for f in findings if f["type"] != "prompt_injection_attempt"][:TOP_N]


def analyst_round(rd, model, findings, led, pending, fix_errors):
    """Ask for explanations of the pending finding IDs. Returns (items, error_text)."""
    views = [finding_view(f, led) for f in targets(findings) if f["id"] in pending]
    payload = {"findings": views}
    if fix_errors:
        payload["fix_these"] = {k: v[:3] for k, v in fix_errors.items()}
    parsed, info = client.call_json(rd, "analyst", model, prompts.ANALYST, payload, schemas.ANALYST)
    if not parsed:
        return [], info["error"]
    return [i for i in parsed["findings"] if i["id"] in pending], ""
