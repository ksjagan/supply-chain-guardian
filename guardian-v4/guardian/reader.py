"""Reader: the quarantined LLM. Sees ONLY untrusted text, outputs booleans only.
It cannot influence anything except by raising flags that the rules turn into risk UP-moves."""
import re

from guardian import feeds
from guardian.llm import client, prompts, schemas
from guardian.security.sanitize import clean_untrusted

MAX_ITEMS = 15
# Code-side phrase check: a second, deterministic look for AI-directed instructions.
INJECTION_RE = re.compile(r"(?i)(ignore (all |any )?(previous|prior|above) instructions|"
                          r"mark (this|it) (as )?safe|you are (now )?an? (ai|assistant)|"
                          r"disregard (the )?(system|previous)|as an ai\b)")


def gather(led, offline, model_components):
    """Collect untrusted text for flagged items only. Returns list of {id, text, cid}."""
    items = []
    flagged = led.by_kind("install_script", "typosquat", "unusual_source")
    seen, wanted = set(), []
    for it in flagged:
        d = it["data"]
        if (d["name"], d["version"]) not in seen:
            seen.add((d["name"], d["version"]))
            wanted.append((it, d["name"], d["version"]))
    texts = feeds.registry_text([(n, v) for _, n, v in wanted], offline) if wanted else {}
    for it, n, v in wanted:
        t = texts.get(f"{n}@{v}")
        if t:
            scripts = "\n".join(f"{k}: {s}" for k, s in sorted(t["scripts"].items())
                                if k in ("preinstall", "install", "postinstall", "prepare"))
            items.append({"id": it["id"], "cid": f"{n}@{v}",
                          "text": clean_untrusted(scripts + "\n" + t["description"])})
    for it in led.by_kind("dockerfile_issue", "workflow_issue"):
        items.append({"id": it["id"], "cid": "", "text": clean_untrusted(it["data"]["text"])})
    return items[:MAX_ITEMS]


def run_reader(rd, model, items):
    """Returns {"flags": {evidence_id: {flag: bool}}, "status": str, "injection_ids": [...]}."""
    out = {"flags": {}, "status": "not run", "injection_ids": [], "raw_items": len(items)}
    out["injection_ids"] = [i["id"] for i in items if INJECTION_RE.search(i["text"])]
    if not items:
        out["status"] = "nothing to read"
        return out
    payload = {"items": [{"id": i["id"], "text": i["text"]} for i in items]}
    parsed, info = client.call_json(rd, "reader", model, prompts.READER, payload, schemas.READER)
    if not parsed:
        out["status"] = "unavailable: " + info["error"]
        return out
    known = {i["id"] for i in items}
    for row in parsed["items"]:
        if row["id"] in known:                           # ignore any ID we did not send
            out["flags"][row["id"]] = {k: row[k] for k in schemas.FLAGS}
    out["status"] = "ok"
    return out
