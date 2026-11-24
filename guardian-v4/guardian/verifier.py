"""Verifier: plain code, no AI. Checks every LLM claim against the ledger.
Returns a list of exact errors; an empty list means the claim passed."""
import json
import re

from guardian import hunter

ID_RE = re.compile(r"\b([EOF])-(\d{1,4})\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
GHSA_RE = re.compile(r"\bGHSA(?:-[0-9a-z]{4}){3}\b")
NUM_RE = re.compile(r"(?<![\w.@-])v?(\d+(?:\.\d+)+|\d{2,})(?![\w-])")
BACKTICK_RE = re.compile(r"`([^`]{2,80})`")
SCOPED_RE = re.compile(r"@[a-z0-9][\w.-]*/[a-z0-9][\w.-]*")
_TOPS = None


def _tops():
    global _TOPS
    if _TOPS is None:
        _TOPS = set(hunter.top_names())
    return _TOPS


def _text_of(evidence_items, extra_text=""):
    return json.dumps([e["data"] for e in evidence_items], sort_keys=True) + " " + extra_text


def verify_claim(text, cited, ledger, option_ids=(), context=""):
    """text: the explanation. cited: IDs the model says it used.
    option_ids: valid O-IDs for this claim. context: extra trusted text (finding title/options)."""
    errors = []
    cited = list(cited or [])
    if not cited:
        errors.append("no evidence IDs cited")
    mentioned = [f"{a}-{b}" for a, b in ID_RE.findall(text)]
    for cid in list(dict.fromkeys(cited + mentioned)):
        if cid.startswith("E-") and not ledger.exists(cid):
            errors.append(f"{cid} does not exist in the ledger")
        elif cid.startswith("O-") and cid not in option_ids:
            errors.append(f"{cid} is not an offered option")
        elif cid[0] not in "EOF":
            errors.append(f"{cid} is not a valid ID")
    for cid in cited:                               # every cited ID must also appear in the text
        if cid.startswith("E-") and ledger.exists(cid) and cid not in mentioned:
            errors.append(f"{cid} is listed as used but not cited in the text")
    if errors:
        return errors
    ev = [ledger.get(c) for c in dict.fromkeys(cited + mentioned) if c.startswith("E-")]
    allowed = _text_of(ev, context)
    body = ID_RE.sub(" ", text)
    for cve in sorted(set(CVE_RE.findall(body) + GHSA_RE.findall(body))):
        if cve not in allowed:
            errors.append(f"{cve} is not in the cited evidence {sorted(set(cited))}")
    for num in sorted(set(NUM_RE.findall(body))):
        if not re.search(r"(?<![\d.])" + re.escape(num) + r"(?![\d])", allowed):
            ids = ", ".join(c for c in cited if c.startswith("E-")) or "none"
            errors.append(f"{ids} does not support the number/version {num}")
    names = set(BACKTICK_RE.findall(body)) | set(SCOPED_RE.findall(body))
    names |= {w for w in re.findall(r"[a-z][a-z0-9._-]{3,}", body) if w in _tops()
              and ("-" in w or "." in w)}
    for n in sorted(names):
        if n not in allowed and not re.search(r"\b" + re.escape(n.split("@")[0]) + r"\b", allowed):
            errors.append(f"name '{n}' does not appear in the cited evidence")
    return errors


def verify_explanations(items, ledger, finding_by_id, rounds_left=2):
    """items: [{id, explanation, evidence_ids_used}]. Returns (ok_map, errors_map)."""
    ok, bad = {}, {}
    for it in items:
        f = finding_by_id.get(it["id"])
        if not f:
            bad[it["id"]] = [f"{it['id']} is not a known finding"]
            continue
        errs = verify_claim(it["explanation"], it["evidence_ids_used"], ledger,
                            context=f["title"] + " " + f.get("detail", ""))
        extra = [e for e in it["evidence_ids_used"]
                 if e.startswith("E-") and e not in f["evidence_ids"]]
        if extra and not errs:
            errs = [f"{extra[0]} is not evidence of finding {f['id']}"]
        (bad if errs else ok)[it["id"]] = errs or it
    return ok, bad
