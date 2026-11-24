"""Explainable priority score (0-100) and confidence. Plain code, visible points."""

SEV_POINTS = {"critical": 40, "high": 30, "medium": 20, "low": 10}


def priority_score(f):
    """Returns (score, breakdown). Breakdown rows are shown in the UI as 'why ranked here'."""
    rows = [{"factor": f"Severity: {f['risk']}", "points": SEV_POINTS[f["risk"]]}]
    fl = f["flags"]
    if fl.get("kev"):
        rows.append({"factor": "Listed in CISA KEV (known exploited)", "points": 25})
    epss = fl.get("epss") or 0
    if epss > 0:
        rows.append({"factor": f"EPSS exploit probability {epss}", "points": round(epss * 15)})
    if fl.get("reach") == "imported":
        rows.append({"factor": "Package is imported in source (heuristic)", "points": 10})
    if fl.get("direct"):
        rows.append({"factor": "Direct dependency", "points": 5})
    if fl.get("introduced"):
        rows.append({"factor": "Introduced by this change", "points": 10})
    if fl.get("dev"):
        rows.append({"factor": "Dev-only dependency", "points": -20})
    total = max(0, min(100, sum(r["points"] for r in rows)))
    return total, rows


def confidence(ledger, evidence_ids):
    """Number of independent evidence SOURCES that agree. 1 = low, 2+ = high. Never from an LLM."""
    sources = sorted({ledger.get(e)["source"] for e in evidence_ids if ledger.get(e)}
                     - {"mapper", "sentinel"})
    return {"sources": sources, "count": len(sources), "level": "high" if len(sources) >= 2 else "low"}
