"""Collect: turn Hunter parts (plain JSON files) into Evidence Ledger entries.
Fixed order = same input gives the same E-IDs every time."""
from guardian.ledger import Ledger


def _fixed_for(vuln, name):
    return list((vuln.get("fixed") or {}).get(name, []))


def build_ledger(rd, model, parts):
    """parts: dict with osv, kev, static, docker, changes, canary (any may be missing)."""
    led = Ledger(rd / "ledger.json")
    led.items = []
    comps = model["components"]
    osv, kev = parts.get("osv") or {}, parts.get("kev") or {}
    static = parts.get("static") or {"typosquat": {}, "install": [], "unusual": {}, "reach": {}}
    kev_cves = set(kev.get("cves", []))
    flagged = set()

    for cid in sorted(comps):
        c = comps[cid]
        base = {"name": c["name"], "version": c["version"]}
        vulns = (osv.get("vulns") or {}).get(cid, [])
        for v in sorted(vulns, key=lambda x: x["id"]):
            flagged.add(cid)
            led.add("vuln", "osv", dict(base, vuln_id=v["id"], cves=v["cves"], severity=v["severity"],
                                        cvss_est=v["cvss_est"], fixed=_fixed_for(v, c["name"]),
                                        direct=c["direct"], dev=c["dev"]))
            for cve in v["cves"]:
                if cve in kev_cves:
                    led.add("kev", "cisa-kev", dict(base, cve=cve, result="listed in CISA KEV"))
                if cve in (osv.get("epss") or {}):
                    led.add("epss", "first-epss", dict(base, cve=cve, epss=osv["epss"][cve]))
        if cid in static["typosquat"]:
            flagged.add(cid)
            led.add("typosquat", "name-check", dict(base, **static["typosquat"][cid]))
        if cid in static["install"]:
            flagged.add(cid)
            led.add("install_script", "lockfile", dict(base, install_script=True))
        if cid in static["unusual"]:
            flagged.add(cid)
            led.add("unusual_source", "lockfile", dict(base, source=static["unusual"][cid]))
        if cid in flagged:
            led.add("dependency_path", "mapper", dict(base, path=c["path"], direct=c["direct"],
                                                      dev=c["dev"]))
            if static["reach"].get(cid) in ("imported", "not found") and vulns:
                led.add("reachability", "text-search", dict(base, result=static["reach"][cid]))

    for i in (parts.get("docker") or {}).get("issues", []):
        kind = "dockerfile_issue" if i["kind"] == "dockerfile" else "workflow_issue"
        led.add(kind, kind.split("_")[0] + "-scan", {"rule": i["rule"], "file": i["file"],
                                                     "line": i["line"], "text": i["text"]})
    s = parts.get("canary")
    if s:
        led.add("sentinel", "sentinel", {"ok": s["ok"], "result": "canary vulnerability caught: "
                + str(s["vuln_caught"]) + "; typosquat caught: " + str(s["typosquat_caught"])})
    for ch in (parts.get("changes") or {}).get("evidence", []):
        data = {k: v for k, v in ch.items() if k not in ("_kind", "_item")}
        eid = led.add(ch["_kind"], "baseline-compare", data)
        parts["changes"]["items"][ch["_item"]]["evidence_id"] = eid
    led.save()
    return led
