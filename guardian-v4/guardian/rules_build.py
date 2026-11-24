"""rules_build.py: change findings, then final ranking of all findings."""
from guardian import scoring
from guardian.rules import Builder, ids
from guardian.rules_more import file_findings, package_findings


def change_findings(b):
    """Findings that exist because of what changed between baseline and now."""
    comps = b.model["components"]
    for it in b.ch.get("items", []):
        ct, name, ev = it["change_type"], it["package"], [it["evidence_id"]]
        cid = f"{name}@{it['new'] or it['old']}"
        known = cid in comps
        if not known and ct != "manifest_lockfile_drift":
            continue
        base = b.base_ev(cid) if known else []
        fl = b.cflags(cid, introduced=True) if known else \
            {"direct": False, "dev": False, "reach": "unknown", "introduced": True}
        path = b.path(cid) if known else [name]
        kinds = b.idx.get(cid, {})
        if ct == "added":
            hot = bool(kinds.get("typosquat") or kinds.get("install_script"))
            b.add("unexpected_dependency", f"{cid} is a new dependency",
                  "high" if hot else "medium", ev + base, path, cid, fl,
                  ["new package since baseline"] + (["typosquat or install script -> high"] if hot else []))
        elif ct in ("upgraded", "downgraded") and (it["flags"].get("major_jump") or ct == "downgraded"):
            vuln = bool(kinds.get("vuln"))
            b.add("suspicious_update", f"{name} {ct} {it['old']} -> {it['new']}",
                  "high" if vuln else "medium", ev + base + ids(kinds.get("vuln", [])), path, cid, fl,
                  ["major version jump or downgrade -> medium"]
                  + (["new version has a known vulnerability -> high"] if vuln else []))
        elif ct == "modified":
            b.add("modified_lockfile", f"{cid}: same version, different integrity/source", "high",
                  ev + base, path, cid, fl, ["same version number but content hash changed -> high"])
        elif ct == "source_changed":
            b.add("source_changed", f"{cid}: download source changed", "high", ev + base, path, cid,
                  fl, ["package now downloads from a different/unusual source -> high"])
        elif ct == "manifest_lockfile_drift":
            b.add("manifest_lockfile_drift", f"package.json and lockfile disagree ({name})",
                  "medium", ev, [name], "", fl, ["manifest and lockfile do not match -> medium"],
                  it["flags"].get("note", ""))


def build_findings(led, model, changes=None, reader=None):
    """Returns the ranked list of findings (F-001...), sorted by priority score."""
    b = Builder(led, model, changes, reader)
    b.vulns()
    package_findings(b)
    file_findings(b)
    change_findings(b)
    seen, uniq = set(), []
    for f in b.out:                                     # drop exact duplicates
        if (f["type"], f["title"]) not in seen:
            seen.add((f["type"], f["title"]))
            uniq.append(f)
    for f in uniq:
        f["score"], f["score_breakdown"] = scoring.priority_score(f)
        f["confidence"] = scoring.confidence(led, f["evidence_ids"])
    uniq.sort(key=lambda f: (-f["score"], f["title"]))
    for n, f in enumerate(uniq, 1):
        f["id"] = "F-%03d" % n
    return uniq
