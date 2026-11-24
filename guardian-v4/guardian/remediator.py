"""Remediator: CODE builds the fix options; the LLM may only pick one and explain.
Options: O-1 upgrade (direct), O-2 overrides pin (transitive), O-3 remove (dev-only, not imported),
O-4 escalate to a human (always available)."""
from guardian.models import cmp_ver, major, parse_ver

PREFER = ["O-1", "O-2", "O-3", "O-4"]
ROLLBACK = ["git checkout -- package.json package-lock.json", "npm ci"]


def _pick_fix(current, fixed_versions):
    """Smallest fixed version above the current one (prefer the same major version)."""
    higher = sorted((v for v in fixed_versions if cmp_ver(v, current) > 0), key=parse_ver)
    same = [v for v in higher if major(v) == major(current)]
    return (same or higher or [None])[0]


def _manifest_for(model, cid):
    lock = (model["components"].get(cid, {}).get("lockfiles") or ["package-lock.json"])[0]
    return lock.rsplit("/", 1)[0] + "/package.json" if "/" in lock else "package.json"


def _opt(oid, kind, name, to, manifest, summary, reduction, compat, rollback=ROLLBACK):
    return {"id": oid, "kind": kind, "package": name, "to_version": to, "manifest": manifest,
            "summary": summary, "risk_reduction": reduction, "compatibility": compat,
            "rollback": rollback}


def build_options(f, model):
    """Options for one vulnerability finding. Only names/versions from ledger/OSV are used."""
    c = model["components"].get(f["component"])
    if not c:
        return []
    cur, name, opts = c["version"], c["name"], []
    fix = _pick_fix(cur, (f.get("fixed") or {}).get(name, []))
    manifest = _manifest_for(model, f["component"])
    if fix:
        jump = major(fix) != major(cur)
        compat = (f"MAJOR version jump {cur} -> {fix}: breaking changes are possible; run your tests"
                  if jump else f"same major version ({cur} -> {fix}): low compatibility risk")
        gain = f"removes {f['vuln_id']} (fixed in {fix})"
        if c["direct"]:
            opts.append(_opt("O-1", "upgrade", name, fix, manifest,
                             f"Upgrade {name} from {cur} to {fix}", gain, compat))
        else:
            opts.append(_opt("O-2", "override", name, fix, manifest,
                             f"Pin transitive {name} to {fix} using npm overrides", gain,
                             compat + "; overrides force a version the parent did not test"))
    if c["direct"] and c["dev"] and f["flags"].get("reach") != "imported":
        opts.append(_opt("O-3", "remove", name, "", manifest, f"Remove dev-only dependency {name}",
                         "removes the component completely",
                         "dev-only and no import found (heuristic); check build scripts"))
    opts.append(_opt("O-4", "escalate", name, "", manifest,
                     f"Escalate {name} for human review (no automatic change)",
                     "none until a human decides", "no change made", ["nothing to roll back"]))
    return opts


def recommended(options):
    """Default pick by code: the first option in preference order."""
    ids = {o["id"] for o in options}
    return next(i for i in PREFER if i in ids)


def build_all(findings, model):
    plans = {}
    for f in findings:
        if f["type"] == "vulnerability":
            opts = build_options(f, model)
            if opts:
                plans[f["id"]] = {"finding_id": f["id"], "component": f["component"],
                                  "options": opts, "recommended": recommended(opts),
                                  "ai_choice": None, "ai_explanation": "", "ai_status": "not run"}
    return plans
