"""Hunter: all deterministic lookups and checks. Each function returns plain data.
In the graph they run in parallel and save to out/<run>/parts/*.json; a join step
(hunt_join) then writes the ledger in one fixed order, so the output is repeatable."""
import os
import re
from pathlib import Path

from guardian import config, feeds
from guardian.ecosystems import dockerfile, workflow

REGISTRY_PREFIX = "https://registry.npmjs.org/"
IMPORT_RE = re.compile(r"""(?:require\(\s*|from\s+|import\s+|import\(\s*)['"]([^'"./][^'"]*)['"]""")
SRC_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}
CANARY = ("canary-old-cve", "0.0.1")
CANARY_TYPO = "lodahs"          # planted typosquat of "lodash"


def part_path(rd, name):
    return Path(rd) / "parts" / f"{name}.json"


def save_part(rd, name, data):
    config.write_json(part_path(rd, name), data)


def load_part(rd, name, default=None):
    return config.read_json(part_path(rd, name), default)


# ---------- typosquat ----------
def top_names():
    text = (config.DATA_DIR / "top_npm_packages.txt").read_text(encoding="utf-8")
    return sorted({x.strip() for x in text.splitlines() if x.strip()})


def edit_distance(a, b, limit=2):
    """Levenshtein distance; gives up (returns limit+1) when clearly too far."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_check(name, tops=None):
    """Return {'similar_to', 'distance'} if `name` looks like a popular name, else None."""
    tops = tops if tops is not None else top_names()
    if name in tops or name.startswith("@") or len(name) < 4:
        return None
    flat = re.sub(r"[-_.]", "", name)
    for top in tops:                               # separator tricks: lo-dash vs lodash
        if top != name and flat == re.sub(r"[-_.]", "", top) and len(flat) >= 4:
            return {"similar_to": top, "distance": 1}
    best = None
    limit = 2
    for top in tops:
        if len(top) < 4:
            continue
        d = edit_distance(name, top, limit)
        if 1 <= d <= limit and (best is None or d < best["distance"]):
            best = {"similar_to": top, "distance": d}
    return best


# ---------- static component checks ----------
def unusual_source(c):
    r = c.get("resolved", "")
    if not r:
        return "no resolved URL" if not c.get("integrity") else None
    if not r.startswith(REGISTRY_PREFIX):
        return "non-registry source: " + r.split("?")[0][:100]
    if not c.get("integrity"):
        return "missing integrity hash"
    return None


def imported_names(repo_dir):
    """Read-only text search: which package names do source files import?"""
    names, seen = set(), 0
    for dp, dn, fn in os.walk(repo_dir):
        dn[:] = [d for d in dn if d not in {"node_modules", ".git", "dist", "build"}]
        for f in fn:
            if Path(f).suffix in SRC_EXT and seen < 3000:
                seen += 1
                try:
                    text = (Path(dp) / f).read_text(encoding="utf-8", errors="ignore")[:300000]
                except OSError:
                    continue
                for m in IMPORT_RE.findall(text):
                    parts = m.split("/")
                    names.add("/".join(parts[:2]) if m.startswith("@") else parts[0])
    return names, seen


def static_checks(model, repo_dir):
    """Typosquat, install script, unusual source, reachability hint (HEURISTIC)."""
    tops = top_names()
    names, seen = imported_names(repo_dir) if repo_dir else (set(), 0)
    out = {"typosquat": {}, "install": [], "unusual": {}, "reach": {}}
    for cid, c in sorted(model["components"].items()):
        t = typosquat_check(c["name"], tops)
        if t:
            out["typosquat"][cid] = t
        if c["install_script"]:
            out["install"].append(cid)
        u = unusual_source(c)
        if u:
            out["unusual"][cid] = u
        if c["direct"] and seen:
            out["reach"][cid] = "imported" if c["name"] in names else "not found"
        else:
            out["reach"][cid] = "unknown"
    return out


# ---------- Dockerfile / workflow ----------
def docker_workflow(repo_dir, scout):
    issues, runs = [], []
    for kind, mod, files in (("dockerfile", dockerfile, scout["dockerfiles"]),
                             ("workflow", workflow, scout["workflows"])):
        for rel in files:
            text = (Path(repo_dir) / rel).read_text(encoding="utf-8", errors="ignore")
            res = mod.scan(text)
            issues += [dict(i, file=rel, kind=kind) for i in res["issues"]]
            runs += [dict(r, file=rel, kind=kind) for r in res["run_lines"]]
    return {"issues": issues, "run_lines": runs}


# ---------- OSV (+EPSS), KEV and Sentinel ----------
def vuln_lookup(components, offline):
    """The ONE code path used for real components and for the Sentinel canary."""
    return feeds.osv_lookup(components, offline)


def hunt_osv(model, offline):
    comps = [(c["name"], c["version"]) for c in model["components"].values()]
    try:
        res = vuln_lookup(comps, offline)
    except feeds.FeedError as e:
        return {"ok": False, "error": "vulnerability data unavailable: " + str(e), "vulns": {}}
    cves = sorted({x for vs in res["vulns"].values() for v in vs for x in v["cves"]})
    out = {"ok": True, "error": "", "vulns": res["vulns"], "snapshot": res["snapshot"],
           "epss": {}, "epss_note": "", "epss_snapshot": ""}
    try:
        out["epss"], out["epss_snapshot"] = feeds.epss_scores(cves, offline)
    except feeds.FeedError as e:
        out["epss_note"] = "EPSS unavailable: " + str(e)
    return out


def hunt_kev(offline):
    try:
        cves, snap = feeds.kev_set(offline)
        return {"ok": True, "cves": sorted(cves), "snapshot": snap, "note": ""}
    except feeds.FeedError as e:
        return {"ok": False, "cves": [], "snapshot": "", "note": "KEV unavailable: " + str(e)}


def sentinel(offline):
    """Plant a known-bad package and a typosquat; both must be caught by the normal code."""
    cid = f"{CANARY[0]}@{CANARY[1]}"
    try:
        res = vuln_lookup([CANARY], offline)
        vuln_ok = bool(res["vulns"].get(cid))
    except feeds.FeedError:
        vuln_ok = False
    typo_ok = typosquat_check(CANARY_TYPO) is not None
    return {"vuln_caught": vuln_ok, "typosquat_caught": typo_ok, "ok": vuln_ok and typo_ok}

