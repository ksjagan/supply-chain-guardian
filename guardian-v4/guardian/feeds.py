"""Data feeds: OSV, CISA KEV, FIRST EPSS, npm registry text. All network use lives here.
Offline mode (--demo-cache) reads committed files from fixtures/osv_offline/ instead."""
import calendar
import os
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from guardian import config
from guardian.models import LABEL_SCORE, LABEL_TO_SEV

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
REGISTRY = "https://registry.npmjs.org/"
TTL = 24 * 3600


class FeedError(Exception):
    pass


def _check_net():
    # Tests and "network blocked" demos set this to prove we never say "clean" on failure.
    if os.environ.get("GUARDIAN_BLOCK_NETWORK") == "1":
        raise FeedError("network blocked (GUARDIAN_BLOCK_NETWORK=1)")


def _post(url, body):
    _check_net()
    try:
        r = requests.post(url, json=body, timeout=30)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        raise FeedError(str(e)[:150])


def _get(url, params=None):
    _check_net()
    try:
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        raise FeedError(str(e)[:150])


def _cache(name):
    return config.CACHE_DIR / name


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def normalize_vuln(v):
    """Boil one OSV record down to the few fields we use."""
    aliases = [a for a in v.get("aliases", []) if isinstance(a, str)]
    cves = sorted({a for a in aliases + [v.get("id", "")] if a.startswith("CVE-")})
    sev = (v.get("database_specific") or {}).get("severity", "")
    sev = LABEL_TO_SEV.get(str(sev).lower(), "medium")
    fixed = {}
    for aff in v.get("affected", []):
        name = (aff.get("package") or {}).get("name")
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev and name:
                    fixed.setdefault(name, []).append(str(ev["fixed"]))
    return {"id": v.get("id", ""), "aliases": aliases, "cves": cves, "severity": sev,
            "cvss_est": LABEL_SCORE[sev], "fixed": {k: sorted(set(x)) for k, x in fixed.items()},
            "summary": str(v.get("summary", ""))[:200]}


def _load_osv_store(offline):
    path = (config.OFFLINE_DIR / "osv.json") if offline else _cache("osv_cache.json")
    store = config.read_json(path, {"pkgs": {}, "vulns": {}, "fetched_at": ""})
    canary = config.read_json(config.DATA_DIR / "canary_osv.json", {"pkgs": {}, "vulns": {}})
    store["pkgs"].update(canary["pkgs"])        # Sentinel fixture goes through the same path
    store["vulns"].update(canary["vulns"])
    return store, path


def osv_lookup(components, offline=False):
    """components: list of (name, version). Returns vulns per component id.
    Raises FeedError if the data source failed (the caller marks the run INCOMPLETE)."""
    store, path = _load_osv_store(offline)
    ids = [f"{n}@{v}" for n, v in components]
    todo = [c for c in components if f"{c[0]}@{c[1]}" not in store["pkgs"]]
    if todo and offline:
        for n, v in todo:                      # offline fixtures are complete: unknown = none
            store["pkgs"][f"{n}@{v}"] = []
    elif todo:
        for i in range(0, len(todo), 500):
            chunk = todo[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v}
                                for n, v in chunk]}
            res = _post(OSV_BATCH, body).get("results", [])
            if len(res) != len(chunk):
                raise FeedError("OSV returned an unexpected number of results")
            for (n, v), r in zip(chunk, res):
                store["pkgs"][f"{n}@{v}"] = sorted({x["id"] for x in r.get("vulns", [])})
        need = sorted({i for c in todo for i in store["pkgs"][f"{c[0]}@{c[1]}"]} - set(store["vulns"]))
        with ThreadPoolExecutor(max_workers=10) as ex:
            for vid, rec in zip(need, ex.map(lambda x: _get(OSV_VULN + x), need)):
                store["vulns"][vid] = normalize_vuln(rec)
        store["fetched_at"] = _now()
        config.write_json(path, store)
    out = {cid: [store["vulns"][i] for i in store["pkgs"].get(cid, []) if i in store["vulns"]]
           for cid in ids}
    return {"vulns": out, "snapshot": store.get("fetched_at") or "offline fixture"}


def _fresh(doc):
    try:
        t = calendar.timegm(time.strptime(doc["fetched_at"], "%Y-%m-%dT%H:%M:%SZ"))
        return time.time() - t < TTL
    except (KeyError, ValueError):
        return False


def kev_set(offline=False):
    """Returns (set of CVE ids, snapshot time). Raises FeedError on failure."""
    if offline:
        doc = config.read_json(config.OFFLINE_DIR / "kev.json", {"cves": [], "fetched_at": ""})
        return set(doc["cves"]), doc.get("fetched_at") or "offline fixture"
    path = _cache("kev.json")
    doc = config.read_json(path, None)
    if not doc or not _fresh(doc):
        data = _get(KEV_URL)
        doc = {"cves": sorted(v["cveID"] for v in data.get("vulnerabilities", [])),
               "fetched_at": _now()}
        config.write_json(path, doc)
    return set(doc["cves"]), doc["fetched_at"]


def epss_scores(cves, offline=False):
    """Returns ({cve: score}, snapshot). Raises FeedError on failure."""
    cves = sorted(set(cves))
    if offline:
        doc = config.read_json(config.OFFLINE_DIR / "epss.json", {"scores": {}, "fetched_at": ""})
        return {c: doc["scores"][c] for c in cves if c in doc["scores"]}, \
            doc.get("fetched_at") or "offline fixture"
    path = _cache("epss.json")
    doc = config.read_json(path, {"scores": {}, "fetched_at": ""})
    need = [c for c in cves if c not in doc["scores"]]
    for i in range(0, len(need), 50):
        chunk = need[i:i + 50]
        data = _get(EPSS_URL, {"cve": ",".join(chunk)})
        got = {d["cve"]: float(d["epss"]) for d in data.get("data", [])}
        for c in chunk:
            doc["scores"][c] = got.get(c, 0.0)
    if need:
        doc["fetched_at"] = _now()
        config.write_json(path, doc)
    return {c: doc["scores"][c] for c in cves if c in doc["scores"]}, doc["fetched_at"]


def registry_text(items, offline=False):
    """items: list of (name, version). Returns {cid: {"scripts": {...}, "description": str}}.
    This is untrusted text; only the quarantined Reader may read it."""
    if offline:
        doc = config.read_json(config.OFFLINE_DIR / "registry.json", {})
        return {f"{n}@{v}": doc[f"{n}@{v}"] for n, v in items if f"{n}@{v}" in doc}
    out = {}
    for n, v in items:
        try:
            d = _get(REGISTRY + n.replace("/", "%2F") + "/" + v)
        except FeedError:
            continue                           # optional: skip quietly
        out[f"{n}@{v}"] = {"scripts": d.get("scripts") or {},
                           "description": str(d.get("description", ""))}
    return out

