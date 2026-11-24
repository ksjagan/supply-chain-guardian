"""changes.py: compare old and new. Both sides go through the SAME Mapper and Hunter code."""
import json
import re

from guardian import feeds, hunter, mapper
from guardian.ecosystems import dockerfile, workflow
from guardian.models import cmp_ver, major


def _host(url):
    m = re.match(r"^[a-z+]+://([^/]+)", url or "")
    return m.group(1) if m else ""


def _by_name(model):
    d = {}
    for c in model["components"].values():
        d.setdefault(c["name"], []).append(c)
    return {k: sorted(v, key=lambda c: c["version"]) for k, v in d.items()}


def _item(items, evs, name, ctype, old, new, **extra):
    data = {"name": name, "change_type": ctype, "old": old, "new": new, **extra}
    items.append({"package": name, "change_type": ctype, "old": old, "new": new,
                  "flags": extra, "evidence_id": ""})
    evs.append(dict(data, _kind="lockfile_diff", _item=len(items) - 1))


def diff_components(old, new):
    """Compare two models. Packages with several versions are compared as sets."""
    items, evs = [], []
    ob, nb = _by_name(old), _by_name(new)
    for name in sorted(set(ob) | set(nb)):
        ov, nv = ob.get(name, []), nb.get(name, [])
        o_map, n_map = {c["version"]: c for c in ov}, {c["version"]: c for c in nv}
        removed = [c for c in ov if c["version"] not in n_map]
        added = [c for c in nv if c["version"] not in o_map]
        for v in sorted(set(o_map) & set(n_map)):          # same version: did it silently change?
            o, n = o_map[v], n_map[v]
            if (o["integrity"], o["resolved"]) != (n["integrity"], n["resolved"]):
                kind = "source_changed" if (_host(o["resolved"]) != _host(n["resolved"])
                                            or hunter.unusual_source(n)) else "modified"
                _item(items, evs, name, kind, v, v,
                      old_integrity=o["integrity"][:30], new_integrity=n["integrity"][:30],
                      old_resolved=o["resolved"][:100], new_resolved=n["resolved"][:100])
            if n["install_script"] and not o["install_script"]:
                _item(items, evs, name, "install_script_gained", v, v, install_script=True)
        pairs = min(len(removed), len(added))
        for o, n in zip(removed[:pairs], added[:pairs]):    # pair up as upgrade/downgrade
            ctype = "upgraded" if cmp_ver(n["version"], o["version"]) > 0 else "downgraded"
            jump = major(n["version"]) != major(o["version"])
            _item(items, evs, name, ctype, o["version"], n["version"], major_jump=jump)
            if n["install_script"] and not o["install_script"]:
                _item(items, evs, name, "install_script_gained", o["version"], n["version"],
                      install_script=True)
            if hunter.unusual_source(n) and not hunter.unusual_source(o):
                _item(items, evs, name, "source_changed", o["version"], n["version"],
                      new_resolved=n["resolved"][:100])
        for n in added[pairs:]:
            _item(items, evs, name, "added", "", n["version"], install_script=n["install_script"],
                  direct=n["direct"], dev=n["dev"])
        for o in removed[pairs:]:
            _item(items, evs, name, "removed", o["version"], "", dev=o["dev"])
    return items, evs


def dependency_drift(texts):
    """package.json vs the lockfile's root entry, per folder. Returns a sorted list of notes."""
    drift = set()
    for mpath, mtext in texts["manifest"].items():
        folder = mpath.rsplit("/", 1)[0] if "/" in mpath else ""
        lock = (folder + "/" if folder else "") + "package-lock.json"
        if lock not in texts["npm_lock"]:
            continue
        try:
            man = json.loads(mtext)
            rootp = json.loads(texts["npm_lock"][lock]).get("packages", {}).get("", {})
        except ValueError:
            continue
        for field in ("dependencies", "devDependencies"):
            want, have = man.get(field) or {}, rootp.get(field) or {}
            for n in sorted(set(want) | set(have)):
                if want.get(n) != have.get(n):
                    drift.add(f"{mpath}: {n} is '{want.get(n)}' in package.json but "
                              f"'{have.get(n)}' in lockfile")
    return sorted(drift)


def _issue_keys(texts, group, mod):
    keys = {}
    for path, text in texts[group].items():
        for i in mod.scan(text)["issues"]:
            keys[(path, i["rule"], i["text"])] = i
    return keys


def diff_files(old, new):
    """Dockerfile and workflow changes: files added/removed, issues added/removed."""
    items, evs = [], []
    for group, mod, kind in (("dockerfile", dockerfile, "dockerfile_diff"),
                             ("workflow", workflow, "workflow_diff")):
        for path in sorted(set(old[group]) | set(new[group])):
            if path not in old[group] or path not in new[group]:
                ctype = "file_added" if path in new[group] else "file_removed"
                items.append({"package": path, "change_type": ctype, "old": "", "new": "",
                              "flags": {}, "evidence_id": ""})
                evs.append({"file": path, "change_type": ctype, "old": "", "new": "",
                            "_kind": kind, "_item": len(items) - 1})
        oi, ni = _issue_keys(old, group, mod), _issue_keys(new, group, mod)
        for key in sorted(set(ni) - set(oi)):
            items.append({"package": key[0], "change_type": "issue_added", "old": "",
                          "new": key[1], "flags": {"rule": key[1], "line": ni[key]["line"]},
                          "evidence_id": ""})
            evs.append({"file": key[0], "change_type": "issue_added", "rule": key[1], "old": "",
                        "new": key[2][:150], "line": ni[key]["line"], "_kind": kind,
                        "_item": len(items) - 1})
        for key in sorted(set(oi) - set(ni)):
            items.append({"package": key[0], "change_type": "issue_removed", "old": key[1],
                          "new": "", "flags": {"rule": key[1]}, "evidence_id": ""})
            evs.append({"file": key[0], "change_type": "issue_removed", "rule": key[1],
                        "old": key[2][:150], "new": "", "_kind": kind, "_item": len(items) - 1})
    return items, evs


def _vuln_keys(model, offline):
    """Set of (component_id, vuln_id) for a model. Raises FeedError if lookup fails."""
    comps = [(c["name"], c["version"]) for c in model["components"].values()]
    res = feeds.osv_lookup(comps, offline)
    return {(cid, v["id"]): v for cid, vs in res["vulns"].items() for v in vs}


def compare(old_texts, new_texts, meta, offline=False, new_model=None):
    """Full comparison. Returns a dict that the graph stores as parts/changes.json.
    meta describes the baseline (kind, label, hash, date)."""
    old_model = mapper.build_model(old_texts["npm_lock"])
    new_model = new_model or mapper.build_model(new_texts["npm_lock"])
    items, evs = diff_components(old_model, new_model)
    fitems, fevs = diff_files(old_texts, new_texts)
    base = len(items)
    items += fitems
    evs += [dict(e, _item=e["_item"] + base) for e in fevs]
    for note in dependency_drift(new_texts):
        items.append({"package": note.split(":")[0], "change_type": "manifest_lockfile_drift",
                      "old": "", "new": "", "flags": {"note": note[:200]}, "evidence_id": ""})
        evs.append({"file": note.split(":")[0], "change_type": "manifest_lockfile_drift",
                    "old": "", "new": "", "note": note[:200], "_kind": "lockfile_diff",
                    "_item": len(items) - 1})
    out = {"status": "ok", "error": "", "baseline": meta, "items": items, "evidence": evs,
           "new_risks": [], "resolved_risks": [], "unchanged_risks": [],
           "old_components": len(old_model["components"]),
           "new_components": len(new_model["components"]), "old_errors": old_model["errors"]}
    try:
        ov, nv = _vuln_keys(old_model, offline), _vuln_keys(new_model, offline)
    except feeds.FeedError as e:
        out["status"] = "incomplete"
        out["error"] = "comparison INCOMPLETE: vulnerability lookup failed (" + str(e)[:100] + ")"
        return out
    pick = lambda keys, src: [{"component": c, "vuln_id": v, "severity": src[(c, v)]["severity"],
                               "cvss_est": src[(c, v)]["cvss_est"]} for c, v in sorted(keys)]
    out["new_risks"] = pick(set(nv) - set(ov), nv)
    out["resolved_risks"] = pick(set(ov) - set(nv), ov)
    out["unchanged_risks"] = pick(set(ov) & set(nv), nv)
    return out

