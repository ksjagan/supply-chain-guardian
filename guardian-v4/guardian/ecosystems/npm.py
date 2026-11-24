"""npm plugin: read package-lock.json (v2/v3) into components and edges. No guessing."""
import json

ROOT_ID = "(app)"


def purl(name, version):
    """Package URL, e.g. pkg:npm/qs@6.5.2 ; the @ of a scope becomes %40."""
    return "pkg:npm/" + name.replace("@", "%40", 1) + "@" + version


def _fail(msg):
    return {"ok": False, "error": msg, "components": {}, "edges": [], "root_deps": {}}


def _resolve(pk, from_path, dep):
    """Find where `dep` lives: look nested under from_path first, then walk up."""
    base = from_path
    while True:
        cand = (base + "/" if base else "") + "node_modules/" + dep
        if cand in pk:
            return cand
        if not base:
            return None
        idx = base.rfind("node_modules/")
        base = base[:idx].rstrip("/") if idx > 0 else ""


def parse_lock(text):
    try:
        data = json.loads(text)
    except ValueError:
        return _fail("lockfile is not valid JSON")
    pk = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(pk, dict) or data.get("lockfileVersion") not in (2, 3) or "" not in pk:
        return _fail("unsupported lockfile (need package-lock.json v2 or v3)")

    comps, path_id = {}, {}
    for path, info in pk.items():
        if path == "" or "node_modules/" not in path or not isinstance(info, dict):
            continue
        if info.get("link"):
            continue
        name = path.rsplit("node_modules/", 1)[1]        # text after the last node_modules/
        version = str(info.get("version", ""))
        cid = f"{name}@{version}"
        path_id[path] = cid
        if cid in comps:
            c = comps[cid]
            c["dev"] = c["dev"] and bool(info.get("dev"))
            c["install_script"] = c["install_script"] or bool(info.get("hasInstallScript"))
            c["paths"].append(path)
            continue
        comps[cid] = {"id": cid, "name": name, "version": version,
                      "resolved": info.get("resolved", ""), "integrity": info.get("integrity", ""),
                      "install_script": bool(info.get("hasInstallScript")),
                      "dev": bool(info.get("dev")), "optional": bool(info.get("optional")),
                      "paths": [path]}

    edges = set()
    root = pk[""]
    for path, info in [("", root)] + [(p, pk[p]) for p in path_id]:
        src = ROOT_ID if path == "" else path_id[path]
        fields = ["dependencies", "optionalDependencies"]
        if path == "":
            fields.append("devDependencies")
        for field in fields:
            for dep in (info.get(field) or {}):
                target = _resolve(pk, path, dep)
                if target in path_id:
                    edges.add((src, path_id[target]))

    root_deps = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        root_deps.update(root.get(field) or {})
    for c in comps.values():
        c["paths"] = sorted(c["paths"])
    return {"ok": True, "error": "", "name": root.get("name", "app"), "components": comps,
            "edges": sorted(edges), "root_deps": root_deps}
