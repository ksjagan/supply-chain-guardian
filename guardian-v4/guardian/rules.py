"""rules.py: ledger + model -> findings with risk. Code only, no AI.
Reader flags are LLM claims; they can only nudge a risk UP, never down."""
from guardian.models import sev_shift

COMP_KINDS = {"vuln", "kev", "epss", "typosquat", "install_script", "unusual_source",
              "dependency_path", "reachability", "injection_text"}
BUMP_FLAGS = ("downloads_and_executes", "reads_env_or_credentials")


def risk_from_cvss(x):
    return "critical" if x >= 9 else "high" if x >= 7 else "medium" if x >= 4 else "low"


def ids(items):
    return [i["id"] for i in items]


class Builder:
    def __init__(self, led, model, changes, reader):
        self.led, self.model = led, model
        self.ch = changes or {}
        self.flags = (reader or {}).get("flags", {})        # {evidence_id: {flag: bool}}
        self.out = []
        self.idx = {}
        for it in led.items:
            d = it["data"]
            if it["kind"] in COMP_KINDS and "name" in d:
                self.idx.setdefault(f"{d['name']}@{d['version']}", {}).setdefault(
                    it["kind"], []).append(it)
        self.new_vulns = {(r["component"], r["vuln_id"]) for r in self.ch.get("new_risks", [])}
        self.new_pkgs = {i["package"] for i in self.ch.get("items", [])
                         if i["change_type"] in ("added", "install_script_gained")}
        self.diff_ev = {}
        for i in self.ch.get("items", []):
            if i["evidence_id"] and i["change_type"] in (
                    "added", "upgraded", "downgraded", "modified", "source_changed",
                    "install_script_gained"):
                self.diff_ev.setdefault(f"{i['package']}@{i['new'] or i['old']}", []).append(
                    i["evidence_id"])

    def reader_flags(self, cid):
        merged = {}
        for kind in ("install_script", "typosquat", "unusual_source", "vuln"):
            for it in self.idx.get(cid, {}).get(kind, []):
                for k, v in (self.flags.get(it["id"]) or {}).items():
                    merged[k] = merged.get(k, False) or bool(v)
        return merged

    def path(self, cid):
        return self.model["components"].get(cid, {}).get("path") or [cid]

    def base_ev(self, cid):
        return ids(self.idx.get(cid, {}).get("dependency_path", []))

    def cflags(self, cid, **extra):
        c = self.model["components"].get(cid, {})
        reach = self.idx.get(cid, {}).get("reachability")
        return dict({"direct": c.get("direct", False), "dev": c.get("dev", False),
                     "reach": reach[0]["data"]["result"] if reach else "unknown"}, **extra)

    def add(self, ftype, title, risk, ev, path, cid="", flags=None, notes=None, detail=""):
        c = self.model["components"].get(cid, {})
        self.out.append({"type": ftype, "title": title, "risk": risk, "base_risk": risk,
                         "component": cid, "name": c.get("name", ""),
                         "version": c.get("version", ""),
                         "evidence_ids": list(dict.fromkeys(ev)), "path": path or [cid or "?"],
                         "flags": flags or {}, "risk_notes": notes or [], "detail": detail,
                         "status": "open", "explanation": "", "ai_status": "not run",
                         "skeptic": None})
        return self.out[-1]

    def vulns(self):
        for cid, kinds in sorted(self.idx.items()):
            for v in kinds.get("vuln", []):
                self.one_vuln(cid, kinds, v)

    def one_vuln(self, cid, kinds, v):
        d = v["data"]
        risk = risk_from_cvss(d["cvss_est"])
        notes = [f"base {risk} from severity estimate {d['cvss_est']}"]
        kev = [k for k in kinds.get("kev", []) if k["data"]["cve"] in d["cves"]]
        eps = [e for e in kinds.get("epss", []) if e["data"]["cve"] in d["cves"]]
        top = max([e["data"]["epss"] for e in eps] or [0])
        if kev:
            risk = "critical"
            notes.append("listed in CISA KEV -> critical")
        if top >= 0.5:
            risk = sev_shift(risk, 1)
            notes.append(f"EPSS {top} >= 0.5 -> one level up")
        rf = self.reader_flags(cid)
        if any(rf.get(k) for k in BUMP_FLAGS):
            risk = sev_shift(risk, 1)
            notes.append("Reader (AI) flagged risky install text -> one level up")
        if d["dev"]:
            risk = sev_shift(risk, -1)
            notes.append("dev-only dependency -> one level down")
        intro = (cid, d["vuln_id"]) in self.new_vulns
        ev = [v["id"]] + ids(kev) + ids(eps) + ids(kinds.get("reachability", [])) + self.base_ev(cid)
        title = f"{d['vuln_id']} in {cid}" + (" (introduced by this change)" if intro else "")
        detail = (f"CVEs: {', '.join(d['cves']) or 'none listed'}; "
                  f"fixed in: {', '.join(d['fixed']) or 'no fix listed'}")
        f = self.add("vulnerability", title, risk, ev, self.path(cid), cid,
                     self.cflags(cid, kev=bool(kev), epss=top, introduced=intro), notes, detail)
        f["vuln_id"] = d["vuln_id"]
        f["fixed"] = d["fixed"]
