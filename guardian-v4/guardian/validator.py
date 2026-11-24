"""Validator: apply an APPROVED option to a temp COPY, rebuild the lockfile (no scripts),
rescan with the same code, compare before/after. The original repo is never modified."""
import difflib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from guardian import config, pipeline
from guardian.ledger import Ledger

IGNORE = shutil.ignore_patterns("node_modules", ".git", "__pycache__")


class NotApproved(Exception):
    pass


def approval_for(led, finding_id):
    """The newest approval_record for this finding, or None. Nothing runs without one."""
    recs = [e for e in led.by_kind("approval_record") if e["data"]["finding_id"] == finding_id]
    return recs[-1] if recs and recs[-1]["data"]["decision"] == "approved" else None


def record_decision(rd, finding_id, option_id, decision, who="human"):
    """Write the approval_record evidence (the human clicked Approve or Reject)."""
    led = Ledger(Path(rd) / "ledger.json")
    eid = led.add("approval_record", "human", {
        "finding_id": finding_id, "option_id": option_id, "decision": decision,
        "who": who, "timestamp": pipeline.stamp()})
    led.save()
    return eid


def apply_option(manifest_text, opt):
    """Return new package.json text for the option, or None if nothing should change."""
    data = json.loads(manifest_text)
    name, ver = opt["package"], opt["to_version"]
    if opt["kind"] == "upgrade":
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            if name in (data.get(field) or {}):
                data[field][name] = ver
                break
        else:
            return None
    elif opt["kind"] == "override":
        data.setdefault("overrides", {})[name] = ver
    elif opt["kind"] == "remove":
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            (data.get(field) or {}).pop(name, None)
    else:
        return None
    return json.dumps(data, indent=2) + "\n"


def _npm_lock(folder):
    """Run npm only in the temp copy. Returns an error string or ''."""
    npm = shutil.which("npm")
    if not npm:
        return "npm is not installed"
    try:
        r = subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts",
                            "--no-audit", "--no-fund"], cwd=folder, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired:
        return "npm took longer than 120 s"
    if r.returncode != 0:
        return "npm failed: " + r.stderr.decode("utf-8", "ignore").strip()[-200:]
    return ""


def _patch(rel, old, new):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        f"a/{rel}", f"b/{rel}"))


def _keys(findings):
    return {(f["type"], f["title"].split(" (introduced")[0]): f for f in findings}


def validate(rd, repo_dir, finding, option, before, offline=True, lock_fn=None):
    """before: dict from pipeline.analyze_tree on the original. Returns the result record.
    lock_fn(folder) -> error string; defaults to real npm (tests pass a stub)."""
    lock_fn = lock_fn or _npm_lock
    rd = Path(rd)
    led = Ledger(rd / "ledger.json")
    appr = approval_for(led, finding["id"])
    if not appr or appr["data"]["option_id"] != option["id"]:
        raise NotApproved(f"no approval record for {finding['id']} / {option['id']}")
    res = {"finding_id": finding["id"], "option_id": option["id"], "approval_evidence": appr["id"],
           "status": "unvalidated suggestion", "reason": "", "fixed": [], "still_open": [],
           "newly_introduced": [], "components_before": len(before["model"]["components"]),
           "components_after": None, "patch": ""}
    man_rel = option["manifest"]
    man_path = Path(repo_dir) / man_rel
    if option["kind"] == "escalate" or not man_path.exists():
        res["reason"] = "escalation: no automatic change was made" if option["kind"] == "escalate" \
            else f"{man_rel} not found"
        return res
    old_text = man_path.read_text(encoding="utf-8")
    new_text = apply_option(old_text, option)
    if new_text is None:
        res["reason"] = "the package is not a direct dependency in package.json"
        return res
    res["patch"] = _patch(man_rel, old_text, new_text)        # patch exists even if unvalidated
    with tempfile.TemporaryDirectory(prefix="guardian-copy-") as tmp:
        copy = Path(tmp) / "copy"
        shutil.copytree(repo_dir, copy, ignore=IGNORE)
        (copy / man_rel).write_text(new_text, encoding="utf-8")
        folder = (copy / man_rel).parent
        err = lock_fn(folder)
        if err:
            res["reason"] = err + " (suggestion not tested)"
            return res
        after = pipeline.analyze_tree(Path(tmp) / "after_run", copy, offline)
        lock_rel = (man_rel.rsplit("/", 1)[0] + "/" if "/" in man_rel else "") + "package-lock.json"
        lock_old = (Path(repo_dir) / lock_rel).read_text(encoding="utf-8") if \
            (Path(repo_dir) / lock_rel).exists() else ""
        res["patch"] += _patch(lock_rel, lock_old, (copy / lock_rel).read_text(encoding="utf-8"))
    bk, ak = _keys(before["findings"]), _keys(after["findings"])
    res["fixed"] = sorted(bk[k]["title"] for k in set(bk) - set(ak))
    res["still_open"] = sorted(ak[k]["title"] for k in set(ak) & set(bk))
    res["newly_introduced"] = sorted(ak[k]["title"] for k in set(ak) - set(bk))
    res["components_after"] = len(after["model"]["components"])
    res["target_fixed"] = (finding["type"], finding["title"].split(" (introduced")[0]) not in ak
    res["status"] = "validated"
    return res
