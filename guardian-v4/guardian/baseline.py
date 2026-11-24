"""Baselines: where the 'old' side of a comparison comes from. Never checks anything out
and never runs repo code. A missing baseline is reported honestly, never faked."""
import re
import subprocess
import time
from pathlib import Path

from guardian import config, scout

GROUPS = ("npm_lock", "manifest", "dockerfile", "workflow")


class BaselineError(Exception):
    pass


def empty_texts():
    return {g: {} for g in GROUPS}


def repo_key(source):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(source).rstrip("/\\"))[-80:] or "repo"


def read_tree(repo_dir):
    """Read all scannable files of a folder into {group: {relative_path: text}}."""
    found = scout.find_files(repo_dir)
    texts = empty_texts()
    for group, key in (("npm_lock", "lockfiles"), ("manifest", "manifests"),
                       ("dockerfile", "dockerfiles"), ("workflow", "workflows")):
        for rel in found[key]:
            texts[group][rel] = (Path(repo_dir) / rel).read_text(encoding="utf-8", errors="ignore")
    return texts


def _git(repo_dir, *args):
    try:
        r = subprocess.run(["git", "-C", str(repo_dir), *args], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise BaselineError(f"git not usable: {e}")
    if r.returncode != 0:
        raise BaselineError(r.stderr.decode("utf-8", "ignore").strip()[:160] or "git error")
    return r.stdout.decode("utf-8", "ignore")


def read_git(repo_dir, ref):
    """Read files as they were at <ref> using `git show` (no checkout)."""
    if not re.match(r"^[A-Za-z0-9_./~^@{}-]{1,100}$", ref) or ref.startswith("-"):
        raise BaselineError(f"invalid ref name '{ref[:40]}'")
    if not (Path(repo_dir) / ".git").exists():
        raise BaselineError("not a git repository (no history to compare)")
    try:
        meta = _git(repo_dir, "log", "-1", "--format=%h|%cI", ref).strip().split("|")
        names = _git(repo_dir, "ls-tree", "-r", "--name-only", ref).splitlines()
    except BaselineError as e:
        raise BaselineError(f"ref '{ref}' not found or unreadable ({e})")
    texts = empty_texts()
    for p in names:
        kind = scout.classify(p)
        if "node_modules/" in p or kind not in ("npm_lock", "manifest", "dockerfile", "workflow"):
            continue
        texts[kind][p] = _git(repo_dir, "show", f"{ref}:{p}")
    return texts, {"kind": "git", "label": ref, "hash": meta[0], "date": meta[1]}


def baseline_file(source):
    return config.OUT_DIR / repo_key(source) / "baseline.json"


def read_last(source):
    doc = config.read_json(baseline_file(source))
    if not doc:
        raise BaselineError("no saved scan for this repository yet (scan once first)")
    return doc["texts"], {"kind": "last", "label": "last scan", "hash": doc.get("hash", ""),
                          "date": doc.get("saved_at", "")}


def save_last(source, texts, commit=""):
    config.write_json(baseline_file(source), {
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "hash": commit,
        "texts": texts})


def head_hash(repo_dir):
    try:
        return _git(repo_dir, "rev-parse", "--short", "HEAD").strip()
    except BaselineError:
        return ""


def read_dir(old_dir):
    if not Path(old_dir).is_dir():
        raise BaselineError(f"folder not found: {old_dir}")
    return read_tree(old_dir), {"kind": "dir", "label": str(old_dir), "hash": "", "date": ""}
