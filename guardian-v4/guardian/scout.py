"""Scout: check the input, clone safely (never run anything), list files worth scanning."""
import os
import re
import shutil
import subprocess
from pathlib import Path

from guardian import config

GITHUB_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?$")
SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "__pycache__"}
MAX_FILE_BYTES = 10 * 1024 * 1024
OTHER = {"requirements.txt": "PyPI", "Pipfile": "PyPI", "pyproject.toml": "PyPI",
         "poetry.lock": "PyPI", "pom.xml": "Maven", "build.gradle": "Maven/Gradle",
         "go.mod": "Go", "yarn.lock": "npm (yarn.lock)", "pnpm-lock.yaml": "npm (pnpm)"}


def classify(rel):
    """What kind of file is this path? Used by Scout and by the git-baseline reader."""
    p = rel.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    if base == "package-lock.json":
        return "npm_lock"
    if base == "package.json":
        return "manifest"
    if base == "Dockerfile" or base.startswith("Dockerfile.") or base.endswith(".Dockerfile"):
        return "dockerfile"
    if re.match(r"^(.*/)?\.github/workflows/[^/]+\.ya?ml$", p):
        return "workflow"
    if base in OTHER:
        return "other:" + OTHER[base]
    return None


def check_source(src):
    """Return ('github'|'local', value) or raise ValueError with a friendly message."""
    src = (src or "").strip()
    if src.startswith("https://"):
        if not GITHUB_RE.match(src):
            raise ValueError("Only public GitHub https URLs are accepted (https://github.com/owner/repo).")
        return "github", src
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", src) or src.startswith("git@"):
        raise ValueError("Only GitHub https URLs or local folders are allowed.")
    if not src or not Path(src).is_dir():
        raise ValueError("Local path not found or not a folder.")
    return "local", str(Path(src).resolve())


def _folder_mb(path):
    total = 0
    for dp, dn, fn in os.walk(path):
        for f in fn:
            try:
                total += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    return total / 1e6


def clone(url, dest):
    """Shallow clone with time and size limits. Hooks are not run by clone."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        subprocess.run(["git", "clone", "--depth", "50", "--no-tags", "--", url, str(dest)],
                       check=True, capture_output=True, timeout=config.CLONE_TIMEOUT_S, env=env)
    except subprocess.TimeoutExpired:
        raise ValueError("git clone took longer than 60 s and was stopped.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise ValueError("git clone failed (is the repo public and is git installed?). "
                         + str(getattr(e, "stderr", b"")[:150]))
    if _folder_mb(dest) > config.CLONE_MAX_MB:
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError("Repository is larger than 300 MB; refused.")


def find_files(repo_dir):
    """Walk the folder (skipping node_modules) and sort files into groups."""
    root = Path(repo_dir)
    found = {"lockfiles": [], "manifests": [], "dockerfiles": [], "workflows": [],
             "skipped": [], "other": []}
    for dp, dn, fn in os.walk(root):
        dn[:] = sorted(d for d in dn if d not in SKIP_DIRS)
        for f in sorted(fn):
            full = Path(dp) / f
            rel = full.relative_to(root).as_posix()
            kind = classify(rel)
            if not kind:
                continue
            if full.stat().st_size > MAX_FILE_BYTES:
                found["skipped"].append({"path": rel, "reason": "file larger than 10 MB"})
            elif kind == "npm_lock":
                found["lockfiles"].append(rel)
            elif kind == "manifest":
                found["manifests"].append(rel)
            elif kind == "dockerfile":
                found["dockerfiles"].append(rel)
            elif kind == "workflow":
                found["workflows"].append(rel)
            else:
                eco = kind.split(":", 1)[1]
                found["other"].append({"path": rel, "ecosystem": eco})
                found["skipped"].append({"path": rel, "reason": f"{eco} not supported yet"})
    if len(found["lockfiles"]) > config.MAX_MANIFESTS:
        for rel in found["lockfiles"][config.MAX_MANIFESTS:]:
            found["skipped"].append({"path": rel, "reason": "over the 50 manifest limit"})
        found["lockfiles"] = found["lockfiles"][:config.MAX_MANIFESTS]
    return found


def run_scout(source, work_dir):
    """Returns the scout record. On a bad input the record carries an 'error'."""
    rec = {"source": source, "kind": "", "repo_dir": "", "error": ""}
    for k in ("lockfiles", "manifests", "dockerfiles", "workflows", "skipped", "other"):
        rec[k] = []
    try:
        kind, value = check_source(source)
        rec["kind"] = kind
        if kind == "github":
            dest = Path(work_dir) / "repo"
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            clone(value, dest)
            value = str(dest)
        rec["repo_dir"] = value
        rec.update(find_files(value))
    except ValueError as e:
        rec["error"] = str(e)
    return rec
