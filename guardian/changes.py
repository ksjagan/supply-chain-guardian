"""
Deterministic, no-AI change detector (Day 1 Checkpoint).
Compares current repository state against a baseline source:
  1. Git ref (via git show <ref>:<path> - never check out or execute code)
  2. Directory diff (guardian diff <old_dir> <new_dir> or --baseline <dir>)
  3. Saved baseline (out/<repo-key>/baseline.json via --since last)

Never executes code from the scanned repository.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from guardian.ecosystems.npm import NpmPlugin
from guardian.ledger import Ledger
from guardian.models import Component, Edge, Evidence


@dataclass
class VersionRecord:
    name: str
    version: str
    integrity: str
    resolved: str
    has_install_script: bool
    is_dev: bool
    is_direct: bool
    manifest_path: str = ""
    direct_parent: str = ""


@dataclass
class ChangeItem:
    change_type: str        # added | removed | upgraded | downgraded | modified | install_script_gained | source_changed
    name: str
    old_version: Optional[str]
    new_version: Optional[str]
    old_val: Any = None
    new_val: Any = None
    is_major_jump: bool = False
    is_direct: bool = False
    flags: List[str] = field(default_factory=list)
    risk_hint: str = "medium"
    direct_parent: str = ""
    details: str = ""


@dataclass
class DiffResult:
    baseline_source: str            # git:HEAD~1 | folder:/path | saved:baseline.json | unavailable
    baseline_available: bool
    baseline_ref: str = ""          # short sha/date or path
    current_ref: str = ""           # short sha/date or path
    unavailable_reason: str = ""
    changes: List[ChangeItem] = field(default_factory=list)
    manifest_lockfile_drift: List[dict] = field(default_factory=list)
    dockerfile_diff: List[dict] = field(default_factory=list)
    workflow_diff: List[dict] = field(default_factory=list)
    newly_introduced_risks: List[dict] = field(default_factory=list)
    resolved_risks: List[dict] = field(default_factory=list)
    unchanged_risks: List[dict] = field(default_factory=list)

    # Summary strip counts
    count_added: int = 0
    count_removed: int = 0
    count_upgraded: int = 0
    count_downgraded: int = 0
    count_modified: int = 0
    count_new_install_scripts: int = 0
    count_new_risks: int = 0


# ── Semver helper ─────────────────────────────────────────────────────────────

def _parse_semver(v: str) -> Tuple[int, int, int]:
    """Extract (major, minor, patch) integers from a semver string."""
    clean = re.sub(r"^[^0-9]*", "", str(v).strip()).split("-")[0].split("+")[0]
    parts = clean.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 and parts[0] else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1] else 0
        patch = int(parts[2]) if len(parts) > 2 and parts[2] else 0
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def _compare_versions(v1: str, v2: str) -> int:
    """Returns > 0 if v1 > v2, < 0 if v1 < v2, 0 if equal."""
    s1 = _parse_semver(v1)
    s2 = _parse_semver(v2)
    if s1 > s2:
        return 1
    elif s1 < s2:
        return -1
    return 0


def _is_major_jump(old_v: str, new_v: str) -> bool:
    old_maj, old_min, _ = _parse_semver(old_v)
    new_maj, new_min, _ = _parse_semver(new_v)
    if new_maj > old_maj:
        return True
    if old_maj == 0 and new_maj == 0 and new_min > old_min:
        return True  # 0.1 -> 0.2 in 0.x is treated as breaking/major
    return False


def _is_unusual_source(resolved: str) -> bool:
    if not resolved:
        return False
    lower = resolved.lower()
    if lower.startswith("git+") or lower.startswith("http://") or lower.startswith("git://"):
        return True
    # Non-standard registry
    standard_hosts = ["registry.npmjs.org", "registry.yarnpkg.com"]
    return not any(h in lower for h in standard_hosts)


# ── Core Change Detector ──────────────────────────────────────────────────────

class ChangeDetector:
    """
    Compares baseline vs current components and configurations.
    All parsing uses the SAME NpmPlugin Mapper logic.
    """

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.npm_plugin = NpmPlugin()

    # ------------------------------------------------------------------
    # Baseline Extraction
    # ------------------------------------------------------------------

    def extract_git_baseline(self, repo_dir: Path, ref: str) -> Tuple[Optional[Path], str, str]:
        """
        Extract manifest/docker/workflow files at git ref into a temp directory using git show.
        Never checks out branches or modifies the working directory.
        Returns: (temp_dir_path, baseline_ref_desc, error_reason)
        """
        # Verify git repo
        if not (repo_dir / ".git").exists():
            return None, "", f"Directory '{repo_dir}' is not a git repository"

        # Check if ref exists
        check_cmd = ["git", "-C", str(repo_dir), "rev-parse", "--verify", f"{ref}^{{commit}}"]
        r = subprocess.run(check_cmd, capture_output=True, text=True)
        if r.returncode != 0:
            return None, "", f"Git ref '{ref}' not found in repository history"

        commit_sha = r.stdout.strip()
        # Get commit date and message for header
        desc_cmd = ["git", "-C", str(repo_dir), "log", "-1", "--pretty=%h (%ci)", commit_sha]
        r_desc = subprocess.run(desc_cmd, capture_output=True, text=True)
        ref_desc = r_desc.stdout.strip() if r_desc.returncode == 0 else commit_sha[:8]

        tmp_dir = Path(tempfile.mkdtemp(prefix="guardian_baseline_"))

        candidates = [
            "package-lock.json",
            "package.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Dockerfile",
        ]

        extracted_any = False
        for rel_path in candidates:
            cmd = ["git", "-C", str(repo_dir), "show", f"{commit_sha}:{rel_path}"]
            res = subprocess.run(cmd, capture_output=True)
            if res.returncode == 0:
                dest = tmp_dir / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(res.stdout)
                extracted_any = True

        # Also search for workflows at that commit
        ls_tree_cmd = ["git", "-C", str(repo_dir), "ls-tree", "-r", "--name-only", commit_sha, ".github/workflows"]
        res_tree = subprocess.run(ls_tree_cmd, capture_output=True, text=True)
        if res_tree.returncode == 0:
            for wf_file in res_tree.stdout.splitlines():
                wf_file = wf_file.strip()
                if wf_file.endswith(".yml") or wf_file.endswith(".yaml"):
                    cmd = ["git", "-C", str(repo_dir), "show", f"{commit_sha}:{wf_file}"]
                    res_wf = subprocess.run(cmd, capture_output=True)
                    if res_wf.returncode == 0:
                        dest = tmp_dir / wf_file
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(res_wf.stdout)
                        extracted_any = True

        if not extracted_any:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            return None, ref_desc, f"No manifest or config files found at ref '{ref}'"

        return tmp_dir, ref_desc, ""

    def load_saved_baseline(self, repo_key: str, out_base_dir: Path) -> Tuple[Optional[List[Component]], Optional[dict], str]:
        """
        Loads baseline.json from out/<repo-key>/baseline.json.
        """
        baseline_file = out_base_dir / repo_key / "baseline.json"
        if not baseline_file.exists():
            candidate_dirs = sorted([d for d in out_base_dir.iterdir() if d.is_dir() and (d / "baseline.json").exists()],
                                    key=lambda x: x.stat().st_mtime, reverse=True)
            if candidate_dirs:
                baseline_file = candidate_dirs[0] / "baseline.json"
            else:
                return None, None, f"No saved baseline.json found for '{repo_key}'"

        try:
            with open(baseline_file, encoding="utf-8") as fh:
                data = json.load(fh)
            components = []
            for c in data.get("components", []):
                components.append(Component(
                    name=c["name"],
                    version=c["version"],
                    ecosystem=c.get("ecosystem", "npm"),
                    purl=c.get("purl", f"pkg:npm/{c['name']}@{c['version']}"),
                    bom_ref=c.get("bom_ref", f"npm:{c['name']}@{c['version']}"),
                    is_direct=c.get("is_direct", False),
                    is_dev=c.get("is_dev", False),
                    is_optional=c.get("is_optional", False),
                    has_install_script=c.get("has_install_script", False),
                    resolved_url=c.get("resolved_url", ""),
                    integrity=c.get("integrity", ""),
                    manifest_path=c.get("manifest_path", "package-lock.json"),
                    evidence_id=c.get("evidence_id", ""),
                    direct_parent=c.get("direct_parent", ""),
                    origin=c.get("origin", {}),
                ))
            return components, data, ""
        except Exception as exc:
            return None, None, f"Failed reading saved baseline: {exc}"

    # ------------------------------------------------------------------
    # Comparison Engine
    # ------------------------------------------------------------------

    def compare(
        self,
        current_repo_dir: Path,
        current_components: List[Component],
        baseline_dir: Optional[Path] = None,
        baseline_components: Optional[List[Component]] = None,
        baseline_desc: str = "baseline",
        current_desc: str = "current",
        unavailable_reason: str = "",
    ) -> DiffResult:
        """
        Compares baseline and current state.
        Produces a DiffResult with full classification and evidence.
        """
        result = DiffResult(
            baseline_source=baseline_desc,
            baseline_available=not bool(unavailable_reason),
            baseline_ref=baseline_desc,
            current_ref=current_desc,
            unavailable_reason=unavailable_reason,
        )

        if unavailable_reason:
            self.ledger.add_evidence(
                kind="lockfile_diff",
                source="hunter.changes",
                component="",
                data={"status": "unavailable", "reason": unavailable_reason},
            )
            return result

        if baseline_components is None and baseline_dir is not None:
            b_comps, _, _ = self.npm_plugin.parse(baseline_dir)
            baseline_components = b_comps
        elif baseline_components is None:
            baseline_components = []

        baseline_map: Dict[str, Dict[str, VersionRecord]] = {}
        for c in baseline_components:
            rec = VersionRecord(
                name=c.name,
                version=c.version,
                integrity=c.integrity,
                resolved=c.resolved_url,
                has_install_script=c.has_install_script,
                is_dev=c.is_dev,
                is_direct=c.is_direct,
                manifest_path=c.manifest_path,
                direct_parent=c.direct_parent,
            )
            baseline_map.setdefault(c.name, {})[c.version] = rec

        current_map: Dict[str, Dict[str, VersionRecord]] = {}
        for c in current_components:
            rec = VersionRecord(
                name=c.name,
                version=c.version,
                integrity=c.integrity,
                resolved=c.resolved_url,
                has_install_script=c.has_install_script,
                is_dev=c.is_dev,
                is_direct=c.is_direct,
                manifest_path=c.manifest_path,
                direct_parent=c.direct_parent,
            )
            current_map.setdefault(c.name, {})[c.version] = rec

        all_names = set(baseline_map.keys()).union(set(current_map.keys()))

        for name in sorted(all_names):
            b_versions = baseline_map.get(name, {})
            c_versions = current_map.get(name, {})

            # Case 1: Added package
            if not b_versions:
                for v, c_rec in c_versions.items():
                    flags = []
                    if c_rec.has_install_script:
                        flags.append("install-script")
                    if _is_unusual_source(c_rec.resolved):
                        flags.append("unusual-source")
                    if c_rec.is_direct:
                        flags.append("direct")

                    item = ChangeItem(
                        change_type="added",
                        name=name,
                        old_version=None,
                        new_version=v,
                        new_val={"integrity": c_rec.integrity, "resolved": c_rec.resolved},
                        is_direct=c_rec.is_direct,
                        direct_parent=c_rec.direct_parent,
                        flags=flags,
                        risk_hint="high" if ("install-script" in flags or "unusual-source" in flags) else "medium",
                        details=f"Package {name}@{v} added to dependencies",
                    )
                    result.changes.append(item)
                    result.count_added += 1
                    if c_rec.has_install_script:
                        result.count_new_install_scripts += 1
                continue

            # Case 2: Removed package
            if not c_versions:
                for v, b_rec in b_versions.items():
                    item = ChangeItem(
                        change_type="removed",
                        name=name,
                        old_version=v,
                        new_version=None,
                        old_val={"integrity": b_rec.integrity, "resolved": b_rec.resolved},
                        is_direct=b_rec.is_direct,
                        direct_parent=b_rec.direct_parent,
                        risk_hint="low",
                        details=f"Package {name}@{v} removed",
                    )
                    result.changes.append(item)
                    result.count_removed += 1
                continue

            # Case 3: Present in both - compare version sets
            b_set = set(b_versions.keys())
            c_set = set(c_versions.keys())

            common_versions = b_set.intersection(c_set)
            for v in common_versions:
                b_rec = b_versions[v]
                c_rec = c_versions[v]

                integrity_changed = bool(b_rec.integrity and c_rec.integrity and b_rec.integrity != c_rec.integrity)
                resolved_changed = bool(b_rec.resolved and c_rec.resolved and b_rec.resolved != c_rec.resolved)
                script_gained = (not b_rec.has_install_script) and c_rec.has_install_script

                flags = []
                if integrity_changed:
                    flags.append("modified-integrity")
                if resolved_changed:
                    flags.append("source-changed")
                if script_gained:
                    flags.append("install-script-gained")
                    result.count_new_install_scripts += 1

                if integrity_changed or resolved_changed or script_gained:
                    ch_type = "modified"
                    if script_gained:
                        ch_type = "install_script_gained"
                    elif resolved_changed and _is_unusual_source(c_rec.resolved):
                        ch_type = "source_changed"

                    item = ChangeItem(
                        change_type=ch_type,
                        name=name,
                        old_version=v,
                        new_version=v,
                        old_val={"integrity": b_rec.integrity, "resolved": b_rec.resolved},
                        new_val={"integrity": c_rec.integrity, "resolved": c_rec.resolved},
                        is_direct=c_rec.is_direct,
                        direct_parent=c_rec.direct_parent,
                        flags=flags,
                        risk_hint="high",
                        details=f"Package {name}@{v} contents or source modified without version bump",
                    )
                    result.changes.append(item)
                    result.count_modified += 1

            added_versions = c_set - b_set
            removed_versions = b_set - c_set

            if added_versions and removed_versions:
                sorted_old = sorted(list(removed_versions), key=_parse_semver)
                sorted_new = sorted(list(added_versions), key=_parse_semver)

                for old_v, new_v in zip(sorted_old, sorted_new):
                    cmp_res = _compare_versions(new_v, old_v)
                    is_major = _is_major_jump(old_v, new_v)
                    c_rec = c_versions[new_v]
                    b_rec = b_versions[old_v]

                    flags = []
                    if is_major:
                        flags.append("major-jump")
                    if (not b_rec.has_install_script) and c_rec.has_install_script:
                        flags.append("install-script-gained")
                        result.count_new_install_scripts += 1
                    if _is_unusual_source(c_rec.resolved):
                        flags.append("unusual-source")

                    if cmp_res > 0:
                        ch_type = "upgraded"
                        result.count_upgraded += 1
                        risk_hint = "high" if (is_major or "install-script-gained" in flags) else "medium"
                    else:
                        ch_type = "downgraded"
                        result.count_downgraded += 1
                        risk_hint = "high"

                    item = ChangeItem(
                        change_type=ch_type,
                        name=name,
                        old_version=old_v,
                        new_version=new_v,
                        old_val={"integrity": b_rec.integrity, "resolved": b_rec.resolved},
                        new_val={"integrity": c_rec.integrity, "resolved": c_rec.resolved},
                        is_major_jump=is_major,
                        is_direct=c_rec.is_direct,
                        direct_parent=c_rec.direct_parent,
                        flags=flags,
                        risk_hint=risk_hint,
                        details=f"Package {name} {ch_type} from {old_v} to {new_v}" + (" (major breaking bump)" if is_major else ""),
                    )
                    result.changes.append(item)

        # Drift Check
        result.manifest_lockfile_drift = self._check_manifest_drift(current_repo_dir, current_components)

        # Dockerfile & Workflow Diff
        if baseline_dir is not None:
            result.dockerfile_diff = self._diff_dockerfiles(baseline_dir, current_repo_dir)
            result.workflow_diff = self._diff_workflows(baseline_dir, current_repo_dir)

        self._record_evidence(result)
        return result

    def _check_manifest_drift(self, repo_dir: Path, components: List[Component]) -> List[dict]:
        drift = []
        pkg_json_path = repo_dir / "package.json"
        if not pkg_json_path.exists():
            return drift

        try:
            with open(pkg_json_path, encoding="utf-8") as fh:
                pj = json.load(fh)
        except Exception:
            return drift

        declared = set(list(pj.get("dependencies", {}).keys()) + list(pj.get("devDependencies", {}).keys()))
        locked_direct = {c.name for c in components if c.is_direct}
        locked_all = {c.name for c in components}

        missing_in_lock = declared - locked_all
        for name in sorted(missing_in_lock):
            drift.append({
                "type": "manifest_without_lock",
                "package": name,
                "details": f"Package '{name}' is in package.json but missing from package-lock.json",
            })

        unlisted_direct = locked_direct - declared
        for name in sorted(unlisted_direct):
            drift.append({
                "type": "lock_without_manifest",
                "package": name,
                "details": f"Package '{name}' is top-level direct in lockfile but not declared in package.json",
            })

        return drift

    def _diff_dockerfiles(self, b_dir: Path, c_dir: Path) -> List[dict]:
        diffs = []
        b_docker = b_dir / "Dockerfile"
        c_docker = c_dir / "Dockerfile"

        if not c_docker.exists():
            return diffs

        c_text = c_docker.read_text(encoding="utf-8", errors="replace")
        b_text = b_docker.read_text(encoding="utf-8", errors="replace") if b_docker.exists() else ""

        for line in c_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("FROM "):
                image = line_s.split()[1] if len(line_s.split()) > 1 else ""
                if (":latest" in image or ":" not in image) and image not in b_text:
                    diffs.append({
                        "type": "untrusted_image",
                        "image": image,
                        "details": f"Dockerfile uses unpinned or untagged base image '{image}'",
                        "risk": "medium",
                    })

        for line in c_text.splitlines():
            if re.search(r"(curl|wget)\s+.*\|\s*(ba)?sh", line):
                if line not in b_text:
                    diffs.append({
                        "type": "curl_pipe_sh",
                        "line": line.strip(),
                        "details": "Piped shell execution added to Dockerfile (curl|sh / wget|sh)",
                        "risk": "high",
                    })

        if "USER " in b_text and "USER " not in c_text:
            diffs.append({
                "type": "root_user",
                "details": "USER directive removed in Dockerfile; container now runs as root",
                "risk": "high",
            })

        return diffs

    def _diff_workflows(self, b_dir: Path, c_dir: Path) -> List[dict]:
        diffs = []
        c_wf_dir = c_dir / ".github" / "workflows"
        b_wf_dir = b_dir / ".github" / "workflows"

        if not c_wf_dir.exists():
            return diffs

        for wf in c_wf_dir.glob("*.y*ml"):
            c_content = wf.read_text(encoding="utf-8", errors="replace")
            b_wf = b_wf_dir / wf.name if b_wf_dir.exists() else None
            b_content = b_wf.read_text(encoding="utf-8", errors="replace") if (b_wf and b_wf.exists()) else ""

            if "pull_request_target" in c_content and "pull_request_target" not in b_content:
                diffs.append({
                    "file": wf.name,
                    "type": "risky_workflow_trigger",
                    "details": f"Risky trigger 'pull_request_target' added in {wf.name}",
                    "risk": "high",
                })

            if "write-all" in c_content and "write-all" not in b_content:
                diffs.append({
                    "file": wf.name,
                    "type": "workflow_permission_widening",
                    "details": f"Widened permissions 'write-all' added in {wf.name}",
                    "risk": "high",
                })

            for m in re.finditer(r"uses:\s*([\w\-]+/[\w\-]+)@([\w\.\-]+)", c_content):
                action, ref = m.group(1), m.group(2)
                if len(ref) != 40 and m.group(0) not in b_content:
                    diffs.append({
                        "file": wf.name,
                        "type": "unpinned_workflow_action",
                        "action": f"{action}@{ref}",
                        "details": f"Unpinned action '{action}@{ref}' added (not pinned to commit SHA)",
                        "risk": "medium",
                    })

        return diffs

    def _record_evidence(self, diff: DiffResult) -> None:
        for item in diff.changes:
            self.ledger.add_evidence(
                kind="lockfile_diff",
                source="hunter.changes",
                component=item.name,
                data={
                    "change_type": item.change_type,
                    "package": item.name,
                    "old_version": item.old_version,
                    "new_version": item.new_version,
                    "flags": item.flags,
                    "is_major_jump": item.is_major_jump,
                    "is_direct": item.is_direct,
                    "direct_parent": item.direct_parent,
                    "risk_hint": item.risk_hint,
                    "details": item.details,
                    "old_val": item.old_val,
                    "new_val": item.new_val,
                },
            )

        for drift in diff.manifest_lockfile_drift:
            self.ledger.add_evidence(
                kind="lockfile_diff",
                source="hunter.changes",
                component=drift.get("package", ""),
                data=drift,
            )

        for d in diff.dockerfile_diff:
            self.ledger.add_evidence(
                kind="dockerfile_diff",
                source="hunter.changes",
                component="Dockerfile",
                data=d,
            )

        for w in diff.workflow_diff:
            self.ledger.add_evidence(
                kind="workflow_diff",
                source="hunter.changes",
                component=w.get("file", ""),
                data=w,
            )
