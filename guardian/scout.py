"""
Scout agent – validates input (GitHub URL or local path), clones if needed,
and finds all manifest/lockfiles.

Writes evidence kinds:
  repo_snapshot  – one record with repo metadata
  file_found     – one record per manifest file discovered
  file_skipped   – one record per file skipped (size / count limits)
"""
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Tuple

from guardian.config import CLONE_TIMEOUT_S, CLONE_MAX_MB, MAX_MANIFEST_FILES
from guardian.ledger import Ledger

# File patterns we care about – order matters (more specific first)
MANIFEST_PATTERNS = [
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "requirements.txt",
    "pom.xml",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
]
DOCKERFILE_PATTERNS = ["Dockerfile", "Dockerfile.*", "*.dockerfile"]
WORKFLOW_GLOB = ".github/workflows/*.yml"

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(\.git)?(/.*)?$"
)


class ScoutError(Exception):
    pass


class Scout:
    """
    Validates an input (URL or path), clones when needed, and catalogues files.
    After run(), self.repo_dir is a Path to the local working copy.
    """

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.repo_dir: Path | None = None
        self._cloned_tmp: str | None = None  # temp dir to clean up later

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, target: str) -> Path:
        """
        target: a GitHub https URL or a local directory path.
        Returns the local path to use for all subsequent agents.
        Raises ScoutError on any validation failure.
        """
        if GITHUB_URL_RE.match(target):
            self.repo_dir = self._clone(target)
        elif Path(target).exists():
            self.repo_dir = Path(target).resolve()
        else:
            raise ScoutError(
                f"Input '{target}' is not a valid GitHub URL "
                f"(must start with https://github.com/...) "
                f"or an existing local path."
            )

        self._check_size()
        self._record_snapshot(target)
        self._find_manifests()
        return self.repo_dir

    # ------------------------------------------------------------------
    # Git clone
    # ------------------------------------------------------------------

    def _clone(self, url: str) -> Path:
        # Strip trailing slashes and optional .git suffix for display
        clean_url = url.rstrip("/")
        if clean_url.endswith(".git"):
            clean_url = clean_url[:-4]

        tmp = tempfile.mkdtemp(prefix="guardian_clone_")
        self._cloned_tmp = tmp

        cmd = ["git", "clone", "--depth", "1", "--", url, tmp]
        print(f"[scout] Cloning {clean_url} …")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=CLONE_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ScoutError(
                f"git clone timed out after {CLONE_TIMEOUT_S}s. "
                "Try a smaller repository or use --depth with a local mirror."
            )

        if result.returncode != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ScoutError(
                f"git clone failed:\n{result.stderr.strip()}"
            )

        print(f"[scout] Clone complete → {tmp}")
        return Path(tmp)

    # ------------------------------------------------------------------
    # Size guard
    # ------------------------------------------------------------------

    def _check_size(self) -> None:
        total_bytes = sum(
            f.stat().st_size
            for f in self.repo_dir.rglob("*")
            if f.is_file()
        )
        total_mb = total_bytes / (1024 * 1024)
        if total_mb > CLONE_MAX_MB:
            raise ScoutError(
                f"Repository is {total_mb:.1f} MB, which exceeds the "
                f"{CLONE_MAX_MB} MB safety limit."
            )
        print(f"[scout] Repo size: {total_mb:.1f} MB ✓")

    # ------------------------------------------------------------------
    # Evidence: repo snapshot
    # ------------------------------------------------------------------

    def _record_snapshot(self, original_target: str) -> None:
        # Try to get git commit info
        commit_sha = ""
        commit_msg = ""
        try:
            r = subprocess.run(
                ["git", "-C", str(self.repo_dir), "log", "-1", "--pretty=%H|%s"],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                parts = r.stdout.strip().split("|", 1)
                commit_sha = parts[0] if parts else ""
                commit_msg = parts[1] if len(parts) > 1 else ""
        except Exception:
            pass

        self.ledger.add_evidence(
            kind="repo_snapshot",
            source="scout",
            component="",
            data={
                "original_target": original_target,
                "local_path": str(self.repo_dir),
                "commit_sha": commit_sha,
                "commit_message": commit_msg,
            },
        )
        print(f"[scout] Snapshot recorded (commit {commit_sha[:8] or 'unknown'})")

    # ------------------------------------------------------------------
    # Evidence: file discovery
    # ------------------------------------------------------------------

    def _find_manifests(self) -> None:
        found = []
        skipped = []

        # Manifest / lockfiles
        for pattern in MANIFEST_PATTERNS:
            for p in sorted(self.repo_dir.rglob(pattern)):
                # Skip node_modules and similar vendor dirs
                if any(part in p.parts for part in ("node_modules", ".git", "vendor", "__pycache__")):
                    continue
                rel = str(p.relative_to(self.repo_dir))
                if len(found) < MAX_MANIFEST_FILES:
                    found.append(("manifest", rel, pattern))
                else:
                    skipped.append(rel)

        # Dockerfiles
        for p in sorted(self.repo_dir.rglob("Dockerfile*")):
            if any(part in p.parts for part in (".git",)):
                continue
            rel = str(p.relative_to(self.repo_dir))
            if len(found) < MAX_MANIFEST_FILES:
                found.append(("dockerfile", rel, "Dockerfile"))
            else:
                skipped.append(rel)

        # GitHub Actions workflows
        wf_dir = self.repo_dir / ".github" / "workflows"
        if wf_dir.exists():
            for p in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
                rel = str(p.relative_to(self.repo_dir))
                if len(found) < MAX_MANIFEST_FILES:
                    found.append(("workflow", rel, "*.yml"))
                else:
                    skipped.append(rel)

        # Record each found file as evidence
        for (ftype, rel, pattern) in found:
            self.ledger.add_evidence(
                kind="file_found",
                source="scout",
                component="",
                data={"type": ftype, "path": rel, "matched_pattern": pattern},
            )

        # Record skipped files
        for rel in skipped:
            self.ledger.add_evidence(
                kind="file_skipped",
                source="scout",
                component="",
                data={"path": rel, "reason": "manifest file count limit reached"},
            )

        print(
            f"[scout] Found {len(found)} manifest/config files"
            + (f", skipped {len(skipped)}" if skipped else "")
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Remove the temp clone directory (call when done)."""
        if self._cloned_tmp:
            shutil.rmtree(self._cloned_tmp, ignore_errors=True)

    def manifest_paths(self, kind: str = "manifest") -> list[Path]:
        """Return paths of all found files of a given type."""
        paths = []
        for ev in self.ledger.evidence:
            if ev.kind == "file_found" and ev.data.get("type") == kind:
                paths.append(self.repo_dir / ev.data["path"])
        return paths
