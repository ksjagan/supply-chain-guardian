"""
Hunter agent (Day 1 Checkpoint).
Performs OSV vulnerability lookup, anomaly detection, typosquatting checks,
Dockerfile and workflow static analysis, Sentinel canary verification,
and baseline change detection.
"""
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests

from guardian.changes import ChangeDetector, DiffResult
from guardian.config import DATA_DIR, CANARY_PACKAGE, CANARY_VERSION, OSV_QUERYBATCH_URL, OSV_VULN_URL, CACHE_DIR, FIXTURES_DIR
from guardian.ledger import Ledger
from guardian.models import Component, Evidence
from guardian.rules import RulesEngine


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _is_typosquat(cand: str, target: str) -> Tuple[bool, int]:
    d = _levenshtein(cand, target)
    if d in (1, 2) and len(target) >= 4 and len(cand) >= 4:
        return True, d

    # Split on - or _ to handle affix tricks (e.g. lodas-core)
    parts = re.split(r"[-_]", cand)
    for p in parts:
        if len(p) >= 4:
            d_part = _levenshtein(p, target)
            if d_part in (1, 2):
                return True, d_part

    return False, 999


class Hunter:
    """
    Vulnerability, anomaly, typosquatting, and diff scanner.
    """

    def __init__(self, ledger: Ledger, out_dir: Path, demo_mode: bool = False):
        self.ledger = ledger
        self.out_dir = out_dir
        self.demo_mode = demo_mode
        self.diff_result: Optional[DiffResult] = None
        self.top_packages: Set[str] = self._load_top_packages()
        self.vuln_data_unavailable = False
        self.osv_cache: Dict[str, list] = self._load_osv_cache()

    def _load_top_packages(self) -> Set[str]:
        pkg_file = DATA_DIR / "top_npm_packages.txt"
        if pkg_file.exists():
            return {line.strip().lower() for line in pkg_file.read_text(encoding="utf-8").splitlines() if line.strip()}
        return set()

    def _load_osv_cache(self) -> Dict[str, list]:
        """Load offline OSV cache from cache/ or fixtures/osv_offline/."""
        cache = {}
        for p in [
            FIXTURES_DIR / "osv_offline" / "osv_cache.json",
            CACHE_DIR / "osv_cache.json",
        ]:
            if p.exists():
                try:
                    with open(p, encoding="utf-8") as fh:
                        cache.update(json.load(fh))
                except Exception:
                    pass
        return cache

    def _save_osv_cache(self) -> None:
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with open(CACHE_DIR / "osv_cache.json", "w", encoding="utf-8") as fh:
                json.dump(self.osv_cache, fh, indent=2)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public Runner
    # ------------------------------------------------------------------

    def run(
        self,
        repo_dir: Path,
        components: List[Component],
        since_ref: str = "",
        baseline_dir: Optional[Path] = None,
    ) -> None:
        """
        Execute Hunter detection pipeline:
          1. OSV Vulnerability Lookup (with offline fallback & network failure detection)
          2. Typosquatting checks
          3. Install script checks
          4. Dockerfile static checks
          5. Workflow static checks
          6. Sentinel canary verification
          7. Baseline diffing (if since_ref or baseline_dir provided)
          8. Rules engine evaluation
        """
        print("[hunter] Running vulnerability & static security checks …")
        self._lookup_osv_vulnerabilities(components)
        self._check_typosquatting(components)
        self._check_install_scripts(components)
        self._check_dockerfiles(repo_dir)
        self._check_workflows(repo_dir)
        self._run_sentinel()

        if since_ref or baseline_dir:
            self._run_diff(repo_dir, components, since_ref, baseline_dir)

        # Run deterministic rules engine to create Findings
        rules = RulesEngine(self.ledger)
        findings = rules.evaluate()
        print(f"[hunter] Produced {len(findings)} findings from evidence")

    # ------------------------------------------------------------------
    # OSV Vulnerability Lookup
    # ------------------------------------------------------------------

    def _lookup_osv_vulnerabilities(self, components: List[Component]) -> None:
        """
        Queries OSV batch API with caching and network resilience.
        If network fails and cache is empty: marks run INCOMPLETE and logs unavailable.
        """
        if not components:
            return

        needed_queries = []
        for c in components:
            key = f"{c.name}@{c.version}"
            if key in self.osv_cache:
                self._record_osv_findings(c, self.osv_cache[key])
            else:
                needed_queries.append(c)

        if not needed_queries:
            return

        # If in demo mode or offline mode requested, do not attempt network
        if self.demo_mode:
            for c in needed_queries:
                self.osv_cache[f"{c.name}@{c.version}"] = []
            return

        # Query OSV Batch API in chunks (OSV limits queries to max 1,000 per request)
        chunk_size = 400
        try:
            print(f"[hunter] Querying OSV for {len(needed_queries)} packages in chunks of {chunk_size} …")
            for i in range(0, len(needed_queries), chunk_size):
                chunk = needed_queries[i : i + chunk_size]
                batch_payload = {
                    "queries": [
                        {"package": {"name": c.name, "ecosystem": "npm"}, "version": c.version}
                        for c in chunk
                    ]
                }
                resp = requests.post(OSV_QUERYBATCH_URL, json=batch_payload, timeout=15)
                if resp.status_code != 200:
                    raise requests.RequestException(f"OSV batch query returned HTTP {resp.status_code}")

                results = resp.json().get("results", [])
                for c, res in zip(chunk, results):
                    vulns_raw = res.get("vulns", [])
                    full_vulns = []
                    for v in vulns_raw:
                        vid = v.get("id")
                        if vid:
                            try:
                                v_resp = requests.get(OSV_VULN_URL.format(id=vid), timeout=5)
                                if v_resp.status_code == 200:
                                    full_vulns.append(v_resp.json())
                                else:
                                    full_vulns.append(v)
                            except Exception:
                                full_vulns.append(v)

                    key = f"{c.name}@{c.version}"
                    self.osv_cache[key] = full_vulns
                    self._record_osv_findings(c, full_vulns)

            self._save_osv_cache()

        except Exception as exc:
            # Network blocked or OSV failure
            print(f"[hunter] OSV network lookup failed ({exc}).")
            # If any needed queries were not in cache, we cannot be confident about vulnerability status
            self.vuln_data_unavailable = True
            self.ledger.run_status = "INCOMPLETE"
            self.ledger.add_evidence(
                kind="osv_record",
                source="hunter.osv",
                component="",
                data={
                    "status": "unavailable",
                    "reason": "vulnerability data unavailable: network connection failed and offline cache unavailable",
                    "error": str(exc),
                },
            )

    def _record_osv_findings(self, comp: Component, vulns: list) -> None:
        for v in vulns:
            # Extract CVE aliases
            aliases = v.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE-")), aliases[0] if aliases else v.get("id", ""))

            # Extract severity
            db_spec = v.get("database_specific", {})
            sev = db_spec.get("severity", "")
            cvss_val = str(db_spec.get("cvss_score", ""))
            if not sev:
                sev = "HIGH" if "HIGH" in str(v) else "MEDIUM"

            # Extract fix versions
            fixed_versions = []
            for aff in v.get("affected", []):
                for r in aff.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            fixed_versions.append(ev["fixed"])

            fix_ver = fixed_versions[0] if fixed_versions else ""

            self.ledger.add_evidence(
                kind="osv_record",
                source="hunter.osv",
                component=comp.name,
                data={
                    "id": v.get("id"),
                    "cve": cve,
                    "package": comp.name,
                    "version": comp.version,
                    "summary": v.get("summary", ""),
                    "details": v.get("details", ""),
                    "severity": sev,
                    "cvss": cvss_val,
                    "fixed_versions": fixed_versions,
                    "fix_version": fix_ver,
                    "direct_parent": comp.direct_parent,
                },
            )

    # ------------------------------------------------------------------
    # Typosquatting Checks
    # ------------------------------------------------------------------

    def _check_typosquatting(self, components: List[Component]) -> None:
        for c in components:
            name_lower = c.name.lower().split("/")[-1]
            for top in self.top_packages:
                if name_lower == top:
                    continue

                is_ts, dist = _is_typosquat(name_lower, top)
                if is_ts:
                    self.ledger.add_evidence(
                        kind="anomaly",
                        source="hunter",
                        component=c.name,
                        data={
                            "type": "typosquat",
                            "package": c.name,
                            "target_package": top,
                            "distance": dist,
                            "details": f"Package name '{c.name}' is typosquat of popular package '{top}' (dist {dist})",
                        },
                    )
                    break

    # ------------------------------------------------------------------
    # Install Scripts Check
    # ------------------------------------------------------------------

    def _check_install_scripts(self, components: List[Component]) -> None:
        for c in components:
            if c.has_install_script:
                self.ledger.add_evidence(
                    kind="anomaly",
                    source="hunter",
                    component=c.name,
                    data={
                        "type": "unsafe_install_script",
                        "package": c.name,
                        "details": f"Package '{c.name}' has install script enabled (hasInstallScript=true)",
                    },
                )

    # ------------------------------------------------------------------
    # Dockerfile Checks
    # ------------------------------------------------------------------

    def _check_dockerfiles(self, repo_dir: Path) -> None:
        for df in repo_dir.rglob("Dockerfile*"):
            if ".git" in df.parts:
                continue
            text = df.read_text(encoding="utf-8", errors="replace")

            # curl | sh
            if re.search(r"(curl|wget)\s+.*\|\s*(ba)?sh", text):
                self.ledger.add_evidence(
                    kind="dockerfile_issue",
                    source="hunter",
                    component="Dockerfile",
                    data={
                        "type": "curl_pipe_sh",
                        "details": f"Piped shell execution (curl|sh) in {df.name}",
                        "risk": "high",
                    },
                )

            # Untagged or :latest
            has_user = False
            for line in text.splitlines():
                line_s = line.strip()
                if line_s.startswith("FROM "):
                    img = line_s.split()[1] if len(line_s.split()) > 1 else ""
                    if ":latest" in img or ":" not in img:
                        self.ledger.add_evidence(
                            kind="dockerfile_issue",
                            source="hunter",
                            component="Dockerfile",
                            data={
                                "type": "untrusted_image",
                                "details": f"Base image '{img}' is unpinned or untagged in {df.name}",
                                "risk": "medium",
                            },
                        )
                if line_s.startswith("USER "):
                    has_user = True

            if not has_user and text.strip():
                self.ledger.add_evidence(
                    kind="dockerfile_issue",
                    source="hunter",
                    component="Dockerfile",
                    data={
                        "type": "root_user",
                        "details": f"Container runs as root (no USER directive) in {df.name}",
                        "risk": "high",
                    },
                )

    # ------------------------------------------------------------------
    # Workflow Checks
    # ------------------------------------------------------------------

    def _check_workflows(self, repo_dir: Path) -> None:
        wf_dir = repo_dir / ".github" / "workflows"
        if not wf_dir.exists():
            return

        for wf in wf_dir.glob("*.y*ml"):
            text = wf.read_text(encoding="utf-8", errors="replace")
            if "pull_request_target" in text:
                self.ledger.add_evidence(
                    kind="workflow_issue",
                    source="hunter",
                    component=wf.name,
                    data={
                        "type": "risky_workflow_trigger",
                        "details": f"Workflow {wf.name} uses dangerous 'pull_request_target' trigger",
                        "risk": "high",
                    },
                )
            if "write-all" in text:
                self.ledger.add_evidence(
                    kind="workflow_issue",
                    source="hunter",
                    component=wf.name,
                    data={
                        "type": "workflow_permission_widening",
                        "details": f"Workflow {wf.name} has widened 'write-all' permissions",
                        "risk": "high",
                    },
                )
            # Unpinned actions
            for m in re.finditer(r"uses:\s*([\w\-]+/[\w\-]+)@([\w\.\-]+)", text):
                action, ref = m.group(1), m.group(2)
                if len(ref) != 40:
                    self.ledger.add_evidence(
                        kind="workflow_issue",
                        source="hunter",
                        component=wf.name,
                        data={
                            "type": "unpinned_workflow_action",
                            "action": f"{action}@{ref}",
                            "details": f"Unpinned action '{action}@{ref}' in {wf.name} (not commit SHA)",
                            "risk": "medium",
                        },
                    )

    # ------------------------------------------------------------------
    # Sentinel Canary Self-Test
    # ------------------------------------------------------------------

    def _run_sentinel(self) -> None:
        canary_osv_path = DATA_DIR / "canary_osv.json"
        if not canary_osv_path.exists():
            return

        try:
            with open(canary_osv_path, encoding="utf-8") as fh:
                canary_vuln = json.load(fh)

            matched_typosquat, _ = _is_typosquat("lodas-core", "lodash")
            if not matched_typosquat:
                print("[hunter] Sentinel WARNING: typosquat detection failed on test fixture!")
                self.ledger.run_status = "UNTRUSTED"
                return

            self.ledger.add_evidence(
                kind="canary_result",
                source="hunter.sentinel",
                component=CANARY_PACKAGE,
                data={"status": "passed", "canary_id": canary_vuln.get("id")},
            )
        except Exception as exc:
            print(f"[hunter] Sentinel error: {exc}")
            self.ledger.run_status = "UNTRUSTED"

    # ------------------------------------------------------------------
    # Baseline Diff
    # ------------------------------------------------------------------

    def _run_diff(
        self,
        repo_dir: Path,
        components: List[Component],
        since_ref: str,
        baseline_dir: Optional[Path],
    ) -> None:
        print(f"[hunter] Computing baseline changes (since: '{since_ref or baseline_dir}') …")
        detector = ChangeDetector(self.ledger)

        if baseline_dir is not None:
            diff_res = detector.compare(
                current_repo_dir=repo_dir,
                current_components=components,
                baseline_dir=baseline_dir,
                baseline_desc=str(baseline_dir),
                current_desc=str(repo_dir),
            )
        elif since_ref == "last":
            repo_key = repo_dir.name
            out_base = self.out_dir.parent
            b_comps, b_data, err = detector.load_saved_baseline(repo_key, out_base)
            if err:
                diff_res = detector.compare(
                    current_repo_dir=repo_dir,
                    current_components=components,
                    unavailable_reason=err,
                    baseline_desc="saved:last",
                )
            else:
                diff_res = detector.compare(
                    current_repo_dir=repo_dir,
                    current_components=components,
                    baseline_components=b_comps,
                    baseline_desc="saved:last",
                    current_desc=str(repo_dir),
                )
        else:
            tmp_baseline, ref_desc, err = detector.extract_git_baseline(repo_dir, since_ref)
            if err:
                diff_res = detector.compare(
                    current_repo_dir=repo_dir,
                    current_components=components,
                    unavailable_reason=err,
                    baseline_desc=f"git:{since_ref}",
                )
            else:
                diff_res = detector.compare(
                    current_repo_dir=repo_dir,
                    current_components=components,
                    baseline_dir=tmp_baseline,
                    baseline_desc=f"git:{ref_desc}",
                    current_desc="HEAD",
                )
                if tmp_baseline:
                    import shutil
                    shutil.rmtree(tmp_baseline, ignore_errors=True)

        self.diff_result = diff_res
        print(f"[hunter] Diff complete: +{diff_res.count_added} added, -{diff_res.count_removed} removed, "
              f"{diff_res.count_upgraded} upgraded, {diff_res.count_modified} modified")
