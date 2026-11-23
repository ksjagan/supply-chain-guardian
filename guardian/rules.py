"""
Risk Rules Engine (rules.py).
Deterministic, code-only classification of findings from Evidence Ledger.
Generates named finding types:
  - vulnerability (with CVE, severity, fix_version, direct_parent_to_upgrade)
  - unexpected_dependency
  - suspicious_update
  - modified_lockfile
  - untrusted_image
  - typosquat
  - unsafe_install_script
  - curl_pipe_sh
  - root_user
  - unpinned_workflow_action
  - risky_workflow_trigger
  - workflow_permission_widening
"""
from typing import Dict, List, Optional, Set
from guardian.ledger import Ledger
from guardian.models import Finding


class RulesEngine:
    """
    Evaluates evidence in the ledger and generates Finding objects.
    Enforces the Day 1 risk hierarchy: critical | high | medium | low
    """

    def __init__(self, ledger: Ledger):
        self.ledger = ledger

    def evaluate(self) -> List[Finding]:
        # Pre-index dependency paths and origins by component name
        path_map: Dict[str, List[str]] = {}
        direct_parent_map: Dict[str, str] = {}

        for ev in self.ledger.evidence:
            if ev.kind == "dependency_path":
                comp_name = ev.data.get("component", "")
                readable = ev.data.get("path_readable", [])
                origin_direct = ev.data.get("origin_direct_dep", "")
                if comp_name and readable:
                    path_map[comp_name] = readable
                if comp_name and origin_direct:
                    direct_parent_map[comp_name] = origin_direct

        comp_meta: Dict[str, dict] = {}
        for ev in self.ledger.evidence:
            if ev.kind == "component":
                name = ev.data.get("name", "")
                comp_meta[name] = ev.data

        # ── 1. OSV Vulnerability Records ──────────────────────────────
        for ev in self.ledger.evidence:
            if ev.kind == "osv_record":
                data = ev.data
                if data.get("status") == "unavailable":
                    continue

                pkg = data.get("package", "")
                ver = data.get("version", "")
                path = path_map.get(pkg, [f"[root]", f"{pkg}@{ver}"])
                direct_parent = direct_parent_map.get(pkg, path[1] if len(path) > 1 else "[root]")

                sev_raw = str(data.get("severity", "HIGH")).upper()
                cvss_str = str(data.get("cvss", ""))
                try:
                    cvss_num = float(cvss_str) if cvss_str else (9.5 if "CRITICAL" in sev_raw else 7.5)
                except ValueError:
                    cvss_num = 7.5

                if cvss_num >= 9.0 or "CRITICAL" in sev_raw:
                    risk = "critical"
                elif cvss_num >= 7.0 or "HIGH" in sev_raw:
                    risk = "high"
                elif cvss_num >= 4.0 or "MEDIUM" in sev_raw:
                    risk = "medium"
                else:
                    risk = "low"

                cve = data.get("cve", data.get("id", ""))
                fix_ver = data.get("fix_version", "")
                summary = data.get("summary", "")

                self.ledger.add_finding(
                    type="vulnerability",
                    component=f"{pkg}@{ver}",
                    path=path,
                    evidence_ids=[ev.id],
                    risk=risk,
                    confidence_basis="1 source (OSV vulnerability database)",
                    context={
                        "cve": cve,
                        "cvss": str(cvss_num),
                        "fixed_versions": data.get("fixed_versions", []),
                        "direct_parent": direct_parent,
                    },
                    explanation=f"Known vulnerability {cve} in {pkg}@{ver}: {summary}",
                    skeptic={},
                    remediation={"fix_version": fix_ver, "direct_parent_to_upgrade": direct_parent},
                    status="verified",
                    cve=cve,
                    cvss=str(cvss_num),
                    fix_version=fix_ver,
                    direct_parent_to_upgrade=direct_parent,
                    raw_data=data,
                )

        # ── 2. Diff Evidence (lockfile_diff, dockerfile_diff, workflow_diff) ──
        for ev in self.ledger.evidence:
            if ev.kind == "lockfile_diff":
                data = ev.data
                pkg = data.get("package", "")
                ch_type = data.get("change_type", "")
                flags = data.get("flags", [])
                is_major = data.get("is_major_jump", False)
                path = path_map.get(pkg, [f"[root]", f"{pkg}@{data.get('new_version', '')}"])
                direct_parent = direct_parent_map.get(pkg, path[1] if len(path) > 1 else "[root]")

                if ch_type == "added":
                    is_risky = ("install-script" in flags) or ("unusual-source" in flags)
                    risk = "high" if is_risky else "medium"
                    conf_sources = 2 if is_risky else 1
                    conf_basis = f"{conf_sources} sources (lockfile diff + package metadata)" if is_risky else "1 source (lockfile diff)"

                    self.ledger.add_finding(
                        type="unexpected_dependency",
                        component=f"{pkg}@{data.get('new_version', '')}",
                        path=path,
                        evidence_ids=[ev.id],
                        risk=risk,
                        confidence_basis=conf_basis,
                        context={"flags": flags, "direct_parent": direct_parent},
                        explanation=f"Dependency '{pkg}' was newly added to the project." +
                                    (" Contains install script/unusual source." if is_risky else ""),
                        skeptic={},
                        remediation={},
                        status="verified",
                        direct_parent_to_upgrade=direct_parent,
                        raw_data=data,
                    )

                elif ch_type == "modified":
                    self.ledger.add_finding(
                        type="modified_lockfile",
                        component=f"{pkg}@{data.get('new_version', '')}",
                        path=path,
                        evidence_ids=[ev.id],
                        risk="high",
                        confidence_basis="2 sources (integrity hash mismatch + resolved URL check)",
                        context={"flags": flags, "direct_parent": direct_parent},
                        explanation=f"Lockfile tampered: Package '{pkg}@{data.get('new_version')}' was modified without a version bump.",
                        skeptic={},
                        remediation={},
                        status="verified",
                        direct_parent_to_upgrade=direct_parent,
                        raw_data=data,
                    )

                elif ch_type in ("upgraded", "downgraded"):
                    if is_major or ch_type == "downgraded":
                        risk = "high" if ("install-script-gained" in flags) else "medium"
                        self.ledger.add_finding(
                            type="suspicious_update",
                            component=f"{pkg}@{data.get('new_version', '')}",
                            path=path,
                            evidence_ids=[ev.id],
                            risk=risk,
                            confidence_basis="1 source (semver diff)",
                            context={"flags": flags, "is_major": is_major, "direct_parent": direct_parent},
                            explanation=f"Package '{pkg}' had a {ch_type} from {data.get('old_version')} to {data.get('new_version')}.",
                            skeptic={},
                            remediation={},
                            status="verified",
                            direct_parent_to_upgrade=direct_parent,
                            raw_data=data,
                        )

            elif ev.kind == "dockerfile_diff":
                data = ev.data
                dtype = data.get("type", "dockerfile_issue")
                self.ledger.add_finding(
                    type=dtype,
                    component="Dockerfile",
                    path=["[root]", "Dockerfile"],
                    evidence_ids=[ev.id],
                    risk=data.get("risk", "medium"),
                    confidence_basis="1 source (Dockerfile diff)",
                    context={},
                    explanation=data.get("details", "Dockerfile risk detected"),
                    skeptic={},
                    remediation={},
                    status="verified",
                    raw_data=data,
                )

            elif ev.kind == "workflow_diff":
                data = ev.data
                wtype = data.get("type", "workflow_issue")
                self.ledger.add_finding(
                    type=wtype,
                    component=f".github/workflows/{data.get('file', 'workflow.yml')}",
                    path=["[root]", f".github/workflows/{data.get('file', '')}"],
                    evidence_ids=[ev.id],
                    risk=data.get("risk", "medium"),
                    confidence_basis="1 source (Workflow diff)",
                    context={},
                    explanation=data.get("details", "Workflow security risk detected"),
                    skeptic={},
                    remediation={},
                    status="verified",
                    raw_data=data,
                )

        # ── 3. Static Anomalies & Security Checks ──────────────────────
        for ev in self.ledger.evidence:
            if ev.kind == "anomaly":
                data = ev.data
                atype = data.get("type", "")
                pkg = data.get("package", "")
                ver = comp_meta.get(pkg, {}).get("version", "")
                path = path_map.get(pkg, [f"[root]", f"{pkg}@{ver}"])
                direct_parent = direct_parent_map.get(pkg, path[1] if len(path) > 1 else "[root]")

                if atype == "typosquat":
                    has_script = comp_meta.get(pkg, {}).get("has_install_script", False)
                    risk = "critical" if has_script else "high"
                    conf = 2 if has_script else 1
                    self.ledger.add_finding(
                        type="typosquat",
                        component=f"{pkg}@{ver}",
                        path=path,
                        evidence_ids=[ev.id],
                        risk=risk,
                        confidence_basis=f"{conf} sources (edit-distance match on top registry package" + (" + install script" if has_script else "") + ")",
                        context={"target_package": data.get("target_package"), "direct_parent": direct_parent},
                        explanation=f"Potential typosquat: '{pkg}' is close to popular package '{data.get('target_package')}'.",
                        skeptic={},
                        remediation={},
                        status="verified",
                        direct_parent_to_upgrade=direct_parent,
                        raw_data=data,
                    )
                elif atype in ("install_script", "unsafe_install_script"):
                    self.ledger.add_finding(
                        type="unsafe_install_script",
                        component=f"{pkg}@{ver}",
                        path=path,
                        evidence_ids=[ev.id],
                        risk="medium",
                        confidence_basis="1 source (package-lock.json hasInstallScript flag)",
                        context={"direct_parent": direct_parent},
                        explanation=f"Package '{pkg}' executes install scripts automatically during npm install.",
                        skeptic={},
                        remediation={},
                        status="verified",
                        direct_parent_to_upgrade=direct_parent,
                        raw_data=data,
                    )

            elif ev.kind == "dockerfile_issue":
                data = ev.data
                dtype = data.get("type", "dockerfile_issue")
                self.ledger.add_finding(
                    type=dtype,
                    component="Dockerfile",
                    path=["[root]", "Dockerfile"],
                    evidence_ids=[ev.id],
                    risk=data.get("risk", "medium"),
                    confidence_basis="1 source (Dockerfile static analysis)",
                    context={},
                    explanation=data.get("details", "Dockerfile risk detected"),
                    skeptic={},
                    remediation={},
                    status="verified",
                    raw_data=data,
                )

            elif ev.kind == "workflow_issue":
                data = ev.data
                wtype = data.get("type", "workflow_issue")
                self.ledger.add_finding(
                    type=wtype,
                    component=f".github/workflows/{ev.component or 'workflow.yml'}",
                    path=["[root]", f".github/workflows/{ev.component or 'workflow.yml'}"],
                    evidence_ids=[ev.id],
                    risk=data.get("risk", "medium"),
                    confidence_basis="1 source (Workflow static analysis)",
                    context={},
                    explanation=data.get("details", "Workflow risk detected"),
                    skeptic={},
                    remediation={},
                    status="verified",
                    raw_data=data,
                )

        return self.ledger.findings
