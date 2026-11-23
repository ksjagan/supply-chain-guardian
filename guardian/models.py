"""
Data models for the Evidence Ledger.
Everything the system knows lives as one of these records.
"""
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Evidence:
    """One atomic fact collected by a code agent."""
    id: str            # E-001, E-002, ...
    kind: str          # repo_snapshot | file_found | coverage | component | edge | ...
    source: str        # which agent wrote this (scout, mapper, hunter ...)
    component: str     # package name or '' if not component-specific
    data: dict         # the actual fact payload
    collected_at: str = field(default_factory=_now)
    sha256: str = ""   # filled in after creation

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = _sha256(self.data)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Component:
    """One software package discovered in the repo."""
    name: str
    version: str
    ecosystem: str          # npm, PyPI, Maven, Go, ...
    purl: str               # pkg:npm/qs@6.5.2
    bom_ref: str            # unique reference inside the SBOM
    is_direct: bool         # true if the root project depends on it directly
    is_dev: bool            # true if dev-only
    is_optional: bool
    has_install_script: bool
    resolved_url: str       # the URL the lockfile says to download from
    integrity: str          # hash string from lockfile (or '')
    manifest_path: str      # which file declared it
    evidence_id: str        # E-xxx that recorded this component
    direct_parent: str = "" # direct dependency root ancestor
    origin: dict = field(default_factory=dict) # {ecosystem, registry_host, manifest_file, direct_parent}


@dataclass
class Edge:
    """A directed dependency edge: parent depends on child."""
    parent: str   # bom_ref
    child: str    # bom_ref
    evidence_id: str


@dataclass
class Finding:
    """One security or risk finding produced by rules.py."""
    id: str             # F-001, F-002, ...
    type: str           # vuln | typosquat | install_script | dockerfile | workflow | ...
    component: str      # name@version
    path: List[str]     # dependency chain root -> ... -> component
    evidence_ids: List[str]
    risk: str           # critical | high | medium | low
    confidence_basis: str   # plain-text explanation of how confidence was computed
    context: dict       # {kev, epss, dev_only, reachable_hint}
    explanation: str    # filled by Analyst or facts-only fallback
    skeptic: dict       # filled by Skeptic agent (or {})
    remediation: dict   # {option_id, validated} or {}
    status: str         # verified | unverified | needs-review
    cve: str = ""       # e.g. CVE-2024-xxxx
    cvss: str = ""      # e.g. 7.5
    fix_version: str = "" # e.g. 4.17.21
    direct_parent_to_upgrade: str = "" # direct parent to upgrade
    raw_data: dict = field(default_factory=dict)
