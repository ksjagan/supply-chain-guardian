"""
npm ecosystem plugin.
Parses package-lock.json v2/v3 into Components and Edges,
following the spec in the build prompt exactly.
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from guardian.models import Component, Edge


# purl encoding: scoped names like @scope/pkg become pkg:%40scope%2Fpkg
def _purl(name: str, version: str) -> str:
    encoded = name.replace("@", "%40").replace("/", "%2F")
    return f"pkg:npm/{encoded}@{version}"


def _bom_ref(name: str, version: str) -> str:
    safe = name.replace("@", "").replace("/", "-")
    return f"npm:{safe}@{version}"


def _strip_semver_prefix(v: str) -> str:
    """Remove leading ^ ~ = < > from a semver range to get a bare version."""
    return re.sub(r"^[^0-9]*", "", v).split(" ")[0]


class NpmPlugin:
    """
    Plugin interface: parse(repo_dir) -> (components, edges, coverage_note)
    
    Returns:
      components: list of Component objects
      edges: list of Edge objects (parent bom_ref -> child bom_ref)
      coverage_note: string like "full" | "partial – only direct deps" | "skipped"
    """

    LOCKFILE = "package-lock.json"
    PACKAGE_JSON = "package.json"

    def parse(
        self, repo_dir: Path
    ) -> Tuple[List[Component], List[Edge], str]:
        """Main entry point."""
        lock_path = repo_dir / self.LOCKFILE
        pkg_path  = repo_dir / self.PACKAGE_JSON

        if not lock_path.exists():
            if pkg_path.exists():
                return self._parse_package_json_only(pkg_path)
            return [], [], "skipped – no package-lock.json or package.json found"

        try:
            with open(lock_path, encoding="utf-8") as fh:
                lock = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            return [], [], f"error reading {self.LOCKFILE}: {exc}"

        lock_version = lock.get("lockfileVersion", 1)
        if lock_version not in (2, 3):
            # v1 format: different structure, we mark PARTIAL
            return self._parse_v1(lock, pkg_path)

        return self._parse_v2_v3(lock, pkg_path)

    # ------------------------------------------------------------------
    # v2 / v3 parser  (the main path)
    # ------------------------------------------------------------------

    def _parse_v2_v3(
        self, lock: dict, pkg_path: Optional[Path]
    ) -> Tuple[List[Component], List[Edge], str]:
        """
        lock['packages'] structure:
          ""              -> root app
          "node_modules/X"       -> top-level install of X
          "node_modules/X/node_modules/Y" -> Y nested under X
        """
        packages = lock.get("packages", {})
        if not packages:
            return [], [], "partial – packages section is empty"

        # -- Step 1: build a map  key -> entry for fast lookup
        # We normalise keys by stripping the leading "node_modules/" prefix levels
        # so we can find a package by its last path segment.

        # We also need to know which deps the root declares as direct.
        root_entry = packages.get("", {})
        direct_dep_names: set[str] = set(
            list(root_entry.get("dependencies", {}).keys())
            + list(root_entry.get("devDependencies", {}).keys())
            + list(root_entry.get("optionalDependencies", {}).keys())
            + list(root_entry.get("peerDependencies", {}).keys())
        )

        # -- Step 2: convert every non-root entry into a Component
        components: Dict[str, Component] = {}  # bom_ref -> Component
        key_to_bom_ref: Dict[str, str] = {}    # lockfile key -> bom_ref

        for key, entry in packages.items():
            if key == "":
                continue  # root app, skip

            name = self._name_from_key(key)
            version = entry.get("version", "0.0.0")
            bref = _bom_ref(name, version)

            # If two keys resolve to the same bom_ref (different nested paths,
            # same name@version) we keep only the first occurrence.
            if bref in components:
                key_to_bom_ref[key] = bref
                continue

            comp = Component(
                name=name,
                version=version,
                ecosystem="npm",
                purl=_purl(name, version),
                bom_ref=bref,
                is_direct=(name in direct_dep_names and not self._is_nested(key)),
                is_dev=entry.get("dev", False),
                is_optional=entry.get("optional", False),
                has_install_script=entry.get("hasInstallScript", False),
                resolved_url=entry.get("resolved", ""),
                integrity=entry.get("integrity", ""),
                manifest_path=str(lock.get("_lockfile_path", "package-lock.json")),
                evidence_id="",   # filled by Mapper
            )
            components[bref] = comp
            key_to_bom_ref[key] = bref

        # -- Step 3: build edges by resolving each package's dependencies
        edges: List[Edge] = []
        root_bref = "root"

        for key, entry in packages.items():
            if key == "":
                # Edges from root
                for dep_name in list(entry.get("dependencies", {}).keys()) + list(entry.get("devDependencies", {}).keys()):
                    child_bref = self._resolve_dep(dep_name, key, packages, key_to_bom_ref)
                    if child_bref:
                        edges.append(Edge(parent=root_bref, child=child_bref, evidence_id=""))
            else:
                for dep_name in list(entry.get("dependencies", {}).keys()):
                    parent_bref = key_to_bom_ref.get(key)
                    if not parent_bref:
                        continue
                    child_bref = self._resolve_dep(dep_name, key, packages, key_to_bom_ref)
                    if child_bref:
                        edges.append(Edge(parent=parent_bref, child=child_bref, evidence_id=""))

        # Deduplicate edges
        seen_edges = set()
        unique_edges = []
        for e in edges:
            k = (e.parent, e.child)
            if k not in seen_edges:
                seen_edges.add(k)
                unique_edges.append(e)

        return list(components.values()), unique_edges, "full"

    # ------------------------------------------------------------------
    # v1 parser  (older lockfile format – partial)
    # ------------------------------------------------------------------

    def _parse_v1(
        self, lock: dict, pkg_path: Optional[Path]
    ) -> Tuple[List[Component], List[Edge], str]:
        """v1 uses lock['dependencies'] (flat map). We get direct deps only."""
        deps = lock.get("dependencies", {})
        components = []
        for name, entry in deps.items():
            version = entry.get("version", "0.0.0")
            comp = Component(
                name=name,
                version=version,
                ecosystem="npm",
                purl=_purl(name, version),
                bom_ref=_bom_ref(name, version),
                is_direct=True,   # can't tell from v1
                is_dev=entry.get("dev", False),
                is_optional=entry.get("optional", False),
                has_install_script=entry.get("hasInstallScript", False),
                resolved_url=entry.get("resolved", ""),
                integrity=entry.get("integrity", ""),
                manifest_path="package-lock.json",
                evidence_id="",
            )
            components.append(comp)
        return components, [], "partial – lockfile v1 (transitive tree not available)"

    # ------------------------------------------------------------------
    # Fallback: package.json only (no lockfile)
    # ------------------------------------------------------------------

    def _parse_package_json_only(
        self, pkg_path: Path
    ) -> Tuple[List[Component], List[Edge], str]:
        """When only package.json exists – direct deps only, versions are ranges."""
        try:
            with open(pkg_path, encoding="utf-8") as fh:
                pkg = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            return [], [], f"error reading package.json: {exc}"

        components = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            is_dev = section == "devDependencies"
            is_opt = section == "optionalDependencies"
            for name, ver_range in pkg.get(section, {}).items():
                bare = _strip_semver_prefix(ver_range)
                comp = Component(
                    name=name,
                    version=bare or ver_range,
                    ecosystem="npm",
                    purl=_purl(name, bare or ver_range),
                    bom_ref=_bom_ref(name, bare or ver_range),
                    is_direct=True,
                    is_dev=is_dev,
                    is_optional=is_opt,
                    has_install_script=False,
                    resolved_url="",
                    integrity="",
                    manifest_path="package.json",
                    evidence_id="",
                )
                components.append(comp)
        return components, [], "partial – package.json only (no lockfile), versions are ranges"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _name_from_key(key: str) -> str:
        """
        'node_modules/lodash'              -> 'lodash'
        'node_modules/@scope/pkg'          -> '@scope/pkg'
        'node_modules/a/node_modules/b'    -> 'b'
        """
        parts = key.split("node_modules/")
        raw = parts[-1].strip("/")
        return raw

    @staticmethod
    def _is_nested(key: str) -> bool:
        """True if the package is nested (not at the top-level node_modules)."""
        # 'node_modules/X/node_modules/Y' has 'node_modules' appearing twice
        return key.count("node_modules/") > 1

    @staticmethod
    def _resolve_dep(
        dep_name: str,
        parent_key: str,
        packages: dict,
        key_to_bom_ref: dict,
    ) -> Optional[str]:
        """
        Find the bom_ref of dep_name as seen from parent_key,
        walking up the folder tree per npm resolution rules.
        """
        # Try nested first: parent_key/node_modules/dep_name
        candidate = parent_key.rstrip("/") + "/node_modules/" + dep_name
        if candidate in packages:
            return key_to_bom_ref.get(candidate)

        # Walk up
        parts = parent_key.split("node_modules/")
        for i in range(len(parts) - 1, 0, -1):
            prefix = "node_modules/".join(parts[:i]) + "node_modules/"
            candidate = prefix + dep_name
            if candidate in packages:
                return key_to_bom_ref.get(candidate)

        # Top-level
        top = "node_modules/" + dep_name
        if top in packages:
            return key_to_bom_ref.get(top)

        return None
