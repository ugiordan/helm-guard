"""Auto-fix engine for helm-guard findings."""

from __future__ import annotations

import os
import re
import tempfile

from ruamel.yaml import YAML


class FixResult:
    def __init__(self):
        self.fixed: list[dict] = []
        self.skipped: list[dict] = []

    def to_dict(self):
        return {"fixed": self.fixed, "skipped": self.skipped,
                "summary": {"fixed": len(self.fixed), "skipped": len(self.skipped)}}


class FixEngine:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._yaml = YAML()
        self._yaml.preserve_quotes = True

    @staticmethod
    def _safe_path(path: str) -> bool:
        """Reject symlinks to prevent write-through-symlink attacks."""
        return os.path.exists(path) and not os.path.islink(path)

    def fix_findings(self, findings: list[dict], chart_dir: str) -> FixResult:
        result = FixResult()
        chart_yaml_path = os.path.join(chart_dir, "Chart.yaml")
        values_yaml_path = os.path.join(chart_dir, "values.yaml")

        pin001_findings = [f for f in findings if f["rule_id"] == "HLM-PIN-001"]
        trust002_findings = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
        other_findings = [f for f in findings if f["rule_id"] not in ("HLM-PIN-001", "HLM-TRUST-002")]

        # Fix PIN-001: SemVer ranges -> exact versions
        if pin001_findings and self._safe_path(chart_yaml_path):
            fixed = self._fix_dependency_pinning(chart_yaml_path, chart_dir, pin001_findings)
            result.fixed.extend(fixed)

        # Fix TRUST-002: Clear secret defaults
        if trust002_findings and self._safe_path(values_yaml_path):
            fixed = self._fix_secret_defaults(values_yaml_path, trust002_findings)
            result.fixed.extend(fixed)

        # Skip everything else
        for f in other_findings:
            result.skipped.append({
                "rule_id": f["rule_id"],
                "reason": "manual_review_required",
            })

        return result

    def _fix_dependency_pinning(self, chart_yaml_path, chart_dir, findings):
        fixed = []
        with open(chart_yaml_path) as f:
            data = self._yaml.load(f)

        # Try to get exact versions from Chart.lock
        lock_versions = {}
        lock_path = os.path.join(chart_dir, "Chart.lock")
        if os.path.exists(lock_path) and not os.path.islink(lock_path):
            try:
                with open(lock_path) as lf:
                    lock_data = self._yaml.load(lf)
                for dep in lock_data.get("dependencies", []):
                    if isinstance(dep, dict):
                        lock_versions[dep.get("name", "")] = dep.get("version", "")
            except Exception:
                pass

        deps = data.get("dependencies", [])
        if not isinstance(deps, list):
            return fixed

        semver_range_re = re.compile(r"[~^>=<|]")
        changed = False
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            version = str(dep.get("version", ""))
            name = str(dep.get("name", ""))
            if not semver_range_re.search(version):
                continue

            # Get exact version from lock or extract first version from range
            exact = lock_versions.get(name, "")
            if not exact:
                exact = self._extract_version_from_range(version)

            if exact and exact != version:
                dep["version"] = exact
                changed = True
                fixed.append({
                    "rule_id": "HLM-PIN-001",
                    "original": version,
                    "resolved": exact,
                    "dependency": name,
                    "method": "chart_lock" if name in lock_versions else "strip_range",
                })

        if changed and not self.dry_run:
            self._atomic_write(chart_yaml_path, data)

        return fixed

    @staticmethod
    def _extract_version_from_range(version: str) -> str:
        """Extract the first valid version from a SemVer range expression.

        Handles compound ranges like '>=1.2.0,<2.0.0' by splitting on
        range separators and returning the first version-like component.
        Strips prerelease/build metadata (e.g. -beta.1, +build.123)
        before matching.
        Returns empty string for wildcard ranges (*, x.x.x) that have
        no extractable numeric version.
        """
        parts = re.split(r"[,| ]+", version)
        for part in parts:
            cleaned = re.sub(r"[~^>=<]", "", part).strip()
            base_version = re.sub(r"[-+].*$", "", cleaned)
            if base_version and re.match(r"\d+(\.\d+)*$", base_version):
                return base_version
        # Fallback: strip all range operators
        fallback = re.sub(r"[~^>=<|]", "", version).strip()
        base_fallback = re.sub(r"[-+].*$", "", fallback)
        if base_fallback and re.match(r"\d+(\.\d+)*$", base_fallback):
            return base_fallback
        return ""

    @staticmethod
    def _resolve_dotpath(data, path: str):
        """Traverse a nested dict/list using a dotpath that may contain array indices.

        Returns (parent_obj, final_key) or (None, None) if traversal fails.
        Handles paths like 'auth.password' and 'databases[0].password'.
        """
        # Split on dots but preserve array indices
        tokens = re.findall(r"[^.\[\]]+|\[\d+\]", path)
        # Normalize: strip brackets from index tokens
        parts = []
        for token in tokens:
            m = re.match(r"\[(\d+)\]", token)
            if m:
                parts.append(int(m.group(1)))
            elif token:
                parts.append(token)

        if not parts:
            return None, None

        obj = data
        for part in parts[:-1]:
            if isinstance(part, int) and isinstance(obj, list) and part < len(obj):
                obj = obj[part]
            elif isinstance(part, str) and isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None, None
        return obj, parts[-1]

    def _fix_secret_defaults(self, values_path, findings):
        fixed = []
        with open(values_path) as f:
            data = self._yaml.load(f)

        if not data:
            return fixed

        # Get the dotpaths from findings
        secret_paths = set()
        for f in findings:
            field = f.get("field", "")
            if field:
                secret_paths.add(field)

        changed = False
        for path in secret_paths:
            parent, key = self._resolve_dotpath(data, path)
            if parent is None or key is None:
                continue
            if isinstance(key, int) and isinstance(parent, list) and key < len(parent):
                current = parent[key]
            elif isinstance(key, str) and isinstance(parent, dict) and key in parent:
                current = parent[key]
            else:
                continue
            if current and isinstance(current, str) and current.strip():
                parent[key] = ""
                changed = True
                fixed.append({
                    "rule_id": "HLM-TRUST-002",
                    "field": path,
                    "original": current[:20] + "..." if len(str(current)) > 20 else str(current),
                    "resolved": "",
                    "method": "clear_default",
                })

        if changed and not self.dry_run:
            self._atomic_write(values_path, data)

        return fixed

    def _atomic_write(self, path, data):
        fd, tmp = tempfile.mkstemp(suffix=".yaml", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "w") as f:
                self._yaml.dump(data, f)
            original_mode = os.stat(path).st_mode
            os.chmod(tmp, original_mode)
            os.replace(tmp, path)
        except Exception:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
