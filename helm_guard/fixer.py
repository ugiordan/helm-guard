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

    def fix_findings(self, findings: list[dict], chart_dir: str) -> FixResult:
        result = FixResult()
        chart_yaml_path = os.path.join(chart_dir, "Chart.yaml")
        values_yaml_path = os.path.join(chart_dir, "values.yaml")

        pin001_findings = [f for f in findings if f["rule_id"] == "HLM-PIN-001"]
        trust002_findings = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
        other_findings = [f for f in findings if f["rule_id"] not in ("HLM-PIN-001", "HLM-TRUST-002")]

        # Fix PIN-001: SemVer ranges -> exact versions
        if pin001_findings and os.path.exists(chart_yaml_path):
            fixed = self._fix_dependency_pinning(chart_yaml_path, chart_dir, pin001_findings)
            result.fixed.extend(fixed)

        # Fix TRUST-002: Clear secret defaults
        if trust002_findings and os.path.exists(values_yaml_path):
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

            # Get exact version from lock or strip range operator
            exact = lock_versions.get(name, "")
            if not exact:
                exact = re.sub(r"[~^>=<|]", "", version).strip()

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
            parts = path.split(".")
            obj = data
            for part in parts[:-1]:
                if isinstance(obj, dict) and part in obj:
                    obj = obj[part]
                else:
                    obj = None
                    break
            if obj is not None and isinstance(obj, dict) and parts[-1] in obj:
                current = obj[parts[-1]]
                if current and isinstance(current, str) and current.strip():
                    obj[parts[-1]] = ""
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
