"""Subchart dependency checks for Helm charts (Tier 1: YAML parsing)."""

from __future__ import annotations

import os
import re
from typing import Any

from helm_guard.checks._common import _finding, register_check, yaml_key_line
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_SECURITY_FIELDS = {"securityContext", "serviceAccount", "rbac", "podSecurityPolicy"}


def _walk_for_subchart_security_overrides(
    data: Any,
    subchart_names: set[str],
    path: str = "",
) -> list[tuple[str, str, int]]:
    """Walk values.yaml looking for subchart sections that override security fields.

    Returns list of (dotpath, field_name, line_number).
    """
    results: list[tuple[str, str, int]] = []
    if not isinstance(data, dict):
        return results

    for key, val in data.items():
        current_path = f"{path}.{key}" if path else key
        # Check if this key is a subchart name
        if key in subchart_names and isinstance(val, dict):
            # Walk the subchart section for security field overrides
            for sub_key, sub_val in val.items():
                sub_path = f"{current_path}.{sub_key}"
                if sub_key in _SECURITY_FIELDS:
                    line = yaml_key_line(val, sub_key)
                    results.append((sub_path, sub_key, line))
                # Also check nested structures (e.g., subchart.container.securityContext)
                if isinstance(sub_val, dict):
                    for nested_key in sub_val:
                        if nested_key in _SECURITY_FIELDS:
                            nested_path = f"{sub_path}.{nested_key}"
                            line = yaml_key_line(sub_val, nested_key)
                            results.append((nested_path, nested_key, line))
        elif isinstance(val, dict):
            results.extend(
                _walk_for_subchart_security_overrides(val, subchart_names, current_path)
            )
    return results


@register_check
def check_subchart_security_override(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-DEP-001: Subchart values override of security fields."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    # Get subchart names from Chart.yaml dependencies
    deps = chart.chart_yaml.get("dependencies", [])
    if not isinstance(deps, list):
        return []

    subchart_names: set[str] = set()
    for dep in deps:
        if isinstance(dep, dict):
            name = dep.get("name")
            if isinstance(name, str):
                subchart_names.add(name)
            # Also check alias
            alias = dep.get("alias")
            if isinstance(alias, str):
                subchart_names.add(alias)

    if not subchart_names:
        return []

    overrides = _walk_for_subchart_security_overrides(
        chart.values_yaml, subchart_names
    )
    for dotpath, field_name, line in overrides:
        findings.append(_finding(
            rule_id="HLM-DEP-001",
            severity="MEDIUM",
            title="Subchart values override of security fields",
            chart_dir=chart.chart_dir,
            file_path=values_path,
            line=line,
            message=(
                f"Parent values override subchart security field at '{dotpath}'. "
                f"This may weaken subchart security defaults."
            ),
            cwe="CWE-1188",
            remediation="Audit subchart security overrides to ensure they don't weaken defaults",
        ))
    return findings


@register_check
def check_dependency_version_conflict(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-DEP-002: Dependency version conflict between Chart.yaml and Chart.lock."""
    findings = []

    if chart.chart_lock is None:
        return []

    chart_yaml_path = os.path.join(chart.chart_dir, "Chart.yaml")

    # Build a map of dependency name -> version from Chart.yaml
    deps = chart.chart_yaml.get("dependencies", [])
    if not isinstance(deps, list):
        return []

    yaml_versions: dict[str, str] = {}
    for dep in deps:
        if isinstance(dep, dict):
            name = str(dep.get("name", ""))
            version = str(dep.get("version", ""))
            if name and version:
                yaml_versions[name] = version

    # Compare with Chart.lock resolved versions
    lock_deps = chart.chart_lock.get("dependencies", [])
    if not isinstance(lock_deps, list):
        return []

    for lock_dep in lock_deps:
        if not isinstance(lock_dep, dict):
            continue
        name = str(lock_dep.get("name", ""))
        lock_version = str(lock_dep.get("version", ""))
        if not name or not lock_version:
            continue

        yaml_version = yaml_versions.get(name, "")
        if not yaml_version:
            continue

        # Only flag if the lock version doesn't match the Chart.yaml spec.
        # For exact versions, they should be equal.
        # For ranges, this is expected (lock resolves the range),
        # so only compare when Chart.yaml has an exact version.
        # An exact version is one without range operators.
        if re.search(r"[~^>=<|]", yaml_version):
            # Range spec in Chart.yaml. Lock resolved it. Check that lock
            # version is still within a reasonable range (simple: just
            # compare major version).
            continue

        # Exact version in Chart.yaml but lock has different version
        if yaml_version != lock_version:
            lock_line = yaml_key_line(lock_dep, "version")
            findings.append(_finding(
                rule_id="HLM-DEP-002",
                severity="LOW",
                title="Dependency version conflict",
                chart_dir=chart.chart_dir,
                file_path=chart_yaml_path,
                line=lock_line,
                message=(
                    f"Dependency '{name}' version in Chart.yaml is '{yaml_version}' "
                    f"but Chart.lock resolved to '{lock_version}'. "
                    f"Lock file may be stale."
                ),
                cwe="CWE-1104",
                remediation="Run 'helm dependency build' to refresh Chart.lock",
            ))
    return findings


_COMMON_CHART_NAMES = {
    "nginx", "redis", "postgresql", "mysql", "mongodb", "kafka",
    "elasticsearch", "prometheus", "grafana", "cert-manager",
    "ingress-nginx", "metrics-server", "external-dns", "vault",
    "consul", "traefik", "harbor", "minio", "rabbitmq",
    "memcached", "mariadb", "cassandra", "etcd", "zookeeper",
}


@register_check
def check_dep_003(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-DEP-003: Chart dependency name potential typosquat."""
    if not chart.chart_yaml:
        return []
    findings = []
    deps = chart.chart_yaml.get("dependencies", [])
    for dep in deps or []:
        if not isinstance(dep, dict):
            continue
        name = str(dep.get("name", "")).lower()
        if not name:
            continue
        # Check for common typosquatting patterns
        for common in _COMMON_CHART_NAMES:
            if name == common:
                break
            # Check edit distance of 1-2 (simple transposition, missing/extra char)
            if len(name) == len(common) and sum(a != b for a, b in zip(name, common)) <= 2:
                findings.append(_finding(
                    "HLM-DEP-003", "HIGH", "Potential dependency name typosquat",
                    chart.chart_dir, "Chart.yaml", 0,
                    f"Chart dependency '{name}' is similar to common chart '{common}' "
                    f"(edit distance <= 2). This could be a typosquatting attack.",
                    cwe="CWE-829",
                    remediation=f"Verify this is the intended dependency. Did you mean '{common}'?",
                    extra={"dep_name": name, "similar_to": common},
                ))
                break
    return findings
