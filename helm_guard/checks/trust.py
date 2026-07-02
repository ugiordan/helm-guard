"""Values trust checks for Helm charts."""

from __future__ import annotations

import os
from typing import Any

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo


def _walk_values_for_secrets(
    data: Any,
    patterns: list[str],
    path: str = "",
) -> list[tuple[str, str, Any]]:
    """Recursively walk values.yaml looking for secret-like keys with non-empty defaults.

    Returns list of (dotpath, key, value).
    """
    results = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            lower_key = key.lower()
            # Check if key matches any secret pattern
            if any(pat.lower() in lower_key for pat in patterns):
                # Only flag if the value is a non-empty string (actual default set)
                if isinstance(val, str) and val.strip():
                    results.append((current_path, key, val))
            results.extend(_walk_values_for_secrets(val, patterns, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(_walk_values_for_secrets(item, patterns, f"{path}[{i}]"))
    return results


@register_check
def check_no_values_schema(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-001: No values.schema.json."""
    # Only flag if there is a values.yaml to validate
    if not chart.values_yaml:
        return []

    if chart.values_schema is not None:
        return []

    values_path = os.path.join(chart.chart_dir, "values.yaml")
    return [_finding(
        rule_id="HLM-TRUST-001",
        severity="HIGH",
        title="No values.schema.json",
        chart_dir=chart.chart_dir,
        file_path=values_path,
        line=1,
        message="Chart has values.yaml but no values.schema.json. Values are not type-checked.",
        cwe="CWE-20",
        remediation="Add values.schema.json with type constraints for all user-facing values",
    )]


@register_check
def check_secrets_in_values(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-002: Secrets in values.yaml."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    for dotpath, key, val in _walk_values_for_secrets(
        chart.values_yaml, config.secret_key_patterns
    ):
        findings.append(_finding(
            rule_id="HLM-TRUST-002",
            severity="HIGH",
            title="Secret with non-empty default in values.yaml",
            chart_dir=chart.chart_dir,
            file_path=values_path,
            line=1,
            message=(
                f"Key '{dotpath}' matches secret pattern and has non-empty default '{val[:20]}...'. "
                f"Use empty defaults and set via --set or external secrets."
            ),
            cwe="CWE-798",
            remediation="Use empty string as default, set secrets via --set or external secret management",
        ))
    return findings


@register_check
def check_untrusted_dependency_repo(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-003: Chart dependency from untrusted repository."""
    findings = []
    chart_yaml_path = os.path.join(chart.chart_dir, "Chart.yaml")

    # Check direct dependencies
    deps = chart.chart_yaml.get("dependencies", [])
    if isinstance(deps, list):
        for i, dep in enumerate(deps):
            if not isinstance(dep, dict):
                continue
            repo = str(dep.get("repository", ""))
            name = str(dep.get("name", f"dependency[{i}]"))
            if repo and not config.is_trusted_chart_repo(repo):
                findings.append(_finding(
                    rule_id="HLM-TRUST-003",
                    severity="HIGH",
                    title="Chart dependency from untrusted repository",
                    chart_dir=chart.chart_dir,
                    file_path=chart_yaml_path,
                    line=1,
                    message=f"Dependency '{name}' uses repository '{repo}' which is not in the trusted list.",
                    cwe="CWE-829",
                    remediation="Use charts from trusted repositories or add the repo to trusted_chart_repos",
                ))

    # Walk charts/ subdirectories for transitive deps
    charts_dir = os.path.join(chart.chart_dir, "charts")
    if os.path.isdir(charts_dir):
        for entry in sorted(os.listdir(charts_dir)):
            subchart_dir = os.path.join(charts_dir, entry)
            subchart_yaml_path = os.path.join(subchart_dir, "Chart.yaml")
            if not os.path.isfile(subchart_yaml_path):
                continue
            from ruamel.yaml import YAML
            yaml = YAML(typ="safe")
            try:
                with open(subchart_yaml_path) as f:
                    subchart_data = yaml.load(f) or {}
            except Exception:
                continue
            sub_deps = subchart_data.get("dependencies", [])
            if not isinstance(sub_deps, list):
                continue
            for j, sub_dep in enumerate(sub_deps):
                if not isinstance(sub_dep, dict):
                    continue
                repo = str(sub_dep.get("repository", ""))
                name = str(sub_dep.get("name", f"dependency[{j}]"))
                if repo and not config.is_trusted_chart_repo(repo):
                    findings.append(_finding(
                        rule_id="HLM-TRUST-003",
                        severity="HIGH",
                        title="Transitive dependency from untrusted repository",
                        chart_dir=chart.chart_dir,
                        file_path=subchart_yaml_path,
                        line=1,
                        message=(
                            f"Subchart '{entry}' has dependency '{name}' from untrusted "
                            f"repository '{repo}'."
                        ),
                        cwe="CWE-829",
                        remediation="Audit subchart dependencies and use trusted repositories",
                    ))

    return findings
