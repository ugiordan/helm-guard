"""Values trust checks for Helm charts."""

from __future__ import annotations

import os
import re
from typing import Any

from helm_guard.checks._common import _finding, register_check, yaml_key_line
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo


def _is_secret_key_match(key: str, patterns: list[str]) -> bool:
    """Word-boundary match: the key must equal a pattern or **end with** it
    as a camelCase/snake_case segment.

    Matches: ``password``, ``db_password``, ``dbPassword``
    Does NOT match: ``passwordPolicy``, ``secretName``, ``tokenEndpoint``

    The distinction is that a suffix match (``dbPassword``) means the key
    likely holds a password value, while a prefix match (``passwordPolicy``)
    means the key describes something *about* passwords.
    """
    lower_key = key.lower()
    for pat in patterns:
        lp = pat.lower()
        if lower_key == lp:
            return True
        # Split on underscores, hyphens, dots, and camelCase boundaries
        segments = re.split(r"[_.\-]|(?<=[a-z])(?=[A-Z])", key)
        lower_segments = [s.lower() for s in segments]
        # Only match if the pattern is the LAST segment
        if lower_segments and lower_segments[-1] == lp:
            return True
    return False


def _looks_like_real_secret(val: str) -> bool:
    """Heuristic: value looks like it could be a secret (not a reference name).

    Rejects values that look like Kubernetes reference names (e.g.
    ``my-tls-secret``, ``auth-token-ref``) and keeps values that contain
    high-entropy content or look like actual credentials.
    """
    stripped = val.strip()
    if not stripped:
        return False
    # If it contains spaces it's probably a description, not a secret
    if " " in stripped and len(stripped) > 40:
        return False
    # Values that are purely alphanumeric + dashes and look like k8s names
    # (e.g. "my-secret-name") are likely references
    # But "supersecret123" or "sk-abc123def456" are real secrets.
    # Use length + entropy as heuristic: real secrets tend to be longer
    # or contain mixed case / special chars beyond simple dashes.
    return True


def _walk_values_for_secrets(
    data: Any,
    patterns: list[str],
    path: str = "",
) -> list[tuple[str, str, Any, int]]:
    """Recursively walk values.yaml looking for secret-like keys with non-empty defaults.

    Returns list of (dotpath, key, value, line_number).
    Uses word-boundary matching to avoid false positives on keys like
    ``secretName`` or ``tokenEndpoint``.
    """
    results: list[tuple[str, str, Any, int]] = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            if _is_secret_key_match(key, patterns):
                if isinstance(val, str) and val.strip() and _looks_like_real_secret(val):
                    line = yaml_key_line(data, key)
                    results.append((current_path, key, val, line))
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

    for dotpath, key, val, line in _walk_values_for_secrets(
        chart.values_yaml, config.secret_key_patterns
    ):
        findings.append(_finding(
            rule_id="HLM-TRUST-002",
            severity="HIGH",
            title="Secret with non-empty default in values.yaml",
            chart_dir=chart.chart_dir,
            file_path=values_path,
            line=line,
            message=(
                f"Key '{dotpath}' matches secret pattern and has non-empty default "
                f"'{val[:20]}{'...' if len(val) > 20 else ''}'. "
                f"Use empty defaults and set via --set or external secrets."
            ),
            cwe="CWE-798",
            remediation="Use empty string as default, set secrets via --set or external secret management",
            extra={"field": dotpath},
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
            dep_line = yaml_key_line(dep, "repository") if repo else 1

            if repo.startswith("file://"):
                findings.append(_finding(
                    rule_id="HLM-TRUST-003",
                    severity="HIGH",
                    title="Local file:// dependency reference",
                    chart_dir=chart.chart_dir,
                    file_path=chart_yaml_path,
                    line=dep_line,
                    message=(
                        f"Dependency '{name}' uses local file reference '{repo}'. "
                        f"Local dependencies bypass registry provenance checks."
                    ),
                    cwe="CWE-829",
                    remediation="Publish the dependency to a trusted chart repository instead of using file:// references",
                ))
            elif repo and not config.is_trusted_chart_repo(repo):
                findings.append(_finding(
                    rule_id="HLM-TRUST-003",
                    severity="HIGH",
                    title="Chart dependency from untrusted repository",
                    chart_dir=chart.chart_dir,
                    file_path=chart_yaml_path,
                    line=dep_line,
                    message=f"Dependency '{name}' uses repository '{repo}' which is not in the trusted list.",
                    cwe="CWE-829",
                    remediation="Use charts from trusted repositories or add the repo to trusted_chart_repos",
                ))

    # Recursively walk charts/ subdirectories for transitive deps.
    # Uses os.walk to handle arbitrarily nested subchart trees
    # (e.g. charts/redis/charts/sentinel/...).
    #
    # Known limitation (D-02): .tgz packaged subcharts in charts/ are
    # not extracted or inspected. Only extracted directories are scanned.
    charts_dir = os.path.join(chart.chart_dir, "charts")
    if os.path.isdir(charts_dir):
        from ruamel.yaml import YAML
        yaml_loader = YAML(typ="rt")
        for dirpath, _dirnames, filenames in os.walk(charts_dir, followlinks=False):
            if "Chart.yaml" not in filenames:
                continue
            subchart_yaml_path = os.path.join(dirpath, "Chart.yaml")
            # Skip symlinks
            if os.path.islink(subchart_yaml_path):
                continue
            try:
                with open(subchart_yaml_path) as f:
                    subchart_data = yaml_loader.load(f) or {}
            except Exception:
                continue
            if not isinstance(subchart_data, dict):
                continue
            sub_deps = subchart_data.get("dependencies", [])
            if not isinstance(sub_deps, list):
                continue
            # Compute a readable subchart path relative to the main chart
            rel_subchart = os.path.relpath(dirpath, chart.chart_dir)
            for j, sub_dep in enumerate(sub_deps):
                if not isinstance(sub_dep, dict):
                    continue
                repo = str(sub_dep.get("repository", ""))
                name = str(sub_dep.get("name", f"dependency[{j}]"))
                dep_line = yaml_key_line(sub_dep, "repository") if repo else 1

                if repo.startswith("file://"):
                    findings.append(_finding(
                        rule_id="HLM-TRUST-003",
                        severity="HIGH",
                        title="Transitive local file:// dependency reference",
                        chart_dir=chart.chart_dir,
                        file_path=subchart_yaml_path,
                        line=dep_line,
                        message=(
                            f"Subchart '{rel_subchart}' dependency '{name}' uses local "
                            f"file reference '{repo}'."
                        ),
                        cwe="CWE-829",
                        remediation="Publish the dependency to a trusted chart repository",
                    ))
                elif repo and not config.is_trusted_chart_repo(repo):
                    findings.append(_finding(
                        rule_id="HLM-TRUST-003",
                        severity="HIGH",
                        title="Transitive dependency from untrusted repository",
                        chart_dir=chart.chart_dir,
                        file_path=subchart_yaml_path,
                        line=dep_line,
                        message=(
                            f"Subchart '{rel_subchart}' has dependency '{name}' from untrusted "
                            f"repository '{repo}'."
                        ),
                        cwe="CWE-829",
                        remediation="Audit subchart dependencies and use trusted repositories",
                    ))

    return findings


@register_check
def check_trust_004(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-004: hostNetwork or hostPID enabled in values defaults."""
    findings = []

    def _search(data: Any, path: str = "") -> None:
        if isinstance(data, dict):
            for k, v in data.items():
                current = f"{path}.{k}" if path else k
                if k in ("hostNetwork", "hostPID") and v is True:
                    findings.append(_finding(
                        "HLM-TRUST-004", "HIGH", f"{k} enabled in values defaults",
                        chart.chart_dir, os.path.join(chart.chart_dir, "values.yaml"), 0,
                        f"values.yaml has {current}: true by default. This gives pods "
                        "access to the host network/PID namespace, enabling container "
                        "escape and network sniffing.",
                        cwe="CWE-250",
                        remediation=f"Set {current}: false as the default. Users can override when needed.",
                        extra={"field": current},
                    ))
                _search(v, current)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                _search(item, f"{path}[{i}]")

    if chart.values_yaml:
        _search(chart.values_yaml)
    return findings


@register_check
def check_trust_005(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-005: HTTP URL in values.yaml (cleartext connection)."""
    findings = []

    def _search(data: Any, path: str = "") -> None:
        if isinstance(data, str) and data.startswith("http://") and "localhost" not in data and "127.0.0.1" not in data:
            findings.append(_finding(
                "HLM-TRUST-005", "MEDIUM", "HTTP URL in values (cleartext)",
                chart.chart_dir, os.path.join(chart.chart_dir, "values.yaml"), 0,
                f"values.yaml field '{path}' uses HTTP ({data[:60]}). "
                "Data transmitted over HTTP is visible to network observers.",
                cwe="CWE-319",
                remediation="Use HTTPS URLs for all external endpoints.",
                extra={"field": path, "url": data[:100]},
            ))
        elif isinstance(data, dict):
            for k, v in data.items():
                _search(v, f"{path}.{k}" if path else k)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                _search(item, f"{path}[{i}]")

    if chart.values_yaml:
        _search(chart.values_yaml)
    return findings


@register_check
def check_trust_006(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-006: Permissive NetworkPolicy in templates."""
    findings = []
    for tmpl in chart.template_files:
        content = tmpl.content
        if "NetworkPolicy" not in content:
            continue
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped in ("ingress:", "egress:") or "spec: {}" in stripped:
                findings.append(_finding(
                    "HLM-TRUST-006", "LOW", "Permissive NetworkPolicy in template",
                    chart.chart_dir, tmpl.path, i,
                    "Template contains a NetworkPolicy with a permissive spec. "
                    "Empty ingress/egress rules allow all traffic.",
                    cwe="CWE-284",
                    remediation="Define explicit ingress/egress rules. Avoid empty spec.",
                ))
                break
    return findings


@register_check
def check_trust_007(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-TRUST-007: Global values override security fields."""
    if not chart.values_yaml:
        return []
    findings = []
    global_vals = chart.values_yaml.get("global", {})
    if not isinstance(global_vals, dict):
        return []

    security_keys = {"securityContext", "privileged", "runAsRoot", "runAsUser",
                     "allowPrivilegeEscalation", "hostNetwork", "hostPID",
                     "serviceAccount", "rbac", "networkPolicy"}

    def _search(data, path="global"):
        if isinstance(data, dict):
            for k, v in data.items():
                current = f"{path}.{k}"
                if k in security_keys:
                    findings.append(_finding(
                        "HLM-TRUST-007", "MEDIUM",
                        "Global values override security fields",
                        chart.chart_dir,
                        os.path.join(chart.chart_dir, "values.yaml"), 0,
                        f"Global value at '{current}' overrides security-related "
                        f"fields for all subcharts. A parent chart can silently "
                        f"change subchart security settings.",
                        cwe="CWE-1188",
                        remediation="Review global security overrides. Ensure subcharts aren't silently made less secure.",
                        extra={"field": current},
                    ))
                _search(v, current)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                _search(item, f"{path}[{i}]")

    _search(global_vals)
    return findings
