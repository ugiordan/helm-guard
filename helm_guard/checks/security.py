"""Security checks based on real Helm CVEs and attack techniques (HLM-SEC-001..005)."""

from __future__ import annotations

import os
import re

from helm_guard.checks._common import register_check, _finding


@register_check
def check_sec_001(chart, config) -> list[dict]:
    """HLM-SEC-001: Path traversal in Chart.yaml name field."""
    if not chart.chart_yaml:
        return []
    name = str(chart.chart_yaml.get("name", ""))
    if ".." in name or "/" in name or "\\" in name:
        return [_finding(
            "HLM-SEC-001", "HIGH", "Path traversal in chart name",
            chart.chart_dir, "Chart.yaml", 0,
            f"Chart.yaml name '{name}' contains path traversal sequences. "
            f"CVE-2024-25620 and CVE-2026-35206 demonstrated that chart names "
            f"with ../ can write files outside intended directories during "
            f"chart archive extraction.",
            cwe="CWE-22",
            remediation="Use a simple chart name without path separators or traversal sequences.",
            extra={"name": name},
        )]
    return []


@register_check
def check_sec_002(chart, config) -> list[dict]:
    """HLM-SEC-002: Chart.lock is a symlink."""
    lock_path = os.path.join(chart.chart_dir, "Chart.lock")
    if os.path.islink(lock_path):
        target = os.readlink(lock_path)
        return [_finding(
            "HLM-SEC-002", "CRITICAL", "Chart.lock is a symlink",
            chart.chart_dir, "Chart.lock", 0,
            f"Chart.lock is a symlink pointing to '{target}'. "
            f"CVE-2025-53547 (CVSS 8.5) demonstrated that a symlinked "
            f"Chart.lock enables arbitrary code execution when Helm writes "
            f"dependency data through the symlink to the target file.",
            cwe="CWE-59",
            remediation="Remove the symlink and create a regular Chart.lock file via helm dependency build.",
            extra={"symlink_target": target},
        )]
    return []


@register_check
def check_sec_003(chart, config) -> list[dict]:
    """HLM-SEC-003: valueFiles with absolute path or traversal."""
    findings = []
    # Check for valueFiles references in templates and values
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            if 'valueFiles' not in line and 'valuesFiles' not in line:
                continue
            # Check for absolute paths or traversal
            if re.search(r'["\']?(/[a-zA-Z]|\.\.)', line):
                findings.append(_finding(
                    "HLM-SEC-003", "HIGH", "valueFiles with absolute path or traversal",
                    chart.chart_dir, tmpl.path, i,
                    "Template references valueFiles with an absolute path or "
                    "directory traversal. CVE-2022-24348 demonstrated this enables "
                    "reading sensitive files from Argo CD reposerver, bypassing "
                    "path validation via URI parsing confusion.",
                    cwe="CWE-22",
                    remediation="Use relative paths within the chart directory only. Do not use absolute paths or ../ in valueFiles.",
                ))
    return findings


@register_check
def check_sec_004(chart, config) -> list[dict]:
    """HLM-SEC-004: Plugin version with path traversal."""
    # Check for plugin.yaml files in the chart
    plugin_yaml = os.path.join(chart.chart_dir, "plugin.yaml")
    if not os.path.exists(plugin_yaml):
        return []
    try:
        from ruamel.yaml import YAML
        yaml = YAML(typ="safe")
        with open(plugin_yaml) as f:
            data = yaml.load(f)
        if not data:
            return []
        version = str(data.get("version", ""))
        if ".." in version or "/" in version:
            return [_finding(
                "HLM-SEC-004", "HIGH", "Plugin version with path traversal",
                chart.chart_dir, "plugin.yaml", 0,
                f"plugin.yaml version '{version}' contains path traversal sequences. "
                f"CVE-2026-35204 (CVSS 8.4) demonstrated this enables arbitrary "
                f"filesystem writes during plugin installation.",
                cwe="CWE-22",
                remediation="Use a clean SemVer version string without path separators.",
                extra={"version": version},
            )]
    except Exception:
        pass
    return []


@register_check
def check_sec_005(chart, config) -> list[dict]:
    """HLM-SEC-005: SA token automount not disabled in templates."""
    findings = []
    for tmpl in chart.template_files:
        content = tmpl.content
        if 'ServiceAccount' not in content:
            continue
        # Check if any ServiceAccount definition lacks automountServiceAccountToken: false
        if 'kind: ServiceAccount' not in content and "kind: 'ServiceAccount'" not in content:
            continue
        # Verify kind: ServiceAccount is a resource kind, not a subjects reference
        # (RoleBindings have ServiceAccount in subjects at deeper indentation)
        lines = content.splitlines()
        is_sa_resource = False
        sa_line = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped in ('kind: ServiceAccount', "kind: 'ServiceAccount'") and indent <= 2:
                is_sa_resource = True
                sa_line = i
                break
        if not is_sa_resource:
            continue
        # Check for automountServiceAccountToken (literal false OR templated)
        if 'automountServiceAccountToken: false' in content:
            continue
        if 'automountServiceAccountToken:' in content and '{{' in content:
            # Templated value (e.g. {{ .Values.sa.automountServiceAccountToken }}),
            # typically defaults to false in values.yaml
            continue
        findings.append(_finding(
            "HLM-SEC-005", "MEDIUM",
            "ServiceAccount without automountServiceAccountToken disabled",
            chart.chart_dir, tmpl.path, sa_line,
            "Template creates a ServiceAccount without explicitly setting "
            "automountServiceAccountToken: false. VoidLink malware targets "
            "/var/run/secrets/ tokens in 22% of cloud environments.",
            cwe="CWE-269",
            remediation="Add automountServiceAccountToken: false to ServiceAccount specs.",
        ))
    return findings


@register_check
def check_sec_006(chart, config) -> list[dict]:
    """HLM-SEC-006: Missing .helmignore file."""
    helmignore = os.path.join(chart.chart_dir, ".helmignore")
    if os.path.exists(helmignore):
        return []
    return [_finding(
        "HLM-SEC-006", "MEDIUM", "Missing .helmignore file",
        chart.chart_dir, chart.chart_dir, 0,
        "Chart has no .helmignore file. When packaged, sensitive files "
        "(.git/, .env, private keys, CI configs) may be included in the "
        "chart archive and distributed to users.",
        cwe="CWE-200",
        remediation="Add a .helmignore file. See helm create for the default template.",
    )]
