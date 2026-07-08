"""Hook security checks for Helm charts (Tier 2: template text regex)."""

from __future__ import annotations

import os
import re

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_HOOK_ANNOTATION_RE = re.compile(r"helm\.sh/hook\b")
_SECURITY_CONTEXT_RE = re.compile(r"securityContext")
_HOOK_DELETE_BEFORE_RE = re.compile(r"helm\.sh/hook-delete-policy[\"']?:\s*before-hook-creation")


@register_check
def check_hook_without_security_context(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-HOOK-001: Hook Job without security context reference."""
    findings = []
    for tmpl in chart.template_files:
        if not _HOOK_ANNOTATION_RE.search(tmpl.content):
            continue
        # Template has a hook annotation. Check if securityContext appears anywhere.
        if _SECURITY_CONTEXT_RE.search(tmpl.content):
            continue
        # Find the line where the hook annotation is declared for precise reporting
        for lineno, line in enumerate(tmpl.content.splitlines(), start=1):
            if _HOOK_ANNOTATION_RE.search(line):
                findings.append(_finding(
                    rule_id="HLM-HOOK-001",
                    severity="HIGH",
                    title="Hook Job without security context reference",
                    chart_dir=chart.chart_dir,
                    file_path=tmpl.path,
                    line=lineno,
                    message=(
                        "Template has 'helm.sh/hook' annotation but no 'securityContext' "
                        "reference. Hook Jobs should define a security context."
                    ),
                    cwe="CWE-250",
                    remediation="Add securityContext to hook Job specs",
                ))
                break  # One finding per template file
    return findings


@register_check
def check_hook_before_creation_delete(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-HOOK-002: Hook with before-hook-creation delete policy."""
    findings = []
    for tmpl in chart.template_files:
        for lineno, line in enumerate(tmpl.content.splitlines(), start=1):
            if _HOOK_DELETE_BEFORE_RE.search(line):
                findings.append(_finding(
                    rule_id="HLM-HOOK-002",
                    severity="MEDIUM",
                    title="Hook with before-hook-creation delete policy",
                    chart_dir=chart.chart_dir,
                    file_path=tmpl.path,
                    line=lineno,
                    message=(
                        "Hook uses 'before-hook-creation' delete policy which removes "
                        "the previous hook resource before the new one runs. This can "
                        "hide failures and lose audit data."
                    ),
                    cwe="CWE-390",
                    remediation="Use 'hook-succeeded' or 'hook-failed' delete policies instead",
                ))
    return findings


@register_check
def check_hook_003(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-HOOK-003: Post-renderer executing external script."""
    findings = []
    # Check values.yaml for postRenderer configuration
    if chart.values_yaml:
        def _search(data, path=""):
            if isinstance(data, dict):
                for k, v in data.items():
                    current = f"{path}.{k}" if path else k
                    if k.lower() in ("postrenderer", "post-renderer", "postrender"):
                        if isinstance(v, dict):
                            cmd = v.get("command", v.get("exec", ""))
                            if cmd:
                                findings.append(_finding(
                                    "HLM-HOOK-003", "HIGH",
                                    "Post-renderer executing external script",
                                    chart.chart_dir, os.path.join(chart.chart_dir, "values.yaml"), 0,
                                    f"Chart configures a post-renderer at '{current}' "
                                    f"that executes '{cmd}'. Post-renderers run arbitrary "
                                    f"code on rendered manifests before apply.",
                                    cwe="CWE-94",
                                    remediation="Audit post-renderer scripts. Pin to known-good versions.",
                                    extra={"command": str(cmd), "path": current},
                                ))
                        elif isinstance(v, str) and v:
                            findings.append(_finding(
                                "HLM-HOOK-003", "HIGH",
                                "Post-renderer executing external script",
                                chart.chart_dir, "values.yaml", 0,
                                f"Chart configures a post-renderer at '{current}': '{v}'. "
                                f"Post-renderers run arbitrary code on rendered manifests.",
                                cwe="CWE-94",
                                remediation="Audit post-renderer scripts. Pin to known-good versions.",
                                extra={"command": v, "path": current},
                            ))
                    _search(v, current)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    _search(item, f"{path}[{i}]")
        _search(chart.values_yaml)
    return findings
