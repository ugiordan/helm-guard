"""OLM/Operator security checks for Helm charts (Tier 1 + Tier 2 fallback)."""

from __future__ import annotations

import os
import re
from typing import Any

from helm_guard.checks._common import _finding, register_check, yaml_key_line
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

# Template regex patterns for Tier 2 fallback
_INSTALL_PLAN_AUTO_RE = re.compile(r"installPlanApproval:\s*Automatic")
_STARTING_CSV_RE = re.compile(r"startingCSV:")
_COMMUNITY_SOURCE_RE = re.compile(r"source:\s*community-operators")
_NAMESPACE_RE = re.compile(r"namespace:\s*(\S+)")


def _walk_for_key(data: Any, target_key: str, path: str = "") -> list[tuple[str, Any, int]]:
    """Walk values.yaml looking for a specific key name.

    Returns list of (dotpath, value, line_number).
    """
    results: list[tuple[str, Any, int]] = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            if key == target_key:
                line = yaml_key_line(data, key)
                results.append((current_path, val, line))
            results.extend(_walk_for_key(val, target_key, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(_walk_for_key(item, target_key, f"{path}[{i}]"))
    return results


def _has_nearby_starting_csv(data: Any, path: str = "") -> bool:
    """Check if values.yaml has a startingCSV field anywhere."""
    if isinstance(data, dict):
        if "startingCSV" in data:
            return True
        for key, val in data.items():
            if _has_nearby_starting_csv(val, f"{path}.{key}" if path else key):
                return True
    elif isinstance(data, list):
        for item in data:
            if _has_nearby_starting_csv(item, path):
                return True
    return False


@register_check
def check_automatic_install_plan(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-OLM-001: Automatic install plan without version pin."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    # Tier 1: check values.yaml for installPlanApproval: Automatic
    for dotpath, val, line in _walk_for_key(chart.values_yaml, "installPlanApproval"):
        if isinstance(val, str) and val.strip() == "Automatic":
            if not _has_nearby_starting_csv(chart.values_yaml):
                findings.append(_finding(
                    rule_id="HLM-OLM-001",
                    severity="HIGH",
                    title="Automatic install plan without version pin",
                    chart_dir=chart.chart_dir,
                    file_path=values_path,
                    line=line,
                    message=(
                        f"'{dotpath}' is set to 'Automatic' without a 'startingCSV' version pin. "
                        f"Operators will auto-upgrade without approval."
                    ),
                    cwe="CWE-829",
                    remediation="Use Manual approval or pin to a CSV version with startingCSV",
                ))

    # Tier 2: regex fallback on template files for hardcoded Subscription CRDs
    for tmpl in chart.template_files:
        for lineno, line_text in enumerate(tmpl.content.splitlines(), start=1):
            if _INSTALL_PLAN_AUTO_RE.search(line_text):
                # Check if there's a startingCSV anywhere in the same template
                if not _STARTING_CSV_RE.search(tmpl.content):
                    findings.append(_finding(
                        rule_id="HLM-OLM-001",
                        severity="HIGH",
                        title="Automatic install plan without version pin",
                        chart_dir=chart.chart_dir,
                        file_path=tmpl.path,
                        line=lineno,
                        message=(
                            "Hardcoded 'installPlanApproval: Automatic' in template without "
                            "'startingCSV'. Operators will auto-upgrade without approval."
                        ),
                        cwe="CWE-829",
                        remediation="Use Manual approval or pin to a CSV version with startingCSV",
                    ))
    return findings


@register_check
def check_community_catalog(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-OLM-002: Subscription using community catalog."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    # Tier 1: check values.yaml for source: community-operators
    for dotpath, val, line in _walk_for_key(chart.values_yaml, "source"):
        if isinstance(val, str) and val.strip() == "community-operators":
            findings.append(_finding(
                rule_id="HLM-OLM-002",
                severity="MEDIUM",
                title="Subscription using community catalog",
                chart_dir=chart.chart_dir,
                file_path=values_path,
                line=line,
                message=(
                    f"'{dotpath}' uses 'community-operators' catalog. Community operators "
                    f"are not certified and may contain vulnerabilities."
                ),
                cwe="CWE-829",
                remediation="Use certified catalogs (redhat-operators, certified-operators)",
            ))

    # Tier 2: regex fallback on template files
    for tmpl in chart.template_files:
        for lineno, line_text in enumerate(tmpl.content.splitlines(), start=1):
            if _COMMUNITY_SOURCE_RE.search(line_text):
                findings.append(_finding(
                    rule_id="HLM-OLM-002",
                    severity="MEDIUM",
                    title="Subscription using community catalog",
                    chart_dir=chart.chart_dir,
                    file_path=tmpl.path,
                    line=lineno,
                    message=(
                        "Hardcoded 'source: community-operators' in template. "
                        "Community operators are not certified."
                    ),
                    cwe="CWE-829",
                    remediation="Use certified catalogs (redhat-operators, certified-operators)",
                ))
    return findings


@register_check
def check_operator_privileged_namespace(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-OLM-003: Operator in privileged namespace."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    # Tier 1: check values.yaml for namespace fields matching privileged list
    for dotpath, val, line in _walk_for_key(chart.values_yaml, "namespace"):
        if isinstance(val, str) and val.strip() in config.privileged_namespaces:
            findings.append(_finding(
                rule_id="HLM-OLM-003",
                severity="MEDIUM",
                title="Operator in privileged namespace",
                chart_dir=chart.chart_dir,
                file_path=values_path,
                line=line,
                message=(
                    f"'{dotpath}' is set to privileged namespace '{val}'. "
                    f"Operators should use dedicated namespaces."
                ),
                cwe="CWE-269",
                remediation="Use a dedicated namespace for operators instead of privileged namespaces",
            ))

    # Tier 2: regex fallback on template files
    for tmpl in chart.template_files:
        for lineno, line_text in enumerate(tmpl.content.splitlines(), start=1):
            match = _NAMESPACE_RE.search(line_text)
            if match:
                ns_value = match.group(1).strip().strip('"').strip("'")
                # Skip Go template expressions
                if "{{" in ns_value:
                    continue
                if ns_value in config.privileged_namespaces:
                    findings.append(_finding(
                        rule_id="HLM-OLM-003",
                        severity="MEDIUM",
                        title="Operator in privileged namespace",
                        chart_dir=chart.chart_dir,
                        file_path=tmpl.path,
                        line=lineno,
                        message=(
                            f"Hardcoded namespace '{ns_value}' is a privileged namespace. "
                            f"Use a dedicated namespace."
                        ),
                        cwe="CWE-269",
                        remediation="Use a dedicated namespace for operators",
                    ))
    return findings
