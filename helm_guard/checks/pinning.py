"""Pinning checks for Helm chart dependencies and image tags."""

from __future__ import annotations

import os
import re
from typing import Any

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_SEMVER_RANGE_RE = re.compile(r"[~^>=<|]")
_OLM_UNPINNED_CHANNEL_RE = re.compile(
    r"^(stable|fast|alpha|beta|preview|candidate|latest|nightly)$",
    re.IGNORECASE,
)


def _walk_values_for_images(
    data: Any,
    path: str = "",
) -> list[tuple[str, str, Any]]:
    """Recursively walk values.yaml looking for image-related keys.

    Returns list of (dotpath, key, value) for keys that look image-related.
    """
    results = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            lower_key = key.lower()
            if lower_key in ("image", "tag", "repository") and isinstance(val, str):
                results.append((current_path, key, val))
            results.extend(_walk_values_for_images(val, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(_walk_values_for_images(item, f"{path}[{i}]"))
    return results


def _walk_values_for_channels(
    data: Any,
    path: str = "",
) -> list[tuple[str, str]]:
    """Recursively walk values.yaml looking for OLM channel fields.

    Returns list of (dotpath, channel_value) for keys named 'channel'.
    """
    results = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            if key.lower() == "channel" and isinstance(val, str):
                results.append((current_path, val))
            results.extend(_walk_values_for_channels(val, current_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(_walk_values_for_channels(item, f"{path}[{i}]"))
    return results


@register_check
def check_dependency_semver_range(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PIN-001: Chart dependency with SemVer range."""
    findings = []
    deps = chart.chart_yaml.get("dependencies", [])
    if not isinstance(deps, list):
        return findings

    chart_yaml_path = os.path.join(chart.chart_dir, "Chart.yaml")
    for i, dep in enumerate(deps):
        if not isinstance(dep, dict):
            continue
        version = str(dep.get("version", ""))
        name = str(dep.get("name", f"dependency[{i}]"))
        if version and _SEMVER_RANGE_RE.search(version):
            findings.append(_finding(
                rule_id="HLM-PIN-001",
                severity="HIGH",
                title="Chart dependency with SemVer range",
                chart_dir=chart.chart_dir,
                file_path=chart_yaml_path,
                line=1,
                message=f"Dependency '{name}' uses SemVer range '{version}'. Pin to an exact version.",
                cwe="CWE-829",
                remediation=f"Pin dependency '{name}' to an exact version (e.g., version: 1.2.3)",
            ))
    return findings


@register_check
def check_missing_chart_lock(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PIN-002: Missing Chart.lock when Chart.yaml has dependencies."""
    deps = chart.chart_yaml.get("dependencies", [])
    if not isinstance(deps, list) or not deps:
        return []

    if chart.chart_lock is not None:
        return []

    chart_yaml_path = os.path.join(chart.chart_dir, "Chart.yaml")
    return [_finding(
        rule_id="HLM-PIN-002",
        severity="HIGH",
        title="Missing Chart.lock",
        chart_dir=chart.chart_dir,
        file_path=chart_yaml_path,
        line=1,
        message="Chart has dependencies but no Chart.lock. Run 'helm dependency build' to generate it.",
        cwe="CWE-829",
        remediation="Run 'helm dependency build' to generate Chart.lock",
    )]


@register_check
def check_mutable_image_tag(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PIN-003: Mutable image tag in values.yaml."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    for dotpath, key, val in _walk_values_for_images(chart.values_yaml):
        if not val or val.strip() == "":
            continue
        # Skip if the value contains a sha256 digest pin
        if "@sha256:" in val:
            continue
        # Skip Go template expressions (these are placeholders, not actual values)
        if "{{" in val:
            continue
        findings.append(_finding(
            rule_id="HLM-PIN-003",
            severity="MEDIUM",
            title="Mutable image tag in values.yaml",
            chart_dir=chart.chart_dir,
            file_path=values_path,
            line=1,
            message=f"Image value at '{dotpath}' is '{val}' (no @sha256: digest). Pin to a digest.",
            cwe="CWE-829",
            remediation="Pin images to digest (e.g., image: registry.io/repo@sha256:abc123...)",
        ))
    return findings


@register_check
def check_olm_channel_not_pinned(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PIN-004: OLM subscription channel not version-pinned."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    for dotpath, channel_val in _walk_values_for_channels(chart.values_yaml):
        if _OLM_UNPINNED_CHANNEL_RE.match(channel_val.strip()):
            findings.append(_finding(
                rule_id="HLM-PIN-004",
                severity="MEDIUM",
                title="OLM subscription channel not version-pinned",
                chart_dir=chart.chart_dir,
                file_path=values_path,
                line=1,
                message=f"Channel at '{dotpath}' is '{channel_val}' without version suffix. Use versioned channels.",
                cwe="CWE-829",
                remediation="Use versioned channels (e.g., stable-v1.3 instead of stable)",
            ))
    return findings
