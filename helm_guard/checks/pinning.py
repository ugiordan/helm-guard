"""Pinning checks for Helm chart dependencies and image tags."""

from __future__ import annotations

import os
import re
from typing import Any

from helm_guard.checks._common import _finding, register_check, yaml_key_line
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_SEMVER_RANGE_RE = re.compile(r"[~^>=<|]")
_OLM_UNPINNED_CHANNEL_RE = re.compile(
    r"^(stable|fast|alpha|beta|preview|candidate|latest|nightly)$",
    re.IGNORECASE,
)


def _is_image_key(key: str, parent_key: str = "") -> bool:
    """Check whether *key* refers to an image-related field.

    Matches:
    - Exact: ``image``, ``tag``, ``repository``
    - Compound: ``containerImage``, ``sidecarImage``, ``initImage``,
      ``imageOverride``, ``imageRegistry`` (anything ending with "image"
      or starting with "image" in camelCase)
    - ``name`` when the parent key is ``image`` (e.g. ``image.name``)
    """
    lower = key.lower()
    if lower in ("image", "tag", "repository"):
        return True
    if lower.endswith("image") or lower.startswith("image"):
        return True
    # image.name pattern: "name" under a parent whose key is/contains "image"
    if lower == "name" and "image" in parent_key.lower():
        return True
    return False


def _walk_values_for_images(
    data: Any,
    path: str = "",
    parent_key: str = "",
) -> list[tuple[str, str, Any, int]]:
    """Recursively walk values.yaml looking for image-related keys.

    Returns list of (dotpath, key, value, line_number) for keys that look
    image-related.  Uses expanded heuristics to catch ``containerImage``,
    ``sidecarImage``, ``initImage``, ``image.name``, etc.
    """
    results: list[tuple[str, str, Any, int]] = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            if _is_image_key(key, parent_key) and isinstance(val, str):
                line = yaml_key_line(data, key)
                results.append((current_path, key, val, line))
            results.extend(_walk_values_for_images(val, current_path, parent_key=key))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(_walk_values_for_images(item, f"{path}[{i}]", parent_key=parent_key))
    return results


def _walk_values_for_channels(
    data: Any,
    path: str = "",
) -> list[tuple[str, str, int]]:
    """Recursively walk values.yaml looking for OLM channel fields.

    Returns list of (dotpath, channel_value, line_number) for keys named
    'channel'.
    """
    results: list[tuple[str, str, int]] = []
    if isinstance(data, dict):
        for key, val in data.items():
            current_path = f"{path}.{key}" if path else key
            if key.lower() == "channel" and isinstance(val, str):
                line = yaml_key_line(data, key)
                results.append((current_path, val, line))
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
            dep_line = yaml_key_line(dep, "version")
            findings.append(_finding(
                rule_id="HLM-PIN-001",
                severity="HIGH",
                title="Chart dependency with SemVer range",
                chart_dir=chart.chart_dir,
                file_path=chart_yaml_path,
                line=dep_line,
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

    for dotpath, key, val, line in _walk_values_for_images(chart.values_yaml):
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
            line=line,
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

    for dotpath, channel_val, line in _walk_values_for_channels(chart.values_yaml):
        stripped = channel_val.strip()
        if _OLM_UNPINNED_CHANNEL_RE.match(stripped):
            # Skip channels known to not offer versioned alternatives
            # Case-insensitive to match _OLM_UNPINNED_CHANNEL_RE (re.IGNORECASE)
            if stripped.lower() in {c.lower() for c in config.known_unversioned_channels}:
                continue
            findings.append(_finding(
                rule_id="HLM-PIN-004",
                severity="MEDIUM",
                title="OLM subscription channel not version-pinned",
                chart_dir=chart.chart_dir,
                file_path=values_path,
                line=line,
                message=f"Channel at '{dotpath}' is '{channel_val}' without version suffix. Use versioned channels.",
                cwe="CWE-829",
                remediation="Use versioned channels (e.g., stable-v1.3 instead of stable)",
            ))
    return findings


_SEMVER_STRICT_RE = re.compile(r"^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$")


@register_check
def check_pin_005(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PIN-005: Chart version not following SemVer."""
    if not chart.chart_yaml:
        return []
    version = str(chart.chart_yaml.get("version", ""))
    chart_yaml_path = os.path.join(chart.chart_dir, "Chart.yaml")
    if not version:
        return [_finding(
            rule_id="HLM-PIN-005",
            severity="MEDIUM",
            title="Missing chart version",
            chart_dir=chart.chart_dir,
            file_path=chart_yaml_path,
            line=0,
            message="Chart.yaml has no version field.",
            cwe="CWE-1104",
            remediation="Add a version field following SemVer (e.g., 1.0.0).",
        )]
    if not _SEMVER_STRICT_RE.match(version):
        return [_finding(
            rule_id="HLM-PIN-005",
            severity="MEDIUM",
            title="Chart version not following SemVer",
            chart_dir=chart.chart_dir,
            file_path=chart_yaml_path,
            line=0,
            message=f"Chart version '{version}' does not follow SemVer format.",
            cwe="CWE-1104",
            remediation="Use SemVer format: MAJOR.MINOR.PATCH (e.g., 1.2.3).",
            extra={"version": version},
        )]
    return []


@register_check
def check_pin_006(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PIN-006: Mutable image tag in values defaults."""
    findings = []
    values_path = os.path.join(chart.chart_dir, "values.yaml")

    def _walk(data: Any, path: str = "") -> None:
        if not isinstance(data, dict):
            return
        for key, val in data.items():
            current = f"{path}.{key}" if path else key
            if isinstance(val, dict):
                _walk(val, current)
                continue
            if not isinstance(val, str):
                continue
            # Only match keys named "tag" that sit next to a "repository" key
            # at the same level (confirming this is an image config block).
            if key != "tag":
                continue
            if "repository" not in data:
                continue
            tag_val = val.strip()
            # Only flag "latest" or empty string.
            # Semver-like tags (1.2.3, v1.0.0) are pinned enough.
            if tag_val == "latest":
                line = yaml_key_line(data, key)
                findings.append(_finding(
                    "HLM-PIN-006", "HIGH", "Mutable image tag 'latest' in values",
                    chart.chart_dir, values_path, line,
                    f"Image tag at '{current}' is set to 'latest'. "
                    f"Mutable tags silently change the deployed image. "
                    f"Use a digest or specific version tag.",
                    cwe="CWE-829",
                    remediation="Pin image to a specific tag or use @sha256: digest.",
                    extra={"path": current, "tag": tag_val},
                ))
            elif tag_val == "":
                line = yaml_key_line(data, key)
                findings.append(_finding(
                    "HLM-PIN-006", "HIGH", "Empty image tag in values",
                    chart.chart_dir, values_path, line,
                    f"Image tag at '{current}' is empty. "
                    f"An empty tag defaults to 'latest' at runtime. "
                    f"Use a digest or specific version tag.",
                    cwe="CWE-829",
                    remediation="Pin image to a specific tag or use @sha256: digest.",
                    extra={"path": current, "tag": tag_val},
                ))

    if chart.values_yaml:
        _walk(chart.values_yaml)
    return findings
