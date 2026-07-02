"""Namespace security checks for Helm charts."""

from __future__ import annotations

import os
import re

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_RELEASE_NAMESPACE_RE = re.compile(r"\.Release\.Namespace")


@register_check
def check_privileged_namespace_render(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-NS-001: Resource in privileged namespace (render mode only)."""
    # Render mode only. Requires rendered_manifests on ChartInfo (Tier 3).
    # Currently a stub: skip if no rendered data is available.
    rendered = getattr(chart, "rendered_manifests", None)
    if not rendered:
        return []

    # Future: iterate rendered manifests and check metadata.namespace
    # against config.privileged_namespaces
    return []


@register_check
def check_release_namespace_no_schema(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-NS-002: Release namespace without schema restriction."""
    findings = []

    # Tier 2: check if any template uses .Release.Namespace
    uses_release_ns = False
    first_ref_file = ""
    first_ref_line = 0
    for tmpl in chart.template_files:
        for lineno, line in enumerate(tmpl.content.splitlines(), start=1):
            if _RELEASE_NAMESPACE_RE.search(line):
                if not uses_release_ns:
                    first_ref_file = tmpl.path
                    first_ref_line = lineno
                uses_release_ns = True
                break
        if uses_release_ns:
            break

    if not uses_release_ns:
        return []

    # Tier 1: check if values.schema.json has namespace constraints
    schema = chart.values_schema
    if schema is not None:
        # Check if the schema defines any namespace-related property
        props = schema.get("properties", {})
        if isinstance(props, dict):
            for key in props:
                if "namespace" in key.lower():
                    return []  # Schema constrains namespace, no finding

    report_file = first_ref_file or os.path.join(chart.chart_dir, "values.yaml")
    findings.append(_finding(
        rule_id="HLM-NS-002",
        severity="MEDIUM",
        title="Release namespace without schema restriction",
        chart_dir=chart.chart_dir,
        file_path=report_file,
        line=first_ref_line or 1,
        message=(
            "Templates use '.Release.Namespace' but values.schema.json does not "
            "constrain namespace values. Users can deploy to any namespace."
        ),
        cwe="CWE-269",
        remediation="Add namespace constraints in values.schema.json",
    ))
    return findings
