"""Provenance checks for Helm charts (Tier 1: file existence)."""

from __future__ import annotations

import os

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo


@register_check
def check_chart_not_signed(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-PROV-001: Chart not signed (no .prov file)."""
    if chart.has_prov:
        return []

    chart_yaml_path = os.path.join(chart.chart_dir, "Chart.yaml")
    return [_finding(
        rule_id="HLM-PROV-001",
        severity="INFO",
        title="Chart not signed",
        chart_dir=chart.chart_dir,
        file_path=chart_yaml_path,
        line=1,
        message="Chart has no .prov file. Chart provenance cannot be verified.",
        cwe="CWE-345",
        remediation="Sign the chart with 'helm package --sign' or Cosign",
    )]
