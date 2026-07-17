"""Check registry with explicit imports (PyInstaller-compatible)."""

from __future__ import annotations

import logging
from typing import Any

from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo
from helm_guard.checks._common import SEVERITY_ORDER, get_all_checks

logger = logging.getLogger(__name__)

# Explicit imports so PyInstaller bundles all check modules.
from helm_guard.checks import deps  # noqa: F401
from helm_guard.checks import hooks  # noqa: F401
from helm_guard.checks import injection  # noqa: F401
from helm_guard.checks import namespace  # noqa: F401
from helm_guard.checks import olm  # noqa: F401
from helm_guard.checks import pinning  # noqa: F401
from helm_guard.checks import provenance  # noqa: F401
from helm_guard.checks import security  # noqa: F401
from helm_guard.checks import trust  # noqa: F401

_EXPECTED_MIN_CHECKS = 51

_loaded = get_all_checks()
if len(_loaded) < _EXPECTED_MIN_CHECKS:
    logger.warning(
        "Expected at least %d checks but only %d registered. Some check modules may have failed to import.",
        _EXPECTED_MIN_CHECKS, len(_loaded),
    )


def run_checks(
    chart: ChartInfo,
    config: ScannerConfig,
) -> list[dict[str, Any]]:
    """Run all registered checks against a chart."""
    min_sev = SEVERITY_ORDER.get(config.min_severity.upper(), 0)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()

    all_checks = get_all_checks()
    for check_fn in all_checks:
        check_id = getattr(check_fn, "check_id", "")
        if check_id and not config.should_run_check(check_id):
            continue
        for f in check_fn(chart, config):
            if SEVERITY_ORDER.get(f["severity"], 0) < min_sev:
                continue
            dedup_key = (f["rule_id"], f["file"], f.get("line_start", 0), f.get("message", ""))
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(f)

    return findings
