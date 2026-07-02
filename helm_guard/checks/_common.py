"""Shared helpers for helm-guard checks."""

from __future__ import annotations

from typing import Any, Callable

from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

CheckFn = Callable[[ChartInfo, ScannerConfig], list[dict]]

_REGISTRY: list[CheckFn] = []


def register_check(func: CheckFn) -> CheckFn:
    """Decorator that registers a check function."""
    _REGISTRY.append(func)
    return func


def get_all_checks() -> list[CheckFn]:
    return list(_REGISTRY)


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    chart_dir: str,
    file_path: str,
    line: int,
    message: str,
    *,
    cwe: str = "",
    remediation: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "file": file_path,
        "line_start": line,
        "line_end": line,
        "message": message,
        "chart_dir": chart_dir,
        "cwe": cwe,
        "remediation": remediation,
    }
    if extra:
        result.update(extra)
    return result
