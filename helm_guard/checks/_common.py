"""Shared helpers for helm-guard checks."""

from __future__ import annotations

from typing import Any, Callable

from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def yaml_key_line(data: Any, key: str) -> int:
    """Return the 1-based source line for *key* inside a ruamel.yaml CommentedMap.

    Falls back to 1 when line info is unavailable (e.g. data loaded with
    ``typ="safe"`` or the key is missing).
    """
    try:
        # CommentedMap stores (line, col) in data.lc.key(key)
        return data.lc.key(key)[0] + 1  # lc lines are 0-based
    except Exception:
        return 1

CheckFn = Callable[[ChartInfo, ScannerConfig], list[dict]]

_REGISTRY: list[CheckFn] = []


def register_check(func: CheckFn) -> CheckFn:
    """Decorator that registers a check function.

    Extracts the check ID (e.g. "HLM-PIN-001") from the docstring at
    registration time and caches it as ``func.check_id``.  If the
    docstring is missing or malformed the attribute is set to ``""``.
    """
    doc = func.__doc__ or ""
    colon_pos = doc.find(":")
    func.check_id = doc[:colon_pos].strip() if colon_pos > 0 else ""  # type: ignore[attr-defined]
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
