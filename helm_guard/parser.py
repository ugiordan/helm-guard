"""Three-tier parser for Helm charts.

Tier 1: Structured YAML (Chart.yaml, values.yaml, Chart.lock, values.schema.json)
Tier 2: Text/regex heuristics (template files read as raw text)
Tier 3: Rendered output (opt-in via --render, not implemented in v1.0)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


@dataclass
class TemplateFile:
    """A Helm template file with its raw text content."""
    path: str
    content: str


@dataclass
class ChartInfo:
    """Parsed Helm chart data across all tiers."""
    chart_yaml: dict[str, Any]
    values_yaml: dict[str, Any]
    values_schema: dict[str, Any] | None
    chart_lock: dict[str, Any] | None
    template_files: list[TemplateFile]
    has_prov: bool
    chart_dir: str


def _load_yaml(path: Path) -> dict[str, Any] | None:
    """Load a YAML file using round-trip mode to preserve line numbers.

    Returns a ``CommentedMap`` (dict subclass) whose values have ``.lc``
    attributes with source line/column information.  Falls back to an
    empty dict for non-dict documents and ``None`` for missing/broken files.
    """
    if not path.exists() or not path.is_file():
        return None
    yaml = YAML(typ="rt")
    try:
        with open(path) as f:
            data = yaml.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    """Load a JSON file, returning None if it does not exist or fails."""
    if not path.exists() or not path.is_file():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _find_template_files(chart_dir: Path) -> list[TemplateFile]:
    """Find and read all template files (Tier 2: raw text, no YAML parsing)."""
    templates_dir = chart_dir / "templates"
    if not templates_dir.is_dir():
        return []

    result = []
    for ext in ("*.yaml", "*.yml", "*.tpl"):
        for p in sorted(templates_dir.rglob(ext)):
            if p.is_symlink():
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                result.append(TemplateFile(path=str(p), content=content))
            except Exception:
                continue
    return result


def parse_chart_dir(path: str | Path) -> ChartInfo:
    """Parse a Helm chart directory into a ChartInfo dataclass.

    Tier 1: Parse Chart.yaml, values.yaml, Chart.lock, values.schema.json as YAML/JSON.
    Tier 2: Read template files as raw text for regex scanning.
    """
    chart_dir = Path(path)

    chart_yaml = _load_yaml(chart_dir / "Chart.yaml") or {}
    values_yaml = _load_yaml(chart_dir / "values.yaml") or {}
    values_schema = _load_json(chart_dir / "values.schema.json")
    chart_lock = _load_yaml(chart_dir / "Chart.lock")

    template_files = _find_template_files(chart_dir)

    # Check for provenance file (.prov)
    has_prov = False
    if chart_dir.is_dir():
        has_prov = any(
            p.suffix == ".prov"
            for p in chart_dir.iterdir()
            if p.is_file()
        )

    return ChartInfo(
        chart_yaml=chart_yaml,
        values_yaml=values_yaml,
        values_schema=values_schema,
        chart_lock=chart_lock,
        template_files=template_files,
        has_prov=has_prov,
        chart_dir=str(chart_dir),
    )
