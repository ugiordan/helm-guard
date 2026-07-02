# Development Setup

## Clone and install

```bash
git clone https://github.com/ugiordan/helm-guard.git
cd helm-guard
pip install -e .
```

## Run tests

```bash
PYTHONPATH=. pytest tests/ -v
```

## Lint

```bash
ruff check helm_guard/
```

## Adding a new check

1. Create or edit a check module in `helm_guard/checks/`
2. Use the `@register_check` decorator
3. Start the docstring with the check ID and colon (e.g., `"""HLM-XXX-001: Description."""`)
4. Return a list of findings using the `_finding()` helper
5. Add test fixtures in `tests/fixtures/`
6. Add tests in `tests/`
7. Update `_EXPECTED_MIN_CHECKS` in `helm_guard/checks/__init__.py`

### Check function template

```python
from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo


@register_check
def check_my_new_check(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-XXX-001: Description of the check."""
    findings = []
    # ... detection logic ...
    if detected:
        findings.append(_finding(
            rule_id="HLM-XXX-001",
            severity="HIGH",
            title="Short title",
            chart_dir=chart.chart_dir,
            file_path="...",
            line=1,
            message="What was found and why it matters.",
            cwe="CWE-NNN",
            remediation="How to fix it",
        ))
    return findings
```

## Project structure

```
helm_guard/          # Source code
tests/               # Test files
tests/fixtures/      # Chart fixtures for testing
site/                # MkDocs documentation site
```
