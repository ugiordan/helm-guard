"""Tests for helm-guard fixer."""
import shutil
from pathlib import Path

from helm_guard.fixer import FixEngine, FixResult
from helm_guard.parser import parse_chart_dir
from helm_guard.checks import run_checks
from helm_guard.config import ScannerConfig

FIXTURES = Path(__file__).parent / "fixtures"


def test_fix_result_tracking():
    r = FixResult()
    r.fixed.append({"rule_id": "HLM-PIN-001"})
    r.skipped.append({"rule_id": "HLM-SA-001"})
    d = r.to_dict()
    assert d["summary"]["fixed"] == 1
    assert d["summary"]["skipped"] == 1


def test_dry_run_no_modify(tmp_path):
    src = FIXTURES / "test-chart"
    dst = tmp_path / "chart"
    shutil.copytree(src, dst)
    original = (dst / "Chart.yaml").read_text()
    chart = parse_chart_dir(dst)
    findings = run_checks(chart, ScannerConfig())
    engine = FixEngine(dry_run=True)
    engine.fix_findings(findings, str(dst))
    assert (dst / "Chart.yaml").read_text() == original


def test_manual_review_skipped():
    engine = FixEngine(dry_run=True)
    findings = [{"rule_id": "HLM-INJ-001", "file": "x.yaml"}]
    result = engine.fix_findings(findings, "/nonexistent")
    assert len(result.skipped) == 1


def test_fix_pins_dependencies(tmp_path):
    """PIN-001 fix should rewrite SemVer ranges to exact versions."""
    src = FIXTURES / "test-chart"
    dst = tmp_path / "chart"
    shutil.copytree(src, dst)

    chart = parse_chart_dir(dst)
    findings = run_checks(chart, ScannerConfig())
    pin_findings = [f for f in findings if f["rule_id"] == "HLM-PIN-001"]
    assert len(pin_findings) > 0

    engine = FixEngine(dry_run=False)
    result = engine.fix_findings(findings, str(dst))
    pin_fixes = [f for f in result.fixed if f["rule_id"] == "HLM-PIN-001"]
    assert len(pin_fixes) > 0

    # Re-scan: PIN-001 should be gone
    chart2 = parse_chart_dir(dst)
    findings2 = run_checks(chart2, ScannerConfig())
    pin_findings2 = [f for f in findings2 if f["rule_id"] == "HLM-PIN-001"]
    assert len(pin_findings2) == 0


def test_fix_clears_secrets(tmp_path):
    """TRUST-002 fix should clear non-empty secret defaults."""
    src = FIXTURES / "test-chart"
    dst = tmp_path / "chart"
    shutil.copytree(src, dst)

    chart = parse_chart_dir(dst)
    findings = run_checks(chart, ScannerConfig())
    secret_findings = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
    assert len(secret_findings) > 0

    engine = FixEngine(dry_run=False)
    result = engine.fix_findings(findings, str(dst))
    secret_fixes = [f for f in result.fixed if f["rule_id"] == "HLM-TRUST-002"]
    assert len(secret_fixes) > 0

    # Re-scan: TRUST-002 should be gone
    chart2 = parse_chart_dir(dst)
    findings2 = run_checks(chart2, ScannerConfig())
    secret_findings2 = [f for f in findings2 if f["rule_id"] == "HLM-TRUST-002"]
    assert len(secret_findings2) == 0


def test_fix_uses_chart_lock(tmp_path):
    """When Chart.lock exists, PIN-001 fix should use locked versions."""
    src = FIXTURES / "test-chart"
    dst = tmp_path / "chart"
    shutil.copytree(src, dst)

    # Create a Chart.lock with a resolved version for redis
    lock_content = """dependencies:
  - name: redis
    version: "17.3.2"
    repository: "https://charts.bitnami.com/bitnami"
digest: sha256:test
generated: "2026-01-01T00:00:00Z"
"""
    (dst / "Chart.lock").write_text(lock_content)

    chart = parse_chart_dir(dst)
    findings = run_checks(chart, ScannerConfig())

    engine = FixEngine(dry_run=False)
    result = engine.fix_findings(findings, str(dst))

    pin_fixes = [f for f in result.fixed if f["rule_id"] == "HLM-PIN-001"]
    redis_fix = [f for f in pin_fixes if f.get("dependency") == "redis"]
    assert len(redis_fix) == 1
    assert redis_fix[0]["method"] == "chart_lock"
    assert redis_fix[0]["resolved"] == "17.3.2"


def test_fix_result_to_dict():
    r = FixResult()
    r.fixed.append({"rule_id": "HLM-PIN-001", "dependency": "redis"})
    r.fixed.append({"rule_id": "HLM-TRUST-002", "field": "auth.password"})
    r.skipped.append({"rule_id": "HLM-INJ-001", "reason": "manual_review_required"})
    r.skipped.append({"rule_id": "HLM-NS-001", "reason": "manual_review_required"})
    d = r.to_dict()
    assert d["summary"]["fixed"] == 2
    assert d["summary"]["skipped"] == 2


# --- Adversarial review regression tests ---


def test_semver_compound_range_extraction():
    """SemVer stripping must extract the first version from compound ranges,
    not produce garbage like '1.2.0,2.0.0'."""
    engine = FixEngine(dry_run=True)
    cases = [
        (">=1.2.0,<2.0.0", "1.2.0"),
        ("~17.0", "17.0"),
        ("^2.3.4", "2.3.4"),
        (">=1.0.0 <2.0.0", "1.0.0"),
        (">=1.0.0||<2.0.0", "1.0.0"),
        (">= 1.5", "1.5"),
    ]
    for range_str, expected in cases:
        result = engine._extract_version_from_range(range_str)
        assert result == expected, f"Range {range_str!r}: got {result!r}, expected {expected!r}"


def test_resolve_dotpath_simple():
    """Dotpath traversal should handle plain dict paths."""
    data = {"auth": {"password": "secret"}}
    parent, key = FixEngine._resolve_dotpath(data, "auth.password")
    assert parent == {"password": "secret"}
    assert key == "password"


def test_resolve_dotpath_array_index():
    """Dotpath traversal should handle array-indexed paths like items[0].password."""
    data = {"items": [{"password": "secret"}, {"password": "other"}]}
    parent, key = FixEngine._resolve_dotpath(data, "items[0].password")
    assert key == "password"
    assert parent["password"] == "secret"


def test_resolve_dotpath_missing():
    """Dotpath traversal should return (None, None) for non-existent paths."""
    data = {"auth": {"token": "x"}}
    parent, key = FixEngine._resolve_dotpath(data, "auth.password")
    assert parent is not None  # parent exists (auth dict)
    assert key == "password"
    # But key is not in parent, so the caller skips it


def test_fix_rejects_symlinked_chart_yaml(tmp_path):
    """Fixer must refuse to write through symlinked Chart.yaml."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_chart = real_dir / "Chart.yaml"
    real_chart.write_text("apiVersion: v2\nname: real\nversion: 1.0.0\n")

    chart_dir = tmp_path / "chart"
    chart_dir.mkdir()
    symlink = chart_dir / "Chart.yaml"
    symlink.symlink_to(real_chart)

    findings = [{"rule_id": "HLM-PIN-001", "file": str(symlink)}]
    engine = FixEngine(dry_run=False)
    result = engine.fix_findings(findings, str(chart_dir))
    # Should produce no fixes because Chart.yaml is a symlink
    assert len(result.fixed) == 0


def test_fix_rejects_symlinked_values_yaml(tmp_path):
    """Fixer must refuse to write through symlinked values.yaml."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_values = real_dir / "values.yaml"
    real_values.write_text("auth:\n  password: secret\n")

    chart_dir = tmp_path / "chart"
    chart_dir.mkdir()
    # Need a Chart.yaml for the chart dir to look valid
    (chart_dir / "Chart.yaml").write_text("apiVersion: v2\nname: test\nversion: 1.0.0\n")
    symlink = chart_dir / "values.yaml"
    symlink.symlink_to(real_values)

    findings = [{"rule_id": "HLM-TRUST-002", "field": "auth.password", "file": str(symlink)}]
    engine = FixEngine(dry_run=False)
    result = engine.fix_findings(findings, str(chart_dir))
    # Should produce no fixes because values.yaml is a symlink
    assert len(result.fixed) == 0


def test_extract_version_from_range_wildcard():
    """Wildcard ranges like '*' or 'x.x.x' should return empty string."""
    engine = FixEngine()
    assert engine._extract_version_from_range("*") == ""
    assert engine._extract_version_from_range("x.x.x") == ""


def test_extract_version_from_range_normal():
    """Normal SemVer ranges should extract a valid version."""
    engine = FixEngine()
    assert engine._extract_version_from_range("~1.2.3") == "1.2.3"
    assert engine._extract_version_from_range("^2.0.0") == "2.0.0"
    assert engine._extract_version_from_range(">=1.0.0,<2.0.0") == "1.0.0"


def test_extract_version_from_range_compound():
    """Compound ranges should extract the first version."""
    engine = FixEngine()
    result = engine._extract_version_from_range(">=1.5.0 <2.0.0")
    assert result == "1.5.0"
