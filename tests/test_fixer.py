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
