"""Tests for all 10 security checks (positive + negative)."""

from pathlib import Path

from helm_guard.checks import run_checks
from helm_guard.config import ScannerConfig
from helm_guard.parser import parse_chart_dir

FIXTURES = Path(__file__).parent / "fixtures"


def _run(fixture: str, **config_kwargs) -> list[dict]:
    config = ScannerConfig(**config_kwargs)
    chart = parse_chart_dir(FIXTURES / fixture)
    return run_checks(chart, config)


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


# --- Pinning checks ---


class TestPinning:
    def test_pin_001_semver_range_detected(self):
        findings = _run("test-chart")
        assert "HLM-PIN-001" in _rule_ids(findings)
        pin_findings = [f for f in findings if f["rule_id"] == "HLM-PIN-001"]
        assert len(pin_findings) == 2  # redis ~17.0 and postgresql >=12.0.0
        messages = " ".join(f["message"] for f in pin_findings)
        assert "redis" in messages
        assert "postgresql" in messages

    def test_pin_001_no_deps_clean(self):
        findings = _run("clean-chart")
        assert "HLM-PIN-001" not in _rule_ids(findings)

    def test_pin_002_missing_chart_lock(self):
        findings = _run("test-chart")
        assert "HLM-PIN-002" in _rule_ids(findings)

    def test_pin_002_no_deps_no_lock_needed(self):
        findings = _run("clean-chart")
        assert "HLM-PIN-002" not in _rule_ids(findings)

    def test_pin_003_mutable_image_tag(self):
        findings = _run("test-chart")
        assert "HLM-PIN-003" in _rule_ids(findings)
        img_findings = [f for f in findings if f["rule_id"] == "HLM-PIN-003"]
        # Should find: image.repository, image.tag, sidecar.image,
        # anotherService.image.repository, anotherService.image.tag
        assert len(img_findings) >= 3

    def test_pin_003_pinned_image_clean(self):
        findings = _run("clean-chart")
        assert "HLM-PIN-003" not in _rule_ids(findings)

    def test_pin_004_olm_unpinned_channel(self):
        findings = _run("test-chart")
        assert "HLM-PIN-004" in _rule_ids(findings)
        chan_findings = [f for f in findings if f["rule_id"] == "HLM-PIN-004"]
        assert any("stable" in f["message"] for f in chan_findings)

    def test_pin_004_no_channel_clean(self):
        findings = _run("clean-chart")
        assert "HLM-PIN-004" not in _rule_ids(findings)


# --- Injection checks ---


class TestInjection:
    def test_inj_001_tpl_function(self):
        findings = _run("test-chart")
        assert "HLM-INJ-001" in _rule_ids(findings)
        tpl_findings = [f for f in findings if f["rule_id"] == "HLM-INJ-001"]
        assert tpl_findings[0]["severity"] == "CRITICAL"

    def test_inj_001_no_tpl_clean(self):
        findings = _run("clean-chart")
        assert "HLM-INJ-001" not in _rule_ids(findings)

    def test_inj_002_shell_injection(self):
        findings = _run("test-chart")
        assert "HLM-INJ-002" in _rule_ids(findings)
        shell_findings = [f for f in findings if f["rule_id"] == "HLM-INJ-002"]
        assert shell_findings[0]["severity"] == "HIGH"

    def test_inj_002_no_shell_clean(self):
        findings = _run("clean-chart")
        assert "HLM-INJ-002" not in _rule_ids(findings)

    def test_inj_003_name_without_trunc(self):
        findings = _run("test-chart")
        assert "HLM-INJ-003" in _rule_ids(findings)
        name_findings = [f for f in findings if f["rule_id"] == "HLM-INJ-003"]
        assert name_findings[0]["severity"] == "MEDIUM"

    def test_inj_003_name_with_trunc_clean(self):
        findings = _run("clean-chart")
        assert "HLM-INJ-003" not in _rule_ids(findings)


# --- Trust checks ---


class TestTrust:
    def test_trust_001_no_schema(self):
        findings = _run("test-chart")
        assert "HLM-TRUST-001" in _rule_ids(findings)

    def test_trust_001_has_schema_clean(self):
        findings = _run("clean-chart")
        assert "HLM-TRUST-001" not in _rule_ids(findings)

    def test_trust_002_secrets_in_values(self):
        findings = _run("test-chart")
        assert "HLM-TRUST-002" in _rule_ids(findings)
        secret_findings = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
        assert len(secret_findings) == 2  # password and apiKey
        messages = " ".join(f["message"] for f in secret_findings)
        assert "password" in messages.lower() or "apiKey" in messages

    def test_trust_002_empty_secrets_clean(self):
        findings = _run("clean-chart")
        assert "HLM-TRUST-002" not in _rule_ids(findings)

    def test_trust_003_untrusted_repo(self):
        findings = _run("test-chart")
        assert "HLM-TRUST-003" in _rule_ids(findings)
        repo_findings = [f for f in findings if f["rule_id"] == "HLM-TRUST-003"]
        messages = " ".join(f["message"] for f in repo_findings)
        # Both bitnami and evil-corp should be flagged (not in default trusted list)
        assert "bitnami" in messages or "evil-corp" in messages

    def test_trust_003_no_deps_clean(self):
        findings = _run("clean-chart")
        assert "HLM-TRUST-003" not in _rule_ids(findings)


# --- Skip checks config ---


class TestConfig:
    def test_skip_checks(self):
        findings = _run("test-chart", skip_checks=["HLM-PIN-001", "HLM-INJ-001"])
        assert "HLM-PIN-001" not in _rule_ids(findings)
        assert "HLM-INJ-001" not in _rule_ids(findings)
        # Other checks should still fire
        assert "HLM-TRUST-001" in _rule_ids(findings)

    def test_min_severity_filter(self):
        findings = _run("test-chart", min_severity="HIGH")
        for f in findings:
            assert f["severity"] in ("HIGH", "CRITICAL")
