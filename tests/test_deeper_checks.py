"""Tests for deeper checks (INJ-004..007, TRUST-004..006, PIN-005, OLM-004)."""
from pathlib import Path
from helm_guard.checks import run_checks
from helm_guard.config import ScannerConfig
from helm_guard.parser import parse_chart_dir

FIXTURES = Path(__file__).parent / "fixtures"


def _run(chart_name: str, **config_kwargs) -> list[dict]:
    config = ScannerConfig(**config_kwargs)
    chart = parse_chart_dir(FIXTURES / chart_name)
    return run_checks(chart, config)


def _rule_ids(findings):
    return [f["rule_id"] for f in findings]


class TestInjectionDeep:
    def test_lookup_detected(self):
        findings = _run("test-chart")
        assert "HLM-INJ-004" in _rule_ids(findings)

    def test_env_detected(self):
        findings = _run("test-chart")
        assert "HLM-INJ-005" in _rule_ids(findings)

    def test_files_get_with_values(self):
        findings = _run("test-chart")
        assert "HLM-INJ-006" in _rule_ids(findings)

    def test_hardcoded_image(self):
        findings = _run("test-chart")
        inj007 = [f for f in findings if f["rule_id"] == "HLM-INJ-007"]
        assert len(inj007) >= 1
        assert "nginx" in str(inj007[0].get("image", "")) or "nginx" in inj007[0].get("message", "")

    def test_clean_chart_no_injection_deep(self):
        findings = _run("clean-chart")
        deep_checks = [f for f in findings if f["rule_id"] in ("HLM-INJ-004", "HLM-INJ-005", "HLM-INJ-006", "HLM-INJ-007")]
        assert len(deep_checks) == 0


class TestTrustDeep:
    def test_host_network_flagged(self):
        findings = _run("test-chart")
        assert "HLM-TRUST-004" in _rule_ids(findings)

    def test_http_url_flagged(self):
        findings = _run("test-chart")
        assert "HLM-TRUST-005" in _rule_ids(findings)

    def test_clean_chart_no_trust_deep(self):
        findings = _run("clean-chart")
        deep_checks = [f for f in findings if f["rule_id"] in ("HLM-TRUST-004", "HLM-TRUST-005", "HLM-TRUST-006")]
        assert len(deep_checks) == 0


class TestOLMDeep:
    def test_unstable_channel_auto_approval(self):
        findings = _run("test-chart")
        assert "HLM-OLM-004" in _rule_ids(findings)


class TestPinDeep:
    def test_clean_chart_semver_ok(self):
        findings = _run("clean-chart")
        assert "HLM-PIN-005" not in _rule_ids(findings)
