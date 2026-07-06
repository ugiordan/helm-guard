"""Tests for deeper checks (INJ-004..007, TRUST-004..006, PIN-005, OLM-004)."""
import tempfile
from pathlib import Path
from helm_guard.checks import run_checks
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo, TemplateFile, parse_chart_dir

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

    def test_env_dict_not_flagged(self):
        """INJ-005 should not flag 'dict "env"' patterns (false positive)."""
        chart = ChartInfo(
            chart_yaml={},
            values_yaml={},
            values_schema=None,
            chart_lock=None,
            template_files=[
                TemplateFile(
                    path="templates/configmap.yaml",
                    content=(
                        '{{ $envVars := dict "env" (list "VAR1" "VAR2") }}\n'
                    ),
                ),
            ],
            has_prov=False,
            chart_dir="/tmp/test",
        )
        config = ScannerConfig()
        findings = run_checks(chart, config)
        inj005 = [f for f in findings if f["rule_id"] == "HLM-INJ-005"]
        assert len(inj005) == 0, "dict 'env' pattern should not trigger INJ-005"

    def test_expandenv_detected(self):
        """INJ-005 should detect expandenv function calls."""
        chart = ChartInfo(
            chart_yaml={},
            values_yaml={},
            values_schema=None,
            chart_lock=None,
            template_files=[
                TemplateFile(
                    path="templates/test.yaml",
                    content='home: {{ expandenv "$HOME" }}\n',
                ),
            ],
            has_prov=False,
            chart_dir="/tmp/test",
        )
        config = ScannerConfig()
        findings = run_checks(chart, config)
        inj005 = [f for f in findings if f["rule_id"] == "HLM-INJ-005"]
        assert len(inj005) == 1, "expandenv should trigger INJ-005"

    def test_clean_chart_no_injection_deep(self):
        findings = _run("clean-chart")
        deep_checks = [f for f in findings if f["rule_id"] in ("HLM-INJ-004", "HLM-INJ-005", "HLM-INJ-006", "HLM-INJ-007")]
        assert len(deep_checks) == 0


class TestOLMCommunityDepth:
    """OLM-002 depth filter should not suppress shallow community-operators findings."""

    def test_shallow_source_flagged(self):
        """source at depth 1 (e.g. olm.source) should be flagged."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text(
                "olm:\n"
                "  source: community-operators\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            olm002 = [f for f in findings if f["rule_id"] == "HLM-OLM-002"]
            assert len(olm002) >= 1, "Shallow source should be flagged"

    def test_deep_source_suppressed(self):
        """source at depth>2 (e.g. operators.gpu.subscription.source) should be suppressed."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text(
                "operators:\n"
                "  gpu:\n"
                "    subscription:\n"
                "      source: community-operators\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            olm002 = [f for f in findings if f["rule_id"] == "HLM-OLM-002"]
            assert len(olm002) == 0, "Deeply nested source should be suppressed"

    def test_toplevel_source_flagged(self):
        """source at depth 0 (top-level) should be flagged."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text(
                "source: community-operators\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            olm002 = [f for f in findings if f["rule_id"] == "HLM-OLM-002"]
            assert len(olm002) >= 1, "Top-level source should be flagged"


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
