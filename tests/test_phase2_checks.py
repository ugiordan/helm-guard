"""Tests for Phase 2 checks: hooks, OLM, provenance."""

import tempfile
from pathlib import Path

from helm_guard.checks import run_checks
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo, TemplateFile, parse_chart_dir

FIXTURES = Path(__file__).parent / "fixtures"


def _run(fixture: str, **config_kwargs) -> list[dict]:
    config = ScannerConfig(**config_kwargs)
    chart = parse_chart_dir(FIXTURES / fixture)
    return run_checks(chart, config)


def _rule_ids(findings: list[dict]) -> list[str]:
    return [f["rule_id"] for f in findings]


# --- Hook checks ---


class TestHookChecks:
    def test_hook_001_no_security_context(self):
        findings = _run("test-chart-phase2")
        hook001 = [f for f in findings if f["rule_id"] == "HLM-HOOK-001"]
        assert len(hook001) >= 1
        # hook-job.yaml has a hook but no securityContext
        assert any("hook-job.yaml" in f["file"] for f in hook001)

    def test_hook_001_with_security_context_clean(self):
        findings = _run("test-chart-phase2")
        hook001 = [f for f in findings if f["rule_id"] == "HLM-HOOK-001"]
        # hook-clean.yaml has both hook and securityContext, should not be flagged
        assert not any("hook-clean.yaml" in f["file"] for f in hook001)

    def test_hook_001_severity(self):
        findings = _run("test-chart-phase2")
        hook001 = [f for f in findings if f["rule_id"] == "HLM-HOOK-001"]
        assert all(f["severity"] == "HIGH" for f in hook001)

    def test_hook_002_before_creation_delete(self):
        findings = _run("test-chart-phase2")
        hook002 = [f for f in findings if f["rule_id"] == "HLM-HOOK-002"]
        assert len(hook002) >= 1
        assert any("hook-delete.yaml" in f["file"] for f in hook002)
        assert hook002[0]["severity"] == "MEDIUM"

    def test_hook_002_succeeded_policy_clean(self):
        findings = _run("test-chart-phase2")
        hook002 = [f for f in findings if f["rule_id"] == "HLM-HOOK-002"]
        # hook-clean.yaml uses hook-succeeded policy, should NOT be flagged
        assert not any("hook-clean.yaml" in f["file"] for f in hook002)

    def test_hook_001_no_hooks_clean_chart(self):
        findings = _run("clean-chart")
        assert "HLM-HOOK-001" not in _rule_ids(findings)
        assert "HLM-HOOK-002" not in _rule_ids(findings)


# --- OLM checks ---


class TestOLMChecks:
    def test_olm_001_automatic_install_plan(self):
        findings = _run("test-chart-phase2")
        olm001 = [f for f in findings if f["rule_id"] == "HLM-OLM-001"]
        assert len(olm001) >= 1
        assert olm001[0]["severity"] == "HIGH"
        assert "Automatic" in olm001[0]["message"]

    def test_olm_001_clean_chart(self):
        findings = _run("clean-chart")
        assert "HLM-OLM-001" not in _rule_ids(findings)

    def test_olm_001_template_fallback(self):
        """OLM-001 should also detect hardcoded installPlanApproval in templates."""
        chart = ChartInfo(
            chart_yaml={},
            values_yaml={},
            values_schema=None,
            chart_lock=None,
            template_files=[
                TemplateFile(
                    path="templates/subscription.yaml",
                    content=(
                        "apiVersion: operators.coreos.com/v1alpha1\n"
                        "kind: Subscription\n"
                        "spec:\n"
                        "  installPlanApproval: Automatic\n"
                        "  channel: stable\n"
                    ),
                ),
            ],
            has_prov=False,
            chart_dir="/tmp/test",
        )
        config = ScannerConfig()
        findings = run_checks(chart, config)
        olm001 = [f for f in findings if f["rule_id"] == "HLM-OLM-001"]
        assert len(olm001) >= 1

    def test_olm_002_community_catalog(self):
        findings = _run("test-chart-phase2")
        olm002 = [f for f in findings if f["rule_id"] == "HLM-OLM-002"]
        assert len(olm002) >= 1
        assert olm002[0]["severity"] == "MEDIUM"
        assert "community-operators" in olm002[0]["message"]

    def test_olm_002_clean_chart(self):
        findings = _run("clean-chart")
        assert "HLM-OLM-002" not in _rule_ids(findings)

    def test_olm_003_privileged_namespace(self):
        findings = _run("test-chart-phase2")
        olm003 = [f for f in findings if f["rule_id"] == "HLM-OLM-003"]
        assert len(olm003) >= 1
        assert olm003[0]["severity"] == "MEDIUM"
        assert "kube-system" in olm003[0]["message"]

    def test_olm_003_clean_chart(self):
        findings = _run("clean-chart")
        assert "HLM-OLM-003" not in _rule_ids(findings)

    def test_olm_003_custom_privileged_list(self):
        """Custom privileged_namespaces should be respected."""
        findings = _run(
            "test-chart-phase2",
            privileged_namespaces=["custom-ns"],
        )
        olm003 = [f for f in findings if f["rule_id"] == "HLM-OLM-003"]
        # kube-system is not in custom list, so should not be flagged
        assert not any("kube-system" in f["message"] for f in olm003)


# --- Provenance checks ---


class TestProvenanceChecks:
    def test_prov_001_no_prov_file(self):
        # PROV-001 is disabled by default. Run with empty skip list.
        # PROV-001 is INFO severity, so we need min_severity=INFO to see it.
        findings = _run("test-chart-phase2", skip_checks=[], min_severity="INFO")
        prov001 = [f for f in findings if f["rule_id"] == "HLM-PROV-001"]
        assert len(prov001) == 1
        assert prov001[0]["severity"] == "INFO"

    def test_prov_001_disabled_by_default(self):
        findings = _run("test-chart-phase2")
        assert "HLM-PROV-001" not in _rule_ids(findings)

    def test_prov_001_with_prov_file(self):
        """Chart with .prov file should not trigger PROV-001."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: signed\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text("replicaCount: 1\n")
            (Path(td) / "signed-1.0.0.tgz.prov").write_text("provenance data")
            chart = parse_chart_dir(td)
            config = ScannerConfig(skip_checks=[])
            findings = run_checks(chart, config)
            assert "HLM-PROV-001" not in [f["rule_id"] for f in findings]
