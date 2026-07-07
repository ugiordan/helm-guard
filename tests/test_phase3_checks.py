"""Tests for Phase 3 checks: namespace, dependencies."""

import tempfile
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


# --- Namespace checks ---


class TestNamespaceChecks:
    def test_ns_001_render_mode_stub(self):
        """NS-001 should not fire without rendered data."""
        findings = _run("test-chart-phase3")
        assert "HLM-NS-001" not in _rule_ids(findings)

    def test_ns_002_release_namespace_no_schema(self):
        """NS-002 should fire when templates use .Release.Namespace without schema."""
        findings = _run("test-chart-phase3")
        ns002 = [f for f in findings if f["rule_id"] == "HLM-NS-002"]
        assert len(ns002) >= 1
        assert ns002[0]["severity"] == "MEDIUM"
        assert ".Release.Namespace" in ns002[0]["message"]

    def test_ns_002_with_namespace_schema(self):
        """NS-002 should not fire when schema constrains namespace."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text("replicaCount: 1\n")
            import json
            (Path(td) / "values.schema.json").write_text(json.dumps({
                "$schema": "https://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "enum": ["my-app-ns", "staging-ns"],
                    },
                },
            }))
            templates_dir = Path(td) / "templates"
            templates_dir.mkdir()
            (templates_dir / "deployment.yaml").write_text(
                "metadata:\n  namespace: {{ .Release.Namespace }}\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            assert "HLM-NS-002" not in [f["rule_id"] for f in findings]

    def test_ns_002_no_release_namespace_clean(self):
        """NS-002 should not fire when templates don't use .Release.Namespace."""
        findings = _run("clean-chart")
        assert "HLM-NS-002" not in _rule_ids(findings)


# --- Dependency checks ---


class TestDependencyChecks:
    def test_dep_001_subchart_security_override(self):
        findings = _run("test-chart-phase3")
        dep001 = [f for f in findings if f["rule_id"] == "HLM-DEP-001"]
        assert len(dep001) >= 1
        assert dep001[0]["severity"] == "MEDIUM"
        # Should detect redis.securityContext, redis.serviceAccount, and postgresql.rbac
        messages = " ".join(f["message"] for f in dep001)
        assert "securityContext" in messages or "serviceAccount" in messages or "rbac" in messages

    def test_dep_001_no_deps_clean(self):
        findings = _run("clean-chart")
        assert "HLM-DEP-001" not in _rule_ids(findings)

    def test_dep_001_all_security_fields_detected(self):
        """All known security fields should be detected in subchart overrides."""
        findings = _run("test-chart-phase3")
        dep001 = [f for f in findings if f["rule_id"] == "HLM-DEP-001"]
        messages = " ".join(f["message"] for f in dep001)
        assert "redis" in messages
        assert "postgresql" in messages

    def test_dep_002_version_conflict(self):
        findings = _run("test-chart-phase3")
        dep002 = [f for f in findings if f["rule_id"] == "HLM-DEP-002"]
        assert len(dep002) >= 1
        assert dep002[0]["severity"] == "LOW"
        # postgresql is 12.1.0 in Chart.yaml but 12.2.0 in Chart.lock
        messages = " ".join(f["message"] for f in dep002)
        assert "postgresql" in messages
        assert "12.1.0" in messages
        assert "12.2.0" in messages

    def test_dep_002_matching_versions_clean(self):
        """Redis has matching versions, should not be flagged."""
        findings = _run("test-chart-phase3")
        dep002 = [f for f in findings if f["rule_id"] == "HLM-DEP-002"]
        messages = " ".join(f["message"] for f in dep002)
        # redis version matches (1.2.3 in both), should not be flagged
        assert "redis" not in messages

    def test_dep_002_no_lock_clean(self):
        findings = _run("clean-chart")
        assert "HLM-DEP-002" not in _rule_ids(findings)

    def test_dep_002_range_versions_not_flagged(self):
        """Range versions in Chart.yaml should not be flagged (lock resolves them)."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: redis\n"
                "    version: '~17.0'\n"
                "    repository: 'https://charts.bitnami.com/bitnami'\n"
            )
            (Path(td) / "Chart.lock").write_text(
                "dependencies:\n"
                "  - name: redis\n"
                "    version: '17.3.14'\n"
                "    repository: 'https://charts.bitnami.com/bitnami'\n"
                "digest: sha256:abc123\n"
            )
            (Path(td) / "values.yaml").write_text("replicaCount: 1\n")
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            dep002 = [f for f in findings if f["rule_id"] == "HLM-DEP-002"]
            assert len(dep002) == 0, "Range versions should not be flagged"


# --- New checks (SEC-006, DEP-004, TRUST-007) ---


class TestHelmignoreCheck:
    def test_sec_006_missing_helmignore(self):
        """test-chart has no .helmignore, should fire SEC-006."""
        findings = _run("test-chart")
        sec006 = [f for f in findings if f["rule_id"] == "HLM-SEC-006"]
        assert len(sec006) == 1
        assert sec006[0]["severity"] == "MEDIUM"

    def test_sec_006_present_helmignore_clean(self):
        """clean-chart has .helmignore, should not fire SEC-006."""
        findings = _run("clean-chart")
        assert "HLM-SEC-006" not in _rule_ids(findings)


class TestAliasCheck:
    def test_dep_004_alias_detected(self):
        """test-chart-phase3 has nginx aliased as webserver."""
        findings = _run("test-chart-phase3")
        dep004 = [f for f in findings if f["rule_id"] == "HLM-DEP-004"]
        assert len(dep004) == 1
        assert dep004[0]["severity"] == "LOW"
        assert dep004[0]["name"] == "nginx"
        assert dep004[0]["alias"] == "webserver"

    def test_dep_004_no_alias_clean(self):
        """clean-chart has no dependencies, should not fire DEP-004."""
        findings = _run("clean-chart")
        assert "HLM-DEP-004" not in _rule_ids(findings)

    def test_dep_004_same_name_alias_not_flagged(self):
        """redis dep has no alias, should not fire DEP-004."""
        findings = _run("test-chart-phase3")
        dep004 = [f for f in findings if f["rule_id"] == "HLM-DEP-004"]
        for f in dep004:
            assert f["name"] != "redis"


class TestGlobalSecurityOverride:
    def test_trust_007_global_override_detected(self):
        """test-chart-phase3 has global.securityContext and global.networkPolicy."""
        findings = _run("test-chart-phase3")
        trust007 = [f for f in findings if f["rule_id"] == "HLM-TRUST-007"]
        assert len(trust007) >= 2
        fields = [f["field"] for f in trust007]
        assert "global.securityContext" in fields
        assert "global.networkPolicy" in fields

    def test_trust_007_no_global_clean(self):
        """clean-chart has no global section, should not fire TRUST-007."""
        findings = _run("clean-chart")
        assert "HLM-TRUST-007" not in _rule_ids(findings)
