"""Tests for CVE-based security checks."""
from pathlib import Path

from helm_guard.checks import run_checks
from helm_guard.config import ScannerConfig
from helm_guard.parser import parse_chart_dir

FIXTURES = Path(__file__).parent / "fixtures"


def _run(chart_name, **config_kwargs):
    config = ScannerConfig(**config_kwargs)
    chart = parse_chart_dir(FIXTURES / chart_name)
    return run_checks(chart, config)


def _rule_ids(findings):
    return [f["rule_id"] for f in findings]


class TestPathTraversal:
    def test_chart_name_traversal_detected(self):
        findings = _run("cve-chart")
        assert "HLM-SEC-001" in _rule_ids(findings)
        sec001 = [f for f in findings if f["rule_id"] == "HLM-SEC-001"]
        assert ".." in sec001[0].get("name", "")

    def test_clean_chart_no_traversal(self):
        findings = _run("clean-chart")
        assert "HLM-SEC-001" not in _rule_ids(findings)


class TestSymlinkLock:
    def test_symlinked_chart_lock_detected(self):
        findings = _run("symlink-chart")
        assert "HLM-SEC-002" in _rule_ids(findings)
        sec002 = [f for f in findings if f["rule_id"] == "HLM-SEC-002"]
        assert sec002[0]["severity"] == "CRITICAL"

    def test_clean_chart_no_symlink(self):
        findings = _run("clean-chart")
        assert "HLM-SEC-002" not in _rule_ids(findings)


class TestDNSExfiltration:
    def test_gethostbyname_detected(self):
        findings = _run("cve-chart")
        assert "HLM-INJ-008" in _rule_ids(findings)

    def test_clean_chart_no_dns(self):
        findings = _run("clean-chart")
        assert "HLM-INJ-008" not in _rule_ids(findings)


class TestValueFilesTraversal:
    def test_absolute_path_valuefiles(self):
        findings = _run("cve-chart")
        sec003 = [f for f in findings if f["rule_id"] == "HLM-SEC-003"]
        assert len(sec003) >= 1

    def test_clean_chart_no_valuefiles_issue(self):
        findings = _run("clean-chart")
        assert "HLM-SEC-003" not in _rule_ids(findings)


class TestSATokenMount:
    def test_sa_without_automount_false(self):
        findings = _run("cve-chart")
        assert "HLM-SEC-005" in _rule_ids(findings)

    def test_clean_chart_sa_ok(self):
        findings = _run("clean-chart")
        assert "HLM-SEC-005" not in _rule_ids(findings)


class TestPostRenderer:
    def test_post_renderer_detected(self):
        findings = _run("cve-chart")
        assert "HLM-HOOK-003" in _rule_ids(findings)

    def test_clean_chart_no_post_renderer(self):
        findings = _run("clean-chart")
        assert "HLM-HOOK-003" not in _rule_ids(findings)


class TestTyposquatting:
    def test_similar_name_flagged(self):
        findings = _run("cve-chart")
        dep003 = [f for f in findings if f["rule_id"] == "HLM-DEP-003"]
        assert len(dep003) >= 1
        # Should flag ngnix (similar to nginx) or reddis (similar to redis)
        names = [f.get("dep_name", "") for f in dep003]
        assert "ngnix" in names or "reddis" in names

    def test_exact_name_not_flagged(self):
        """A dependency named exactly 'nginx' should not trigger typosquatting."""
        findings = _run("clean-chart")
        assert "HLM-DEP-003" not in _rule_ids(findings)


class TestEdgeCases:
    def test_empty_chart_yaml_no_crash(self):
        """Chart with minimal content shouldn't crash on any new check."""
        findings = _run("clean-chart")
        # Should produce zero SEC findings
        sec = [f for f in findings if f["rule_id"].startswith("HLM-SEC")]
        assert len(sec) == 0

    def test_all_new_checks_registered(self):
        """Verify all 8 new checks are registered."""
        from helm_guard.checks._common import get_all_checks
        check_ids = [getattr(c, "check_id", "") for c in get_all_checks()]
        new_ids = [
            "HLM-SEC-001", "HLM-SEC-002", "HLM-SEC-003", "HLM-SEC-004",
            "HLM-SEC-005", "HLM-INJ-008", "HLM-HOOK-003", "HLM-DEP-003",
        ]
        for cid in new_ids:
            assert cid in check_ids, f"{cid} not registered"
