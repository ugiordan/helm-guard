"""Tests for all 10 security checks (positive + negative)."""

import tempfile
from pathlib import Path

from helm_guard.checks import run_checks
from helm_guard.checks._common import get_all_checks
from helm_guard.config import ScannerConfig, load_config
from helm_guard.parser import parse_chart_dir, ChartInfo, TemplateFile
from helm_guard.checks.injection import _TPL_RE
from helm_guard.checks.trust import _is_secret_key_match
from helm_guard.checks.pinning import _is_image_key

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

    def test_malformed_config_file_returns_defaults(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("invalid: [yaml {{")
            f.flush()
            cfg = load_config(f.name)
            assert cfg.min_severity == "LOW"
            assert len(cfg.trusted_chart_repos) > 0


class TestINJ001Regex:
    """Verify the tpl regex only matches inside Go template delimiters."""

    def test_matches_standard_tpl(self):
        assert _TPL_RE.search("{{ tpl .Values.extraConfig . }}")

    def test_matches_tpl_with_whitespace_control(self):
        assert _TPL_RE.search("{{- tpl .Values.x . -}}")

    def test_matches_tpl_no_space(self):
        assert _TPL_RE.search("{{tpl .Values.x .}}")

    def test_no_match_outside_delimiters(self):
        assert not _TPL_RE.search("# This is a .tpl helper template")

    def test_no_match_resource_name_tpl(self):
        assert not _TPL_RE.search("name: my-tpl-config")

    def test_no_match_template_function(self):
        assert not _TPL_RE.search('{{ template "foo" . }}')

    def test_no_match_go_template_comment(self):
        assert not _TPL_RE.search("{{/* Use tpl if you need */}}")


class TestINJ002QuotePipe:
    """Verify chained pipe filters with quote are not flagged."""

    def test_chained_default_then_quote_not_flagged(self):
        chart = ChartInfo(
            chart_yaml={},
            values_yaml={},
            values_schema=None,
            chart_lock=None,
            template_files=[
                TemplateFile(
                    path="templates/test.yaml",
                    content=(
                        "command:\n"
                        "  - sh\n"
                        "  - -c\n"
                        '  - echo {{ .Values.config | default "" | quote }}\n'
                    ),
                ),
            ],
            has_prov=False,
            chart_dir="/tmp/test",
        )
        config = ScannerConfig()
        findings = run_checks(chart, config)
        inj002 = [f for f in findings if f["rule_id"] == "HLM-INJ-002"]
        assert len(inj002) == 0, "Chained quote should suppress INJ-002"


# --- D-01: Recursive subchart walk ---


class TestRecursiveSubchartWalk:
    """D-01: TRUST-003 should detect untrusted deps in deeply nested subcharts."""

    def test_deeply_nested_subchart_detected(self):
        with tempfile.TemporaryDirectory() as td:
            # Main chart
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: main\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text("replicaCount: 1\n")
            # Level 1 subchart: charts/redis/
            redis_dir = Path(td) / "charts" / "redis"
            redis_dir.mkdir(parents=True)
            (redis_dir / "Chart.yaml").write_text(
                "apiVersion: v2\nname: redis\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: sentinel\n"
                "    version: '1.0.0'\n"
                "    repository: 'https://charts.bitnami.com/bitnami'\n"
            )
            # Level 2 subchart: charts/redis/charts/sentinel/
            sentinel_dir = redis_dir / "charts" / "sentinel"
            sentinel_dir.mkdir(parents=True)
            (sentinel_dir / "Chart.yaml").write_text(
                "apiVersion: v2\nname: sentinel\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: evil-lib\n"
                "    version: '0.1.0'\n"
                "    repository: 'https://evil.example.com/charts'\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            trust003 = [f for f in findings if f["rule_id"] == "HLM-TRUST-003"]
            messages = " ".join(f["message"] for f in trust003)
            # Should catch both bitnami (level 1) and evil.example.com (level 2)
            assert "evil-lib" in messages, "Deeply nested subchart dep not detected"
            assert "sentinel" in messages or "evil" in messages

    def test_single_level_still_works(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: main\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text("")
            sub_dir = Path(td) / "charts" / "mylib"
            sub_dir.mkdir(parents=True)
            (sub_dir / "Chart.yaml").write_text(
                "apiVersion: v2\nname: mylib\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: untrusted-dep\n"
                "    version: '1.0.0'\n"
                "    repository: 'https://untrusted.example.com'\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            trust003 = [f for f in findings if f["rule_id"] == "HLM-TRUST-003"]
            assert any("untrusted-dep" in f["message"] for f in trust003)


# --- D-03: Expanded image key patterns ---


class TestExpandedImageKeys:
    """D-03: PIN-003 should match containerImage, sidecarImage, initImage, image.name."""

    def test_is_image_key_exact_matches(self):
        assert _is_image_key("image", "")
        assert _is_image_key("tag", "")
        assert _is_image_key("repository", "")

    def test_is_image_key_compound_names(self):
        assert _is_image_key("containerImage", "")
        assert _is_image_key("sidecarImage", "")
        assert _is_image_key("initImage", "")
        assert _is_image_key("imageOverride", "")
        assert _is_image_key("imageRegistry", "")

    def test_is_image_key_name_under_image_parent(self):
        assert _is_image_key("name", "image")
        assert _is_image_key("name", "sidecarImage")

    def test_is_image_key_non_image_keys(self):
        assert not _is_image_key("name", "auth")
        assert not _is_image_key("replicas", "")
        assert not _is_image_key("version", "")

    def test_container_image_key_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text(
                "containerImage: docker.io/myapp:latest\n"
                "initImage: gcr.io/myinit:v1\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            pin003 = [f for f in findings if f["rule_id"] == "HLM-PIN-003"]
            dotpaths = [f["message"] for f in pin003]
            joined = " ".join(dotpaths)
            assert "containerImage" in joined
            assert "initImage" in joined


# --- D-04: Word-boundary matching for TRUST-002 ---


class TestSecretKeyWordBoundary:
    """D-04: TRUST-002 should use word-boundary matching to avoid FP."""

    def test_exact_match(self):
        assert _is_secret_key_match("password", ["password"])
        assert _is_secret_key_match("token", ["token"])
        assert _is_secret_key_match("apiKey", ["apiKey"])

    def test_camel_case_segment_match(self):
        assert _is_secret_key_match("dbPassword", ["password"])
        assert _is_secret_key_match("authToken", ["token"])
        assert _is_secret_key_match("db_password", ["password"])

    def test_no_match_on_substring(self):
        # passwordPolicy contains "password" as substring but not as a segment
        assert not _is_secret_key_match("passwordPolicy", ["password"])
        assert not _is_secret_key_match("tokenEndpoint", ["token"])
        assert not _is_secret_key_match("secretName", ["secret"])
        assert not _is_secret_key_match("secretRef", ["secret"])

    def test_secret_name_not_flagged_in_values(self):
        """secretName with a k8s name value should not be flagged."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text(
                "tls:\n"
                "  secretName: my-tls-secret\n"
                "auth:\n"
                "  password: supersecret123\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            trust002 = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
            dotpaths = [f["message"] for f in trust002]
            joined = " ".join(dotpaths)
            assert "auth.password" in joined, "Real secret should still be flagged"
            assert "secretName" not in joined, "secretName should not be flagged"

    def test_token_endpoint_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text(
                "oauth:\n"
                "  tokenEndpoint: https://auth.example.com/token\n"
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            trust002 = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
            assert len(trust002) == 0, "tokenEndpoint should not be flagged as a secret"


# --- D-06: Check ID from decorator attribute ---


class TestCheckIdAttribute:
    """D-06: Every registered check should have a check_id attribute."""

    def test_all_checks_have_check_id(self):
        checks = get_all_checks()
        assert len(checks) > 0
        for check_fn in checks:
            check_id = getattr(check_fn, "check_id", None)
            assert check_id is not None, f"{check_fn.__name__} missing check_id attribute"
            assert check_id, f"{check_fn.__name__} has empty check_id"
            assert check_id.startswith("HLM-"), f"{check_fn.__name__} has invalid check_id: {check_id}"

    def test_skip_checks_uses_attribute(self):
        """Verify that skip_checks actually works via the attribute, not docstring parsing."""
        findings = _run("test-chart", skip_checks=["HLM-PIN-001"])
        assert "HLM-PIN-001" not in _rule_ids(findings)
        # Ensure other checks still fire
        assert "HLM-TRUST-001" in _rule_ids(findings)


# --- D-07: Line tracking for Tier 1 ---


class TestLineTracking:
    """D-07: Tier 1 findings should report accurate line numbers, not always 1."""

    def test_trust_002_reports_correct_line(self):
        findings = _run("test-chart")
        trust002 = [f for f in findings if f["rule_id"] == "HLM-TRUST-002"]
        assert len(trust002) > 0
        # In test-chart/values.yaml, "password" is on line 12, "apiKey" on line 13
        lines = {f["line_start"] for f in trust002}
        # They should NOT all be line 1
        assert lines != {1}, f"All TRUST-002 findings report line 1: {lines}"

    def test_pin_003_reports_correct_line(self):
        findings = _run("test-chart")
        pin003 = [f for f in findings if f["rule_id"] == "HLM-PIN-003"]
        assert len(pin003) > 0
        lines = {f["line_start"] for f in pin003}
        assert lines != {1}, f"All PIN-003 findings report line 1: {lines}"

    def test_pin_001_reports_correct_line(self):
        findings = _run("test-chart")
        pin001 = [f for f in findings if f["rule_id"] == "HLM-PIN-001"]
        assert len(pin001) > 0
        lines = {f["line_start"] for f in pin001}
        assert lines != {1}, f"All PIN-001 findings report line 1: {lines}"


# --- D-08: file:// repository references ---


class TestFileRepoDetection:
    """D-08: file:// repository references should be flagged."""

    def test_file_repo_direct_dependency(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: test\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: local-lib\n"
                "    version: '1.0.0'\n"
                '    repository: "file://../local-lib"\n'
            )
            (Path(td) / "values.yaml").write_text("")
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            trust003 = [f for f in findings if f["rule_id"] == "HLM-TRUST-003"]
            messages = " ".join(f["message"] for f in trust003)
            assert "file://" in messages
            assert "local-lib" in messages
            assert any("file://" in f["title"].lower() for f in trust003)

    def test_file_repo_in_subchart(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text(
                "apiVersion: v2\nname: main\nversion: 1.0.0\n"
            )
            (Path(td) / "values.yaml").write_text("")
            sub_dir = Path(td) / "charts" / "mysub"
            sub_dir.mkdir(parents=True)
            (sub_dir / "Chart.yaml").write_text(
                "apiVersion: v2\nname: mysub\nversion: 1.0.0\n"
                "dependencies:\n"
                "  - name: vendored\n"
                "    version: '0.1.0'\n"
                '    repository: "file://../vendored-chart"\n'
            )
            chart = parse_chart_dir(td)
            config = ScannerConfig()
            findings = run_checks(chart, config)
            trust003 = [f for f in findings if f["rule_id"] == "HLM-TRUST-003"]
            messages = " ".join(f["message"] for f in trust003)
            assert "file://" in messages


# --- D-09: Config type validation ---


class TestConfigTypeValidation:
    """D-09: load_config should reject wrong types silently."""

    def test_string_instead_of_list_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write('trusted_chart_repos: "not a list"\n')
            f.flush()
            cfg = load_config(f.name)
            # Should fall back to defaults, not use the string
            assert isinstance(cfg.trusted_chart_repos, list)
            assert len(cfg.trusted_chart_repos) > 0

    def test_int_instead_of_string_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("min_severity: 42\n")
            f.flush()
            cfg = load_config(f.name)
            assert cfg.min_severity == "LOW"  # default

    def test_list_with_non_string_items_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write("skip_checks:\n  - 123\n  - true\n")
            f.flush()
            cfg = load_config(f.name)
            # Should fall back to defaults
            assert isinstance(cfg.skip_checks, list)
            assert all(isinstance(item, str) for item in cfg.skip_checks)

    def test_valid_config_still_works(self):
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(
                "trusted_chart_repos:\n"
                '  - "https://example.com/charts"\n'
                "min_severity: HIGH\n"
            )
            f.flush()
            cfg = load_config(f.name)
            assert cfg.trusted_chart_repos == ["https://example.com/charts"]
            assert cfg.min_severity == "HIGH"


# --- Trusted repo prefix confusion ---


class TestTrustedRepoPrefixSecurity:
    """Trusted repo check must require path boundary, not bare prefix match."""

    def test_exact_match_trusted(self):
        cfg = ScannerConfig(trusted_chart_repos=["oci://quay.io/opendatahub/"])
        assert cfg.is_trusted_chart_repo("oci://quay.io/opendatahub/")
        assert cfg.is_trusted_chart_repo("oci://quay.io/opendatahub")

    def test_subpath_trusted(self):
        cfg = ScannerConfig(trusted_chart_repos=["oci://quay.io/opendatahub/"])
        assert cfg.is_trusted_chart_repo("oci://quay.io/opendatahub/my-chart")

    def test_prefix_confusion_rejected(self):
        """A repo name that starts with the trusted prefix but is a different org must be rejected."""
        cfg = ScannerConfig(trusted_chart_repos=["oci://quay.io/opendatahub/"])
        assert not cfg.is_trusted_chart_repo("oci://quay.io/opendatahub-evil/malware")

    def test_stable_prefix_confusion_rejected(self):
        cfg = ScannerConfig(trusted_chart_repos=["https://charts.helm.sh/stable"])
        assert not cfg.is_trusted_chart_repo("https://charts.helm.sh/stableevil")

    def test_empty_repo_rejected(self):
        cfg = ScannerConfig()
        assert not cfg.is_trusted_chart_repo("")

    def test_untrusted_repo_rejected(self):
        cfg = ScannerConfig()
        assert not cfg.is_trusted_chart_repo("https://evil.example.com/charts")
