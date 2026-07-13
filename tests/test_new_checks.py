"""Tests for the 10 new checks: SEC-007..014, PIN-006, INJ-009.

Each check has one positive test (should fire) and one negative test (should NOT fire).
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo, TemplateFile, parse_chart_dir

FIXTURES = Path(__file__).parent / "fixtures"
POSITIVE_CHART = str(FIXTURES / "new-checks-chart")
CLEAN_CHART = str(FIXTURES / "clean-new-checks-chart")


def _make_chart(
    templates: list[TemplateFile] | None = None,
    values: dict | None = None,
    schema: dict | None = None,
    chart_yaml: dict | None = None,
    tmpdir: str | None = None,
) -> ChartInfo:
    """Build a minimal ChartInfo for unit testing."""
    d = tmpdir or tempfile.mkdtemp()
    return ChartInfo(
        chart_yaml=chart_yaml or {"apiVersion": "v2", "name": "test", "version": "1.0.0"},
        values_yaml=values or {},
        values_schema=schema,
        chart_lock=None,
        template_files=templates or [],
        has_prov=False,
        chart_dir=d,
    )


def _tmpl(content: str, name: str = "test.yaml") -> TemplateFile:
    return TemplateFile(path=name, content=content)


def _run_check(check_fn, chart: ChartInfo) -> list[dict]:
    return check_fn(chart, ScannerConfig())


def _ids(findings: list[dict]) -> set[str]:
    return {f["rule_id"] for f in findings}


# ---------------------------------------------------------------------------
# SEC-007: Wildcard RBAC
# ---------------------------------------------------------------------------
class TestSEC007:
    def test_positive_wildcard_rbac(self):
        from helm_guard.checks.security import check_sec_007
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: ClusterRole\n"
            "metadata:\n"
            "  name: admin\n"
            "rules:\n"
            '  - apiGroups:\n'
            '      - "*"\n'
            '    resources:\n'
            '      - "*"\n'
            '    verbs:\n'
            '      - "*"\n'
        )])
        findings = _run_check(check_sec_007, chart)
        assert any(f["rule_id"] == "HLM-SEC-007" for f in findings)

    def test_negative_specific_rbac(self):
        from helm_guard.checks.security import check_sec_007
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: Role\n"
            "metadata:\n"
            "  name: reader\n"
            "rules:\n"
            '  - apiGroups:\n'
            '      - ""\n'
            '    resources:\n'
            '      - pods\n'
            '    verbs:\n'
            '      - get\n'
            '      - list\n'
        )])
        findings = _run_check(check_sec_007, chart)
        assert not any(f["rule_id"] == "HLM-SEC-007" for f in findings)

    def test_fp_guard_not_rbac_kind(self):
        """Wildcard in a non-RBAC document should not fire."""
        from helm_guard.checks.security import check_sec_007
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            "  name: config\n"
            "data:\n"
            '  selector: "*"\n'
        )])
        findings = _run_check(check_sec_007, chart)
        assert not any(f["rule_id"] == "HLM-SEC-007" for f in findings)


# ---------------------------------------------------------------------------
# SEC-008: hostPath volumes
# ---------------------------------------------------------------------------
class TestSEC008:
    def test_positive_hostpath(self):
        from helm_guard.checks.security import check_sec_008
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      volumes:\n"
            "        - name: data\n"
            "          hostPath:\n"
            "            path: /var/data\n"
        )])
        findings = _run_check(check_sec_008, chart)
        assert any(f["rule_id"] == "HLM-SEC-008" for f in findings)

    def test_negative_no_hostpath(self):
        from helm_guard.checks.security import check_sec_008
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      volumes:\n"
            "        - name: data\n"
            "          emptyDir: {}\n"
        )])
        findings = _run_check(check_sec_008, chart)
        assert not any(f["rule_id"] == "HLM-SEC-008" for f in findings)

    def test_fp_guard_non_workload_kind(self):
        """hostPath in a ConfigMap-like document should not fire."""
        from helm_guard.checks.security import check_sec_008
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "data:\n"
            "  hostPath:\n"
            "    path: /var/data\n"
        )])
        findings = _run_check(check_sec_008, chart)
        assert not any(f["rule_id"] == "HLM-SEC-008" for f in findings)


# ---------------------------------------------------------------------------
# SEC-009: Dangerous capabilities
# ---------------------------------------------------------------------------
class TestSEC009:
    def test_positive_sys_admin(self):
        from helm_guard.checks.security import check_sec_009
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          securityContext:\n"
            "            capabilities:\n"
            "              add:\n"
            "                - SYS_ADMIN\n"
        )])
        findings = _run_check(check_sec_009, chart)
        sec009 = [f for f in findings if f["rule_id"] == "HLM-SEC-009"]
        assert len(sec009) >= 1
        assert sec009[0]["severity"] == "HIGH"

    def test_negative_drop_all(self):
        from helm_guard.checks.security import check_sec_009
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          securityContext:\n"
            "            capabilities:\n"
            "              drop:\n"
            "                - ALL\n"
        )])
        findings = _run_check(check_sec_009, chart)
        assert not any(f["rule_id"] == "HLM-SEC-009" for f in findings)

    def test_fp_guard_templated_capability(self):
        """Capabilities set via .Values should not fire."""
        from helm_guard.checks.security import check_sec_009
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          securityContext:\n"
            "            capabilities:\n"
            "              add:\n"
            "                - {{ .Values.capabilities }}\n"
        )])
        findings = _run_check(check_sec_009, chart)
        assert not any(f["rule_id"] == "HLM-SEC-009" for f in findings)


# ---------------------------------------------------------------------------
# SEC-010: runAsNonRoot missing
# ---------------------------------------------------------------------------
class TestSEC010:
    def test_positive_no_run_as_non_root(self):
        from helm_guard.checks.security import check_sec_010
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          image: nginx\n"
        )])
        findings = _run_check(check_sec_010, chart)
        assert any(f["rule_id"] == "HLM-SEC-010" for f in findings)

    def test_negative_has_run_as_non_root(self):
        from helm_guard.checks.security import check_sec_010
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      securityContext:\n"
            "        runAsNonRoot: true\n"
            "      containers:\n"
            "        - name: app\n"
        )])
        findings = _run_check(check_sec_010, chart)
        assert not any(f["rule_id"] == "HLM-SEC-010" for f in findings)

    def test_fp_guard_run_as_user_nonzero(self):
        """runAsUser: 1000 should suppress SEC-010."""
        from helm_guard.checks.security import check_sec_010
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      securityContext:\n"
            "        runAsUser: 1000\n"
            "      containers:\n"
            "        - name: app\n"
        )])
        findings = _run_check(check_sec_010, chart)
        assert not any(f["rule_id"] == "HLM-SEC-010" for f in findings)

    def test_fp_guard_templated_run_as_non_root(self):
        """Templated runAsNonRoot should suppress SEC-010."""
        from helm_guard.checks.security import check_sec_010
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: DaemonSet\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      securityContext:\n"
            "        runAsNonRoot: {{ .Values.runAsNonRoot }}\n"
            "      containers:\n"
            "        - name: app\n"
        )])
        findings = _run_check(check_sec_010, chart)
        assert not any(f["rule_id"] == "HLM-SEC-010" for f in findings)


# ---------------------------------------------------------------------------
# SEC-011: Missing resource limits
# ---------------------------------------------------------------------------
class TestSEC011:
    def test_positive_no_resources(self):
        from helm_guard.checks.security import check_sec_011
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: StatefulSet\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: db\n"
            "          image: postgres\n"
        )])
        findings = _run_check(check_sec_011, chart)
        assert any(f["rule_id"] == "HLM-SEC-011" for f in findings)

    def test_negative_has_resources(self):
        from helm_guard.checks.security import check_sec_011
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          resources:\n"
            "            limits:\n"
            "              cpu: 500m\n"
        )])
        findings = _run_check(check_sec_011, chart)
        assert not any(f["rule_id"] == "HLM-SEC-011" for f in findings)


# ---------------------------------------------------------------------------
# SEC-012: Schema $ref to external resource
# ---------------------------------------------------------------------------
class TestSEC012:
    def test_positive_external_ref(self):
        from helm_guard.checks.security import check_sec_012
        chart = _make_chart(schema={
            "type": "object",
            "properties": {
                "image": {"$ref": "https://evil.example.com/schema.json"}
            }
        })
        findings = _run_check(check_sec_012, chart)
        assert any(f["rule_id"] == "HLM-SEC-012" for f in findings)

    def test_positive_dev_ref(self):
        from helm_guard.checks.security import check_sec_012
        chart = _make_chart(schema={
            "type": "object",
            "properties": {
                "sink": {"$ref": "/dev/urandom"}
            }
        })
        findings = _run_check(check_sec_012, chart)
        assert any(f["rule_id"] == "HLM-SEC-012" for f in findings)

    def test_negative_internal_ref(self):
        from helm_guard.checks.security import check_sec_012
        chart = _make_chart(schema={
            "type": "object",
            "properties": {
                "config": {"$ref": "#/definitions/config"}
            },
            "definitions": {"config": {"type": "object"}}
        })
        findings = _run_check(check_sec_012, chart)
        assert not any(f["rule_id"] == "HLM-SEC-012" for f in findings)

    def test_negative_no_schema(self):
        from helm_guard.checks.security import check_sec_012
        chart = _make_chart(schema=None)
        findings = _run_check(check_sec_012, chart)
        assert not any(f["rule_id"] == "HLM-SEC-012" for f in findings)


# ---------------------------------------------------------------------------
# SEC-013: ArgoCD Application with HTTP source
# ---------------------------------------------------------------------------
class TestSEC013:
    def test_positive_http_repo(self):
        from helm_guard.checks.security import check_sec_013
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Application\n"
            "spec:\n"
            "  source:\n"
            "    repoURL: http://charts.example.com/repo\n"
        )])
        findings = _run_check(check_sec_013, chart)
        assert any(f["rule_id"] == "HLM-SEC-013" for f in findings)

    def test_negative_https_repo(self):
        from helm_guard.checks.security import check_sec_013
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Application\n"
            "spec:\n"
            "  source:\n"
            "    repoURL: https://charts.example.com/repo\n"
        )])
        findings = _run_check(check_sec_013, chart)
        assert not any(f["rule_id"] == "HLM-SEC-013" for f in findings)

    def test_fp_guard_localhost(self):
        """HTTP to localhost should not fire."""
        from helm_guard.checks.security import check_sec_013
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Application\n"
            "spec:\n"
            "  source:\n"
            "    repoURL: http://localhost:8080/repo\n"
        )])
        findings = _run_check(check_sec_013, chart)
        assert not any(f["rule_id"] == "HLM-SEC-013" for f in findings)

    def test_fp_guard_non_argoproj(self):
        """kind: Application without argoproj.io apiVersion should not fire."""
        from helm_guard.checks.security import check_sec_013
        chart = _make_chart(templates=[_tmpl(
            "apiVersion: v1\n"
            "kind: Application\n"
            "spec:\n"
            "  source:\n"
            "    repoURL: http://charts.example.com/repo\n"
        )])
        findings = _run_check(check_sec_013, chart)
        assert not any(f["rule_id"] == "HLM-SEC-013" for f in findings)


# ---------------------------------------------------------------------------
# SEC-014: Suspicious chart complexity
# ---------------------------------------------------------------------------
class TestSEC014:
    def test_positive_many_templates(self):
        from helm_guard.checks.security import check_sec_014
        # Create 201 fake template files
        templates = [_tmpl(f"# template {i}", f"t{i}.yaml") for i in range(201)]
        chart = _make_chart(templates=templates)
        findings = _run_check(check_sec_014, chart)
        assert any(f["rule_id"] == "HLM-SEC-014" for f in findings)

    def test_negative_normal_count(self):
        from helm_guard.checks.security import check_sec_014
        templates = [_tmpl(f"# template {i}", f"t{i}.yaml") for i in range(10)]
        chart = _make_chart(templates=templates)
        findings = _run_check(check_sec_014, chart)
        assert not any(
            f["rule_id"] == "HLM-SEC-014" and "templates" in f.get("title", "")
            for f in findings
        )

    def test_positive_deep_nesting(self):
        from helm_guard.checks.security import check_sec_014
        with tempfile.TemporaryDirectory() as d:
            # Create a deeply nested charts/ structure (depth 6)
            nested = os.path.join(d, "charts", "a", "b", "c", "d", "e", "f")
            os.makedirs(nested)
            chart = _make_chart(tmpdir=d)
            findings = _run_check(check_sec_014, chart)
            assert any(
                f["rule_id"] == "HLM-SEC-014" and "nesting" in f.get("title", "")
                for f in findings
            )


# ---------------------------------------------------------------------------
# PIN-006: Mutable image tag in values
# ---------------------------------------------------------------------------
class TestPIN006:
    def test_positive_latest_tag(self):
        from helm_guard.checks.pinning import check_pin_006
        from ruamel.yaml import YAML
        yaml = YAML(typ="rt")
        import io
        values = yaml.load(io.StringIO("image:\n  repository: nginx\n  tag: latest\n"))
        chart = _make_chart(values=values)
        findings = _run_check(check_pin_006, chart)
        assert any(f["rule_id"] == "HLM-PIN-006" for f in findings)

    def test_positive_empty_tag(self):
        from helm_guard.checks.pinning import check_pin_006
        from ruamel.yaml import YAML
        import io
        yaml = YAML(typ="rt")
        values = yaml.load(io.StringIO('image:\n  repository: nginx\n  tag: ""\n'))
        chart = _make_chart(values=values)
        findings = _run_check(check_pin_006, chart)
        assert any(f["rule_id"] == "HLM-PIN-006" for f in findings)

    def test_negative_semver_tag(self):
        from helm_guard.checks.pinning import check_pin_006
        from ruamel.yaml import YAML
        import io
        yaml = YAML(typ="rt")
        values = yaml.load(io.StringIO("image:\n  repository: nginx\n  tag: '1.25.3'\n"))
        chart = _make_chart(values=values)
        findings = _run_check(check_pin_006, chart)
        assert not any(f["rule_id"] == "HLM-PIN-006" for f in findings)

    def test_fp_guard_tag_without_repository(self):
        """A 'tag' key without adjacent 'repository' should not fire."""
        from helm_guard.checks.pinning import check_pin_006
        from ruamel.yaml import YAML
        import io
        yaml = YAML(typ="rt")
        values = yaml.load(io.StringIO("app:\n  tag: latest\n  name: foo\n"))
        chart = _make_chart(values=values)
        findings = _run_check(check_pin_006, chart)
        assert not any(f["rule_id"] == "HLM-PIN-006" for f in findings)


# ---------------------------------------------------------------------------
# INJ-009: Filesystem-probing sprig functions
# ---------------------------------------------------------------------------
class TestINJ009:
    def test_positive_osbase(self):
        from helm_guard.checks.injection import check_inj_009
        chart = _make_chart(templates=[_tmpl(
            "data:\n"
            "  base: {{ osBase .Values.path }}\n"
        )])
        findings = _run_check(check_inj_009, chart)
        assert any(f["rule_id"] == "HLM-INJ-009" for f in findings)

    def test_positive_osdir(self):
        from helm_guard.checks.injection import check_inj_009
        chart = _make_chart(templates=[_tmpl(
            "data:\n"
            "  dir: {{ osDir .Values.path }}\n"
        )])
        findings = _run_check(check_inj_009, chart)
        assert any(f["rule_id"] == "HLM-INJ-009" for f in findings)

    def test_negative_no_sprig_fs(self):
        from helm_guard.checks.injection import check_inj_009
        chart = _make_chart(templates=[_tmpl(
            "data:\n"
            "  name: {{ .Values.name }}\n"
        )])
        findings = _run_check(check_inj_009, chart)
        assert not any(f["rule_id"] == "HLM-INJ-009" for f in findings)

    def test_fp_guard_comment_line(self):
        """sprig function in a YAML comment should not fire."""
        from helm_guard.checks.injection import check_inj_009
        chart = _make_chart(templates=[_tmpl(
            "# {{ osBase .Values.path }}\n"
            "data: foo\n"
        )])
        findings = _run_check(check_inj_009, chart)
        assert not any(f["rule_id"] == "HLM-INJ-009" for f in findings)

    def test_fp_guard_go_template_comment(self):
        """sprig function inside Go template comment should not fire."""
        from helm_guard.checks.injection import check_inj_009
        chart = _make_chart(templates=[_tmpl(
            "{{/* osBase is not used here */}}\n"
            "data: foo\n"
        )])
        findings = _run_check(check_inj_009, chart)
        assert not any(f["rule_id"] == "HLM-INJ-009" for f in findings)


# ---------------------------------------------------------------------------
# Integration: parse real fixture directories
# ---------------------------------------------------------------------------
class TestFixtureIntegration:
    def test_positive_fixture_has_findings(self):
        """The new-checks-chart fixture should trigger all new checks."""
        chart = parse_chart_dir(POSITIVE_CHART)
        from helm_guard.checks import run_checks
        findings = run_checks(chart, ScannerConfig())
        found_ids = _ids(findings)
        # These should all fire on the positive fixture
        expected = {
            "HLM-SEC-007",  # wildcard RBAC
            "HLM-SEC-008",  # hostPath
            "HLM-SEC-009",  # dangerous caps
            "HLM-SEC-012",  # external $ref
            "HLM-SEC-013",  # ArgoCD HTTP
            "HLM-INJ-009",  # sprig fs functions
            "HLM-PIN-006",  # mutable tag latest
        }
        for eid in expected:
            assert eid in found_ids, f"{eid} expected but not found in {found_ids}"

    def test_clean_fixture_no_new_findings(self):
        """The clean fixture should NOT trigger any of the new SEC/PIN/INJ checks."""
        chart = parse_chart_dir(CLEAN_CHART)
        from helm_guard.checks import run_checks
        findings = run_checks(chart, ScannerConfig())
        new_check_ids = {
            "HLM-SEC-007", "HLM-SEC-008", "HLM-SEC-009",
            "HLM-SEC-010", "HLM-SEC-011", "HLM-SEC-012",
            "HLM-SEC-013", "HLM-SEC-014",
            "HLM-PIN-006",
            "HLM-INJ-009",
        }
        found_new = {f["rule_id"] for f in findings if f["rule_id"] in new_check_ids}
        assert not found_new, f"Clean fixture triggered unexpected checks: {found_new}"
