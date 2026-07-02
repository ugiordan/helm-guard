"""Tests for the Helm chart parser."""

import os
import tempfile
from pathlib import Path

from helm_guard.parser import parse_chart_dir

FIXTURES = Path(__file__).parent / "fixtures"


class TestParser:
    def test_parse_test_chart(self):
        chart = parse_chart_dir(FIXTURES / "test-chart")
        assert chart.chart_yaml["name"] == "test-chart"
        assert chart.chart_yaml["version"] == "0.1.0"
        assert len(chart.chart_yaml["dependencies"]) == 2
        assert chart.values_yaml["replicaCount"] == 1
        assert chart.values_yaml["image"]["tag"] == "latest"
        assert chart.values_schema is None
        assert chart.chart_lock is None
        assert len(chart.template_files) >= 1
        assert not chart.has_prov

    def test_parse_clean_chart(self):
        chart = parse_chart_dir(FIXTURES / "clean-chart")
        assert chart.chart_yaml["name"] == "clean-chart"
        assert "dependencies" not in chart.chart_yaml
        assert chart.values_schema is not None
        assert chart.values_schema["type"] == "object"
        assert len(chart.template_files) >= 1

    def test_template_files_contain_content(self):
        chart = parse_chart_dir(FIXTURES / "test-chart")
        assert any("Deployment" in t.content for t in chart.template_files)

    def test_nonexistent_dir_returns_empty(self):
        chart = parse_chart_dir("/nonexistent/path")
        assert chart.chart_yaml == {}
        assert chart.values_yaml == {}
        assert chart.template_files == []

    def test_empty_chart_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text("")
            chart = parse_chart_dir(td)
            assert chart.chart_yaml == {}

    def test_scalar_chart_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text("just a string")
            chart = parse_chart_dir(td)
            assert chart.chart_yaml == {}

    def test_list_chart_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text("- item1\n- item2\n")
            chart = parse_chart_dir(td)
            assert chart.chart_yaml == {}

    def test_malformed_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text("key: [invalid yaml {{")
            chart = parse_chart_dir(td)
            assert chart.chart_yaml == {}

    def test_no_values_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text("apiVersion: v2\nname: test\n")
            chart = parse_chart_dir(td)
            assert chart.values_yaml == {}

    def test_symlinks_in_templates_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Chart.yaml").write_text("apiVersion: v2\nname: test\n")
            tdir = Path(td) / "templates"
            tdir.mkdir()
            (tdir / "real.yaml").write_text("apiVersion: v1\nkind: ConfigMap\n")
            symlink = tdir / "evil.yaml"
            symlink.symlink_to("/etc/hosts")
            chart = parse_chart_dir(td)
            template_names = [os.path.basename(t.path) for t in chart.template_files]
            assert "real.yaml" in template_names
            assert "evil.yaml" not in template_names
