"""Tests for CLI exit codes and flags."""

from pathlib import Path

from helm_guard.cli import main

FIXTURES = str(Path(__file__).parent / "fixtures")


def test_exit_1_findings():
    code = main([FIXTURES + "/test-chart", "--format", "text"])
    assert code == 1


def test_exit_0_clean_chart():
    code = main([FIXTURES + "/clean-chart", "--format", "text"])
    assert code == 0


def test_exit_2_bad_path():
    code = main(["/nonexistent/path", "--format", "text"])
    assert code == 2


def test_exit_2_not_a_chart():
    code = main([FIXTURES, "--format", "text"])
    assert code == 2


def test_exit_zero_flag():
    code = main([FIXTURES + "/test-chart", "--exit-zero", "--format", "text"])
    assert code == 0


def test_fail_on_critical_skips_high():
    code = main([FIXTURES + "/test-chart", "--fail-on", "CRITICAL", "--format", "text"])
    # test-chart has HLM-INJ-001 which is CRITICAL, so this should return 1
    assert code == 1


def test_json_format():
    import json
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    code = main([FIXTURES + "/test-chart", "--format", "json"])
    sys.stdout = old_stdout
    output = buffer.getvalue()
    report = json.loads(output)
    assert report["scanner"] == "helm-guard"
    assert report["summary"]["total"] > 0
    assert code == 1


def test_sarif_format():
    import json
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    code = main([FIXTURES + "/test-chart", "--format", "sarif"])
    sys.stdout = old_stdout
    output = buffer.getvalue()
    sarif = json.loads(output)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) > 0


def test_output_file(tmp_path):
    outfile = str(tmp_path / "results.json")
    code = main([FIXTURES + "/test-chart", "--format", "json", "--output", outfile])
    assert code == 1
    import json
    report = json.loads(Path(outfile).read_text())
    assert report["summary"]["total"] > 0


def test_min_severity_high():
    import json
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    code = main([FIXTURES + "/test-chart", "--format", "json", "--min-severity", "HIGH"])
    sys.stdout = old_stdout
    output = buffer.getvalue()
    report = json.loads(output)
    for f in report["findings"]:
        assert f["severity"] in ("HIGH", "CRITICAL")
