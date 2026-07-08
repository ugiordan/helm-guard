"""Tests for CLI exit codes and flags."""

import json
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
    main([FIXTURES + "/test-chart", "--format", "sarif"])
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
    main([FIXTURES + "/test-chart", "--format", "json", "--min-severity", "HIGH"])
    sys.stdout = old_stdout
    output = buffer.getvalue()
    report = json.loads(output)
    for f in report["findings"]:
        assert f["severity"] in ("HIGH", "CRITICAL")


def test_update_baseline_creates_file(tmp_path):
    baseline_file = str(tmp_path / "baseline.json")
    main([FIXTURES + "/test-chart", "--format", "text", "--update-baseline", baseline_file])
    assert Path(baseline_file).exists()
    data = json.loads(Path(baseline_file).read_text())
    assert len(data["findings"]) > 0
    assert data["version"] == "1.0"
    # Every entry must have a reason
    for entry in data["findings"]:
        assert entry.get("reason"), f"Missing reason for {entry['rule_id']}"


def test_baseline_suppresses_findings(tmp_path):
    baseline_file = str(tmp_path / "baseline.json")
    main([FIXTURES + "/test-chart", "--format", "text", "--update-baseline", baseline_file])
    code = main([FIXTURES + "/test-chart", "--format", "text", "--baseline", baseline_file])
    assert code == 0  # all findings suppressed


def test_baseline_rejects_no_reason(tmp_path):
    """Baseline entries without reason should be rejected (finding not suppressed)."""
    import io
    import sys

    baseline_file = str(tmp_path / "baseline.json")
    # Create baseline manually without reason
    main([FIXTURES + "/test-chart", "--format", "text", "--update-baseline", baseline_file])
    data = json.loads(Path(baseline_file).read_text())
    # Remove reason from first entry
    if data["findings"]:
        del data["findings"][0]["reason"]
    Path(baseline_file).write_text(json.dumps(data))

    old_stderr = sys.stderr
    sys.stderr = err_buf = io.StringIO()
    main([FIXTURES + "/test-chart", "--format", "text", "--baseline", baseline_file])
    sys.stderr = old_stderr
    assert "rejecting entry without reason" in err_buf.getvalue()


def test_baseline_expired_entries_ignored(tmp_path):
    """Expired baseline entries should not suppress findings."""
    import io
    import sys

    baseline_file = str(tmp_path / "baseline.json")
    main([FIXTURES + "/test-chart", "--format", "text", "--update-baseline", baseline_file])
    data = json.loads(Path(baseline_file).read_text())
    # Set all entries to expired
    for entry in data["findings"]:
        entry["expires"] = "2020-01-01T00:00:00+00:00"
    Path(baseline_file).write_text(json.dumps(data))

    old_stderr = sys.stderr
    sys.stderr = err_buf = io.StringIO()
    code = main([FIXTURES + "/test-chart", "--format", "text", "--baseline", baseline_file])
    sys.stderr = old_stderr
    assert "expired" in err_buf.getvalue()
    assert code == 1  # findings not suppressed


def test_exclude_paths(tmp_path):
    """--exclude-paths should filter template files."""
    import io
    import sys

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = err_buf = io.StringIO()
    main([FIXTURES + "/test-chart", "--format", "json", "--exclude-paths", "*injection*"])
    sys.stdout = old_stdout
    sys.stderr = old_stderr
    assert "Excluded" in err_buf.getvalue()


def test_fix_dry_run_flag(tmp_path):
    """--fix-dry-run should report fixes without modifying files."""
    import io
    import shutil
    import sys

    src = Path(FIXTURES) / "test-chart"
    dst = tmp_path / "chart"
    shutil.copytree(src, dst)

    original_chart = (dst / "Chart.yaml").read_text()

    old_stderr = sys.stderr
    sys.stderr = err_buf = io.StringIO()
    main([str(dst), "--format", "text", "--fix-dry-run"])
    sys.stderr = old_stderr
    assert "Fix dry-run:" in err_buf.getvalue()
    assert (dst / "Chart.yaml").read_text() == original_chart


def test_fix_and_fix_dry_run_mutually_exclusive(tmp_path):
    """--fix and --fix-dry-run are mutually exclusive."""
    import shutil
    src = Path(FIXTURES) / "test-chart"
    dst = tmp_path / "chart"
    shutil.copytree(src, dst)

    try:
        main([str(dst), "--format", "text", "--fix", "--fix-dry-run"])
        # argparse should have raised SystemExit(2)
        assert False, "Should have raised SystemExit"
    except SystemExit as e:
        assert e.code == 2
