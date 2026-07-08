"""CLI entry point for helm-guard."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from helm_guard.checks import run_checks, SEVERITY_ORDER
from helm_guard.config import load_config
from helm_guard.formatter import format_json, format_sarif, format_text
from helm_guard.parser import parse_chart_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="helm-guard",
        description="Security scanner for Helm chart supply chain integrity",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to a Helm chart directory",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "sarif", "text"],
        default="json",
        dest="output_format",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Config file with trust lists and check settings",
    )
    parser.add_argument(
        "--min-severity",
        default=None,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to report (overrides config)",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Exit 1 only if findings at or above this severity (default: any finding)",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        default=False,
        help="Always exit 0 regardless of findings (for informational runs)",
    )

    parser.add_argument(
        "--explain",
        default=None,
        metavar="RULE_ID",
        help="Show detailed information about a specific check rule",
    )

    fix_group = parser.add_mutually_exclusive_group()
    fix_group.add_argument(
        "--fix",
        action="store_true",
        default=False,
        help="Apply safe fixes (dependency pinning, clear secret defaults).",
    )
    fix_group.add_argument(
        "--fix-dry-run",
        action="store_true",
        default=False,
        help="Preview fixes without applying them.",
    )

    parser.add_argument(
        "--baseline",
        default=None,
        help="Baseline file to suppress known findings (.helm-guard-baseline.json)",
    )
    parser.add_argument(
        "--update-baseline",
        default=None,
        help="Write current findings as a new baseline file",
    )

    parser.add_argument(
        "--exclude-paths",
        nargs="*",
        default=None,
        help="Glob patterns to exclude from scanning",
    )

    args = parser.parse_args(argv)

    if args.explain:
        from helm_guard.checks._common import get_all_checks
        rule = args.explain.upper()
        for check_fn in get_all_checks():
            check_id = getattr(check_fn, 'check_id', '')
            if check_id == rule:
                doc = check_fn.__doc__ or ''
                print(f"\n{check_id}: {doc.split(':', 1)[1].strip() if ':' in doc else doc}")
                print(f"\nDocs: https://ugiordan.github.io/helm-guard/reference/rules/#{rule.lower()}")
                return 0
        print(f"Unknown rule: {rule}", file=sys.stderr)
        return 2

    if not args.target:
        parser.error("the following arguments are required: target")

    config = load_config(args.config)
    if args.min_severity:
        config.min_severity = args.min_severity

    target = Path(args.target)
    if not target.is_dir():
        print(f"Error: '{args.target}' is not a valid chart directory", file=sys.stderr)
        return 2

    chart_yaml = target / "Chart.yaml"
    if not chart_yaml.exists():
        print(f"Error: '{args.target}' does not contain Chart.yaml", file=sys.stderr)
        return 2

    chart = parse_chart_dir(target)

    # Exclude paths: filter template files by glob patterns
    # Match against both the absolute path and the relative path from chart dir
    # so patterns like 'templates/deployment.yaml' and '*injection*' both work.
    if args.exclude_paths:
        import fnmatch
        import os
        chart_dir_prefix = str(target) + os.sep
        original = len(chart.template_files)
        def _matches_exclude(tpath: str) -> bool:
            rel = tpath[len(chart_dir_prefix):] if tpath.startswith(chart_dir_prefix) else tpath
            return any(
                fnmatch.fnmatch(tpath, pat) or fnmatch.fnmatch(rel, pat)
                for pat in args.exclude_paths
            )
        chart.template_files = [t for t in chart.template_files if not _matches_exclude(t.path)]
        excluded = original - len(chart.template_files)
        if excluded:
            print(f"Excluded {excluded} template(s) matching {args.exclude_paths}", file=sys.stderr)

    findings = run_checks(chart, config)

    # Baseline: suppress known findings
    if args.baseline:
        baseline_path = Path(args.baseline)
        if baseline_path.exists():
            baseline_data = json.loads(baseline_path.read_text())
            baseline_keys: set[tuple[str, str, str]] = set()
            now = datetime.now(timezone.utc)
            expired_count = 0
            for entry in baseline_data.get("findings", []):
                reason = entry.get("reason", "")
                if not reason or not str(reason).strip():
                    print(f"Baseline: rejecting entry without reason (rule: {entry.get('rule_id')})", file=sys.stderr)
                    continue
                expires = entry.get("expires")
                if expires:
                    try:
                        exp_dt = datetime.fromisoformat(expires)
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        if exp_dt < now:
                            expired_count += 1
                            continue
                    except (ValueError, TypeError):
                        pass
                key = (entry["rule_id"], entry["file"], entry.get("content_hash", ""))
                baseline_keys.add(key)
            if expired_count:
                print(f"Baseline: {expired_count} expired entry(ies) ignored", file=sys.stderr)
            original_count = len(findings)
            findings = [f for f in findings if (
                f["rule_id"], f.get("file", ""),
                hashlib.sha256(f"{f.get('message', '')}:{f.get('line_start', 0)}".encode()).hexdigest()[:16]
            ) not in baseline_keys]
            suppressed = original_count - len(findings)
            if suppressed:
                print(f"Baseline: suppressed {suppressed} known finding(s)", file=sys.stderr)

    # Update baseline: write current findings
    if args.update_baseline:
        baseline = {
            "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "findings": []
        }
        for f in findings:
            content_hash = hashlib.sha256(
                f"{f.get('message', '')}:{f.get('line_start', 0)}".encode()
            ).hexdigest()[:16]
            baseline["findings"].append({
                "rule_id": f["rule_id"],
                "file": f.get("file", ""),
                "content_hash": content_hash,
                "line_hint": f.get("line_start", 0),
                "reason": "Accepted via --update-baseline",
            })
        Path(args.update_baseline).write_text(json.dumps(baseline, indent=2))
        print(f"Baseline written: {len(baseline['findings'])} finding(s) to {args.update_baseline}", file=sys.stderr)

    # Fix mode: apply safe fixes
    if args.fix or args.fix_dry_run:
        from helm_guard.fixer import FixEngine
        engine = FixEngine(dry_run=args.fix_dry_run)
        fix_result = engine.fix_findings(findings, str(target))
        mode = "dry-run" if args.fix_dry_run else "applied"
        print(f"Fix {mode}: {len(fix_result.fixed)} fixed, {len(fix_result.skipped)} skipped", file=sys.stderr)

    if args.output_format == "json":
        output = format_json(findings, str(target))
    elif args.output_format == "sarif":
        output = format_sarif(findings, str(target))
    else:
        output = format_text(findings, str(target))

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)

    if args.exit_zero:
        return 0

    if not findings:
        return 0

    if args.fail_on:
        threshold = SEVERITY_ORDER.get(args.fail_on, 0)
        if any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold for f in findings):
            return 1
        return 0

    return 1
