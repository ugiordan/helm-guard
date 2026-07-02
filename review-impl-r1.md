# Adversarial Code Review: helm-guard Phase 1

**Date**: 2026-07-02
**Reviewer**: Claude Opus 4.6 (adversarial)
**Scope**: All source files, tests, and fixtures
**Baseline**: 36 tests, all passing

## Summary

15 findings total. 6 fixed directly in code, 9 documented for future work.

## Fixed (6)

### F-01: INJ-001 `\btpl\b` regex matches outside Go template delimiters [CRITICAL FP]

**File**: `helm_guard/checks/injection.py:11`
**Issue**: The regex `\btpl\b` matched "tpl" anywhere in a line, including YAML comments (`# helper.tpl`), resource names (`my-tpl-config`), Go template comments (`{{/* tpl */}}`), and file references. Since INJ-001 is severity CRITICAL, every false positive is a broken user experience.
**Fix**: Changed to `\{\{-?\s*tpl\b` which requires Go template opening delimiters before `tpl`. This correctly matches `{{ tpl ...}}`, `{{- tpl ...}}`, and `{{tpl ...}}` while rejecting all non-template occurrences.
**Tests added**: 7 regex tests in `TestINJ001Regex`.

### F-02: INJ-002 quote pipe regex misses chained filters [HIGH FN]

**File**: `helm_guard/checks/injection.py:27`
**Issue**: The regex `\.Values\.[a-zA-Z0-9_.]+\s*\|\s*(quote|squote)` only matched when `quote` was the FIRST filter after `.Values.x`. The common pattern `{{ .Values.x | default "" | quote }}` was flagged as unquoted (false positive), and `{{ .Values.x | toYaml | quote }}` similarly.
**Fix**: Changed to `\.Values\.[a-zA-Z0-9_.]+.*\|\s*(quote|squote)` to match `quote`/`squote` anywhere in the pipe chain.
**Tests added**: 1 test in `TestINJ002QuotePipe`.

### F-03: `load_config` crashes on malformed YAML [MEDIUM]

**File**: `helm_guard/config.py:74`
**Issue**: `load_config()` had no try/except around `yaml.load()`. A malformed `.helm-guard.yaml` file (e.g., `key: [invalid {{`) raised `ruamel.yaml.parser.ParserError` and crashed the scanner instead of falling back to defaults.
**Fix**: Wrapped YAML loading in try/except, returning `ScannerConfig()` defaults on parse failure. Also added a guard for non-dict YAML documents (e.g., a YAML file containing only a scalar or list).
**Tests added**: 1 test in `TestConfig.test_malformed_config_file_returns_defaults`.

### F-04: Parser follows symlinks in templates/ [MEDIUM - Security]

**File**: `helm_guard/parser.py:69`
**Issue**: `_find_template_files` used `rglob()` without checking for symlinks. A malicious chart could include a symlink in `templates/` pointing to arbitrary files (e.g., `/etc/shadow`, `~/.ssh/id_rsa`), and the scanner would read and include their content in findings output.
**Fix**: Added `if p.is_symlink(): continue` before reading template files.
**Tests added**: 1 test in `TestParser.test_symlinks_in_templates_skipped`.

### F-05: SARIF output uses absolute file paths [LOW - Information Disclosure]

**File**: `helm_guard/formatter.py:80`
**Issue**: When invoked with absolute chart paths (the common case), SARIF artifact URIs contained absolute filesystem paths like `/home/user/project/charts/mychart/Chart.yaml`, leaking server directory structure. The SARIF 2.1.0 spec recommends relative URIs.
**Fix**: Added `_relativize_uri()` helper that converts absolute paths to relative paths based on the target directory's parent. SARIF output now contains paths like `test-chart/Chart.yaml` instead of absolute paths.

### F-06: TRUST-002 message truncation misleading for short values [LOW]

**File**: `helm_guard/checks/trust.py:80`
**Issue**: The message always appended `...` after truncating to 20 chars: `'{val[:20]}...'`. For values shorter than 20 chars (e.g., `abc`), the output was `'abc...'`, implying the value was truncated when it was shown in full.
**Fix**: Changed to conditional truncation: `'{val[:20]}{'...' if len(val) > 20 else ''}'`.

### Parser edge case tests (5 tests added)

Not bugs per se, but the parser had zero coverage for degenerate inputs:
- Empty Chart.yaml
- Scalar-only Chart.yaml
- List-only Chart.yaml
- Malformed YAML
- Missing values.yaml

All handled correctly (return empty dict). Tests added to prevent regressions.

## Documented, Not Fixed (9)

### D-01: TRUST-003 transitive walk is single-level, not recursive [HIGH]

**File**: `helm_guard/checks/trust.py:117-153`
The `charts/` subdirectory walk only goes one level deep. A chart at `charts/redis/charts/sentinel/Chart.yaml` with untrusted dependencies would not be detected. Real-world charts with deep dependency trees (e.g., kube-prometheus-stack) would have blind spots.
**Recommendation**: Implement recursive walk using `os.walk()` or a recursive function. Consider a depth limit (e.g., 3 levels) to prevent infinite loops from circular symlinks.

### D-02: TRUST-003 does not handle .tgz packaged subcharts [MEDIUM]

**File**: `helm_guard/checks/trust.py:118`
Helm stores downloaded dependencies as `.tgz` archives in `charts/`. The current implementation only looks at extracted directories. If `helm dependency build` was run but the chart is distributed as-is, `.tgz` files would be skipped.
**Recommendation**: Add `.tgz` extraction (via `tarfile`) to read `Chart.yaml` from packaged subcharts.

### D-03: PIN-003 image detection heuristics miss common patterns [MEDIUM]

**File**: `helm_guard/checks/pinning.py:33`
The image walker only matches keys literally named `image`, `tag`, or `repository`. Real charts use many variants:
- `containerImage`, `sidecarImage` (compound names)
- `image.name` (uses `name` key instead of `repository`)
- `initImage`, `imageOverride`
- `global.imageRegistry`

**Recommendation**: Extend the heuristic to match keys where `lower_key.endswith("image")` or `"image" in lower_key`, and also match dict keys named `name` when the parent key is `image`.

### D-04: TRUST-002 secret detection has false positives on non-secret "secret" keys [LOW]

**File**: `helm_guard/checks/trust.py:28`
The pattern matching `any(pat.lower() in lower_key for pat in patterns)` flags keys like `tls.secretName` (a Kubernetes secret reference, not a secret value) and `tokenEndpoint` (a URL, not a token). The substring match is too broad.
**Recommendation**: Use word-boundary matching or a blocklist of known-safe patterns like `secretName`, `secretRef`, `tokenEndpoint`.

### D-05: INJ-002 misses exec-form shell commands [MEDIUM]

**File**: `helm_guard/checks/injection.py:14`
The shell context regex only matches `sh -c` / `bash -c` / `script:` patterns. It misses:
- Exec form: `["/bin/sh", "-c", "echo {{ .Values.x }}"]`
- Python/Ruby interpreters: `python -c`
- `eval` in configmap data
- Heredoc patterns: `sh <<EOF`

**Recommendation**: Add exec-form array pattern detection and expand interpreter coverage.

### D-06: Check ID extraction from docstrings is fragile [LOW]

**File**: `helm_guard/checks/__init__.py:48`
The logic `check_fn.__doc__.split(":")[0].strip()` extracts check IDs from function docstrings. If a check function has no docstring, or the docstring format changes (e.g., no colon), the skip logic silently breaks. A check without a colon in its docstring would have its entire docstring used as the check ID, which would never match any skip_checks entry.
**Recommendation**: Add a `check_id` attribute to `register_check` decorator, or validate docstring format at registration time.

### D-07: All Tier 1 findings report line_start=1 [LOW]

**Files**: `pinning.py`, `trust.py` (all Tier 1 checks)
Every finding from YAML-parsed checks reports `line=1` because ruamel.yaml (with `typ="safe"`) does not preserve source line numbers. This makes findings less useful for developers navigating large values.yaml files.
**Recommendation**: Switch to `YAML(typ="rt")` (round-trip) which preserves line numbers via `lc` (line/column) attributes on loaded data.

### D-08: No `file://` repository dependency detection [LOW]

**File**: `helm_guard/checks/trust.py`
Dependencies with `repository: "file://../some-chart"` (local file references) bypass the trusted repo check because `file://` is not in any trusted list. While flagging them is correct, the error message ("not in trusted list") is misleading. File-based dependencies deserve a dedicated check since they indicate vendored or local charts.
**Recommendation**: Add a dedicated check for `file://` repository references.

### D-09: Config `trusted_chart_repos` accepts wrong types silently [LOW]

**File**: `helm_guard/config.py:78-89`
If the config file has `trusted_chart_repos: "not a list"` (a string instead of a list), the value is passed directly to `ScannerConfig()`. The dataclass accepts it without validation, and `is_trusted_chart_repo()` would then iterate over characters of the string instead of list items, silently breaking trust validation.
**Recommendation**: Add type validation in `load_config()` before constructing the dataclass.

## Test Coverage

| Metric | Before | After |
|--------|--------|-------|
| Total tests | 36 | 51 |
| Parser edge cases | 1 | 7 |
| Regex validation tests | 0 | 8 |
| Config error handling | 0 | 1 |

## Verdict

Phase 1 is solid for a v1.0 scanner. The core architecture (three-tier parser, check registry, SARIF output) is well-designed. The 6 fixes address the most impactful issues: false positives on the CRITICAL-severity tpl check, a crash on malformed config, symlink traversal, and SARIF spec compliance. The 9 documented items are real gaps but not blockers for initial deployment.
