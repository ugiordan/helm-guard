# Quickstart

## Scan a chart

```bash
# JSON output (default)
helm-guard /path/to/chart

# Text output for terminal readability
helm-guard /path/to/chart --format text

# SARIF output for GitHub Code Scanning
helm-guard /path/to/chart --format sarif
```

## Use a config file

```bash
helm-guard /path/to/chart --config .helm-guard.yaml
```

## Filter by severity

```bash
# Only report HIGH and CRITICAL findings
helm-guard /path/to/chart --min-severity HIGH

# Only fail (exit 1) on CRITICAL findings
helm-guard /path/to/chart --fail-on CRITICAL
```

## CI integration

```bash
# Run in CI, fail the build on HIGH+ findings
helm-guard /path/to/chart --fail-on HIGH --format sarif --output results.sarif
```

## Example output (text format)

```
Helm Chart Security Scan: ./my-chart
Found 4 issue(s)

[CRITICAL] HLM-INJ-001: tpl function usage
  File: ./my-chart/templates/deployment.yaml:28
  Template uses 'tpl' function which executes input as a Go template, enabling arbitrary code execution.
  Fix: Avoid 'tpl' entirely. Use direct value interpolation instead.

[HIGH] HLM-PIN-001: Chart dependency with SemVer range
  File: ./my-chart/Chart.yaml:8
  Dependency 'redis' uses SemVer range '~17.0'. Pin to an exact version.
  Fix: Pin dependency 'redis' to an exact version (e.g., version: 1.2.3)

[HIGH] HLM-TRUST-001: No values.schema.json
  File: ./my-chart/values.yaml:1
  Chart has values.yaml but no values.schema.json. Values are not type-checked.
  Fix: Add values.schema.json with type constraints for all user-facing values

[MEDIUM] HLM-PIN-003: Mutable image tag in values.yaml
  File: ./my-chart/values.yaml:5
  Image value at 'image.tag' is 'latest' (no @sha256: digest). Pin to a digest.
  Fix: Pin images to digest (e.g., image: registry.io/repo@sha256:abc123...)
```
