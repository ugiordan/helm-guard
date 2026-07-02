# CLI Reference

## Synopsis

```
helm-guard TARGET [OPTIONS]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `TARGET` | Path to a Helm chart directory (must contain Chart.yaml) |

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--format`, `-f` | Output format: `json`, `sarif`, `text` | `json` |
| `--output`, `-o` | Write output to file instead of stdout | stdout |
| `--config`, `-c` | Path to config file with trust lists and check settings | none |
| `--min-severity` | Minimum severity to report: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `LOW` |
| `--fail-on` | Exit 1 only if findings at or above this severity | any finding |
| `--exit-zero` | Always exit 0 regardless of findings | false |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or `--exit-zero` used, or no findings above `--fail-on` threshold) |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Error (bad path, missing Chart.yaml) |

## Examples

```bash
# Basic scan with JSON output
helm-guard /path/to/chart

# Text output for terminal readability
helm-guard /path/to/chart --format text

# SARIF output for GitHub Code Scanning
helm-guard /path/to/chart --format sarif --output results.sarif

# Custom config
helm-guard /path/to/chart --config .helm-guard.yaml

# Only fail on HIGH or CRITICAL
helm-guard /path/to/chart --fail-on HIGH

# Filter output to HIGH+ severity
helm-guard /path/to/chart --min-severity HIGH

# Informational mode (never fail)
helm-guard /path/to/chart --exit-zero

# Combine flags for CI
helm-guard /path/to/chart --fail-on HIGH --format sarif --output results.sarif
```
