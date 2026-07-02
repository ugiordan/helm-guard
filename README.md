# helm-guard

Security scanner for Helm chart supply chain integrity.

Checks what no existing tool covers: dependency pinning, template injection via `tpl`, values trust chains, and chart provenance. Static analysis by default (no `helm` CLI dependency).

## What it checks

| ID | Category | Severity | Description |
|----|----------|----------|-------------|
| HLM-PIN-001 | Pinning | HIGH | Chart dependency with SemVer range |
| HLM-PIN-002 | Pinning | HIGH | Missing Chart.lock when dependencies exist |
| HLM-PIN-003 | Pinning | MEDIUM | Mutable image tag in values.yaml |
| HLM-PIN-004 | Pinning | MEDIUM | OLM subscription channel not version-pinned |
| HLM-INJ-001 | Injection | CRITICAL | `tpl` function usage (Go template RCE) |
| HLM-INJ-002 | Injection | HIGH | `.Values` in shell context without `quote` |
| HLM-INJ-003 | Injection | MEDIUM | `.Values` in `name:` without `trunc 63` |
| HLM-TRUST-001 | Trust | HIGH | No values.schema.json |
| HLM-TRUST-002 | Trust | HIGH | Secrets with non-empty defaults in values.yaml |
| HLM-TRUST-003 | Trust | HIGH | Dependency from untrusted repository |

## Install

```bash
pip install helm-guard
```

Or run from source:

```bash
git clone https://github.com/ugiordan/helm-guard.git
cd helm-guard
pip install -e .
```

## Usage

```bash
# Scan a chart directory (JSON output, default)
helm-guard /path/to/chart

# Text output
helm-guard /path/to/chart --format text

# SARIF output (for GitHub Code Scanning)
helm-guard /path/to/chart --format sarif

# Custom config
helm-guard /path/to/chart --config .helm-guard.yaml

# Only fail on HIGH or CRITICAL
helm-guard /path/to/chart --fail-on HIGH

# Filter output to HIGH+ severity
helm-guard /path/to/chart --min-severity HIGH

# Always exit 0 (informational mode)
helm-guard /path/to/chart --exit-zero

# Write output to file
helm-guard /path/to/chart --output results.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or `--exit-zero` used) |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Error (bad path, missing Chart.yaml) |

## Configuration

Create `.helm-guard.yaml` in your project root:

```yaml
trusted_chart_repos:
  - "https://charts.helm.sh/stable"
  - "oci://quay.io/opendatahub/"
  - "oci://registry.redhat.io/"

trusted_olm_sources:
  - "redhat-operators"
  - "certified-operators"

skip_checks:
  - "HLM-PROV-001"

min_severity: "LOW"

secret_key_patterns:
  - "password"
  - "token"
  - "secret"
  - "apiKey"
  - "credentials"

privileged_namespaces:
  - "kube-system"
  - "kube-public"
  - "default"
  - "openshift-operators"
```

## Three-tier parser

helm-guard uses a three-tier parser design because Helm templates contain Go template directives that make them invalid YAML:

- **Tier 1 (Structured YAML)**: `Chart.yaml`, `values.yaml`, `Chart.lock`, `values.schema.json`. Parsed with `ruamel.yaml`. Used by PIN and TRUST checks.
- **Tier 2 (Text/regex)**: Template files scanned as raw text with regex patterns. Used by INJ checks.
- **Tier 3 (Rendered output)**: Planned for v1.2, requires `helm template` CLI. Not enabled by default.

## Scope boundary

helm-guard checks chart-level supply chain integrity. It does not duplicate what existing tools cover:

- **kube-linter**: Resource best practices (probes, limits, pod security)
- **kube-chainsaw**: RBAC privilege escalation chains

## License

Apache 2.0
