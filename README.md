<p align="center">
  <img src="site/docs/images/logo.svg" alt="helm-guard logo" width="120">
</p>

# helm-guard

Static security analysis for Helm chart supply chain integrity.

helm-guard uses a three-tier parser (structured YAML, text regex, rendered output) to analyze Helm charts without requiring the helm CLI. It runs 53 checks covering dependency pinning, template injection, values trust, OLM security, and CVE-based risks that rendered-manifest scanners like Checkov and Trivy miss entirely.

**[Documentation](https://ugiordan.github.io/helm-guard/)** | **[Detection Rules Reference](https://ugiordan.github.io/helm-guard/reference/rules/)**

## Install

```bash
pip install git+https://github.com/ugiordan/helm-guard.git
```

Requires Python 3.10+ and `ruamel.yaml`.

### GitHub Action
```yaml
- uses: ugiordan/kube-security-action@v1
```

### Pre-commit
```yaml
repos:
  - repo: https://github.com/ugiordan/helm-guard
    rev: v1.0.0
    hooks:
      - id: helm-guard
```

## Quick Start

```bash
helm-guard /path/to/chart --format text
```

Example output:
```
Helm Chart Security Scan: charts/rhai-on-openshift-chart
Found 3 issue(s)

[LOW] HLM-INJ-004: lookup function in template
  File: templates/definitions/_helpers.tpl:319
  Template uses lookup which queries live cluster API during rendering
  Fix: Consider alternatives. Use skipCrdCheck fallback if needed.

[HIGH] HLM-OLM-001: Automatic install plan without version pin
  File: values.yaml:23
  installPlanApproval is Automatic without startingCSV version pin
  Fix: Use Manual approval or pin to a specific CSV version

[MEDIUM] HLM-PIN-004: OLM channel not version-pinned
  File: values.yaml:59
  Channel 'beta' without version suffix
  Fix: Use versioned channels (e.g., stable-v1.3)

Summary: 1 HIGH, 1 MEDIUM, 1 LOW
```

## What It Detects

53 checks across 10 categories:

- **Injection** (9): tpl function (CRITICAL), lookup, env/expandenv, getHostByName, shell injection, .Files.Get, hardcoded registries, filesystem-probing sprig functions. All backed by real CVEs.
- **Pinning** (6): SemVer ranges in Chart.yaml, missing Chart.lock, mutable image tags, OLM channels, SemVer compliance, mutable image tags in values
- **Trust** (7): missing schema, secrets in values, untrusted repos, hostNetwork/hostPID, HTTP URLs, permissive NetworkPolicy, global overrides
- **Security** (15): path traversal in chart name (CVE-2024-25620), symlinked Chart.lock (CVE-2025-53547), valueFiles traversal (CVE-2022-24348), plugin path traversal (CVE-2026-35204), SA automount, missing .helmignore, wildcard RBAC, hostPath volumes, dangerous capabilities, runAsNonRoot, resource limits, schema $ref (CVE-2025-55199), ArgoCD HTTP, chart complexity, default scaffolding name collision
- **OLM** (4): auto-approval without pin, community catalog, privileged namespace, unstable channel + auto-approval
- **Hooks** (3): hook without securityContext, delete-policy evidence destruction, post-renderer scripts
- **Dependencies** (4): subchart security overrides, version conflicts, typosquatting, alias hiding
- **Namespace** (2): privileged namespace (render mode), release namespace without schema
- **Provenance** (1): missing chart signature

## CVEs Covered

- [CVE-2020-11013](https://nvd.nist.gov/vuln/detail/CVE-2020-11013): lookup function cluster API access
- [CVE-2023-25165](https://nvd.nist.gov/vuln/detail/CVE-2023-25165): getHostByName DNS exfiltration
- [CVE-2024-25620](https://nvd.nist.gov/vuln/detail/CVE-2024-25620): Chart.yaml path traversal
- [CVE-2025-53547](https://nvd.nist.gov/vuln/detail/CVE-2025-53547): symlinked Chart.lock code execution
- [CVE-2026-35204](https://nvd.nist.gov/vuln/detail/CVE-2026-35204): plugin version path traversal
- [CVE-2022-24348](https://nvd.nist.gov/vuln/detail/CVE-2022-24348): Argo CD valueFiles path traversal
- [CVE-2025-55199](https://nvd.nist.gov/vuln/detail/CVE-2025-55199): Schema $ref external resource SSRF/DoS

## Why helm-guard?

| Tool | Chart-Level | Template Injection | Dependency Trust | CVE-Based |
|------|:-:|:-:|:-:|:-:|
| **helm-guard** | Yes | Yes | Yes | Yes |
| Checkov | No | No | No | No |
| Trivy | No | No | No | No |
| Kubescape | No | No | No | No |
| kube-linter | No | No | No | No |

helm-guard is the only tool that performs chart-level supply chain analysis. Existing tools scan rendered manifests for K8s best practices but miss dependency pinning, template injection, and chart provenance.

## Key Features

- **Three-tier parser**: structured YAML (Chart.yaml/values.yaml), text regex (templates), rendered output (opt-in via `--render`)
- **Auto-fix** (`--fix`): pins Chart.yaml dependencies, clears secret defaults in values.yaml
- **Baseline management** (`--baseline`): suppress known findings with content fingerprinting
- **No helm CLI dependency**: static mode works without helm installed
- **Render safety interlock**: refuses `--render` if tpl injection is detected
- **SARIF output**: integrates with GitHub Code Scanning

## Output Formats

- **Text**: human-readable with severity summary
- **JSON**: machine-parseable findings with docs_url per finding
- **SARIF**: integrates with GitHub Code Scanning, GitLab SAST

```bash
helm-guard /path/to/chart --format sarif --output results.sarif
```

## Ecosystem Tested

- odh-gitops: 3 findings (tuned with real-world feedback)
- 18 bitnami charts: zero crashes, FP rate reduced to ~15%
- 3 prometheus-community charts, 3 grafana charts

## License

Apache 2.0
