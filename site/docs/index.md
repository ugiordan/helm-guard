# helm-guard

Security scanner for Helm chart supply chain integrity.

## Demo

![Demo](images/demo.gif)

helm-guard checks what no existing tool covers: dependency pinning, template injection via `tpl`, hook security, values trust chains, OLM subscription security, and chart provenance. Static analysis by default (no `helm` CLI dependency).

## 20 checks across 8 categories

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
| HLM-HOOK-001 | Hooks | HIGH | Hook Job without security context reference |
| HLM-HOOK-002 | Hooks | MEDIUM | Hook with before-hook-creation delete policy |
| HLM-OLM-001 | OLM | HIGH | Automatic install plan without version pin |
| HLM-OLM-002 | OLM | MEDIUM | Subscription using community catalog |
| HLM-OLM-003 | OLM | MEDIUM | Operator in privileged namespace |
| HLM-PROV-001 | Provenance | INFO | Chart not signed (disabled by default) |
| HLM-NS-001 | Namespace | HIGH | Resource in privileged namespace (render mode) |
| HLM-NS-002 | Namespace | MEDIUM | Release namespace without schema restriction |
| HLM-DEP-001 | Dependencies | MEDIUM | Subchart values override of security fields |
| HLM-DEP-002 | Dependencies | LOW | Dependency version conflict (Chart.yaml vs Chart.lock) |

## Quick start

```bash
pip install helm-guard
helm-guard /path/to/chart
```

See [Installation](getting-started/installation.md) and [Quickstart](getting-started/quickstart.md) for details.

## Scope boundary

helm-guard checks chart-level supply chain integrity. It does not duplicate existing tools:

| helm-guard covers | kube-linter covers | kube-chainsaw covers |
|---|---|---|
| Dependency pinning (Chart.yaml/Chart.lock) | Resource best practices (probes, limits) | RBAC privilege escalation chains |
| `tpl` function injection | Pod security (rendered) | SA -> Role -> permission graphs |
| Hook annotation security | Namespace usage (default only) | |
| Values trust (schema, secrets) | SA token automount (pod-spec level) | |
| Chart provenance | | |
| OLM subscription security | | |
