# helm-guard

Security scanner for Helm chart supply chain integrity.

## Demo

![Demo](images/demo.gif)

helm-guard checks what no existing tool covers: dependency pinning, template injection via `tpl`, hook security, values trust chains, OLM subscription security, and chart provenance. Static analysis by default (no `helm` CLI dependency).

## 37 checks across 10 categories

| ID | Category | Severity | Description |
|----|----------|----------|-------------|
| HLM-PIN-001 | Pinning | HIGH | Chart dependency with SemVer range |
| HLM-PIN-002 | Pinning | HIGH | Missing Chart.lock when dependencies exist |
| HLM-PIN-003 | Pinning | MEDIUM | Mutable image tag in values.yaml |
| HLM-PIN-004 | Pinning | MEDIUM | OLM subscription channel not version-pinned |
| HLM-PIN-005 | Pinning | MEDIUM | Chart version not following SemVer |
| HLM-INJ-001 | Injection | CRITICAL | `tpl` function usage (Go template RCE) |
| HLM-INJ-002 | Injection | HIGH | `.Values` in shell context without `quote` |
| HLM-INJ-003 | Injection | MEDIUM | `.Values` in `name:` without `trunc 63` |
| HLM-INJ-004 | Injection | CRITICAL | `lookup` function in template (cluster data exfil) |
| HLM-INJ-005 | Injection | HIGH | `env`/`expandenv` function (host env leak) |
| HLM-INJ-006 | Injection | HIGH | `.Files.Get`/`.Files.Glob` with `.Values` path |
| HLM-INJ-007 | Injection | MEDIUM | Hardcoded container registry in template |
| HLM-INJ-008 | Injection | HIGH | `getHostByName` DNS exfiltration (CVE-2023-25165) |
| HLM-TRUST-001 | Trust | HIGH | No values.schema.json |
| HLM-TRUST-002 | Trust | HIGH | Secrets with non-empty defaults in values.yaml |
| HLM-TRUST-003 | Trust | HIGH | Dependency from untrusted repository |
| HLM-TRUST-004 | Trust | HIGH | `hostNetwork`/`hostPID` enabled in values defaults |
| HLM-TRUST-005 | Trust | MEDIUM | HTTP URL in values.yaml (cleartext connection) |
| HLM-TRUST-006 | Trust | MEDIUM | Permissive NetworkPolicy in templates |
| HLM-HOOK-001 | Hooks | HIGH | Hook Job without security context reference |
| HLM-HOOK-002 | Hooks | MEDIUM | Hook with before-hook-creation delete policy |
| HLM-HOOK-003 | Hooks | HIGH | Post-renderer executing external script |
| HLM-OLM-001 | OLM | HIGH | Automatic install plan without version pin |
| HLM-OLM-002 | OLM | MEDIUM | Subscription using community catalog |
| HLM-OLM-003 | OLM | MEDIUM | Operator in privileged namespace |
| HLM-OLM-004 | OLM | HIGH | Automatic approval with unstable channel |
| HLM-PROV-001 | Provenance | INFO | Chart not signed (disabled by default) |
| HLM-NS-001 | Namespace | HIGH | Resource in privileged namespace (render mode) |
| HLM-NS-002 | Namespace | MEDIUM | Release namespace without schema restriction |
| HLM-SEC-001 | Security | HIGH | Path traversal in chart name (CVE-2024-25620) |
| HLM-SEC-002 | Security | CRITICAL | Chart.lock symlink arbitrary write (CVE-2025-53547) |
| HLM-SEC-003 | Security | HIGH | valueFiles path traversal (CVE-2022-24348) |
| HLM-SEC-004 | Security | HIGH | Plugin version path traversal (CVE-2026-35204) |
| HLM-SEC-005 | Security | MEDIUM | ServiceAccount token automount not disabled |
| HLM-DEP-001 | Dependencies | MEDIUM | Subchart values override of security fields |
| HLM-DEP-002 | Dependencies | LOW | Dependency version conflict (Chart.yaml vs Chart.lock) |
| HLM-DEP-003 | Dependencies | HIGH | Potential dependency name typosquat |

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
