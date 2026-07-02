# Rules Reference

helm-guard implements 29 checks across 8 categories. Each check operates at a specific parser tier.

## Parser tiers

| Tier | Files | Parser | Reliability |
|------|-------|--------|-------------|
| Tier 1 | Chart.yaml, values.yaml, Chart.lock, values.schema.json | ruamel.yaml (structured YAML) | High, no false negatives |
| Tier 2 | templates/*.yaml, templates/*.tpl | Line-by-line text scanning with regex | May miss complex patterns |
| Tier 3 | Rendered output (via `helm template`) | YAML parsing of rendered manifests | Requires helm CLI, opt-in |

---

## Pinning (HLM-PIN)

### HLM-PIN-001: Chart dependency with SemVer range

- **Severity**: HIGH
- **CWE**: CWE-829
- **Tier**: 1
- **Detects**: `dependencies[].version` uses range operators (`^`, `~`, `>=`, `>`, `<`, `||`)
- **Remediation**: Pin to exact version (e.g., `version: 1.2.3`)

### HLM-PIN-002: Missing Chart.lock

- **Severity**: HIGH
- **CWE**: CWE-829
- **Tier**: 1
- **Detects**: Chart has dependencies in Chart.yaml but no Chart.lock
- **Remediation**: Run `helm dependency build` to generate Chart.lock

### HLM-PIN-003: Mutable image tag in values.yaml

- **Severity**: MEDIUM
- **CWE**: CWE-829
- **Tier**: 1
- **Detects**: Image-related keys with mutable tags (no `@sha256:` digest)
- **Remediation**: Pin images to digest

### HLM-PIN-004: OLM subscription channel not version-pinned

- **Severity**: MEDIUM
- **CWE**: CWE-829
- **Tier**: 1
- **Detects**: OLM channel like `stable`, `fast`, `alpha` without version suffix
- **Remediation**: Use versioned channels (e.g., `stable-v1.3`)

### HLM-PIN-005: Chart version not following SemVer

- **Severity**: MEDIUM
- **CWE**: CWE-1104
- **Tier**: 1
- **Detects**: Chart.yaml `version` field missing or not following strict SemVer format (`MAJOR.MINOR.PATCH`)
- **Remediation**: Use SemVer format (e.g., `1.2.3`)

---

## Injection (HLM-INJ)

### HLM-INJ-001: tpl function usage

- **Severity**: CRITICAL
- **CWE**: CWE-94
- **Tier**: 2
- **Detects**: Any `tpl` function call in template files. The `tpl` function executes its input as a Go template, enabling arbitrary code execution.
- **Remediation**: Avoid `tpl` entirely. Use direct value interpolation.

### HLM-INJ-002: Values in shell script without quote

- **Severity**: HIGH
- **CWE**: CWE-78
- **Tier**: 2
- **Detects**: `.Values.*` inside `sh -c`, `bash -c`, or `script:` blocks without pipe to `quote`/`squote`
- **Remediation**: Pipe values through `quote` in shell contexts

### HLM-INJ-003: Values in resource name without length control

- **Severity**: MEDIUM
- **CWE**: CWE-20
- **Tier**: 2
- **Detects**: `.Values.*` in lines containing `name:` without `trunc 63`
- **Remediation**: Use `{{ .Values.name | trunc 63 | trimSuffix "-" }}`

### HLM-INJ-004: lookup function in template

- **Severity**: CRITICAL
- **CWE**: CWE-94
- **Tier**: 2
- **Detects**: Any `lookup` function call inside `{{ }}` delimiters. The `lookup` function queries the live Kubernetes API during rendering, enabling exfiltration of cluster secrets and resources.
- **Remediation**: Remove lookup calls. Use known resource references instead of dynamic cluster queries.

### HLM-INJ-005: env/expandenv function in template

- **Severity**: HIGH
- **CWE**: CWE-200
- **Tier**: 2
- **Detects**: `env` or `expandenv` function calls inside `{{ }}` delimiters. These leak host environment variables (CI/CD secrets, tokens, credentials) into rendered manifests.
- **Remediation**: Remove env/expandenv calls. Pass values explicitly via values.yaml.

### HLM-INJ-006: .Files access with user-controlled path

- **Severity**: HIGH
- **CWE**: CWE-22
- **Tier**: 2
- **Detects**: `.Files.Get` or `.Files.Glob` calls where the path argument is derived from `.Values`. An attacker can craft values to read arbitrary files from the chart directory.
- **Remediation**: Hardcode file paths in .Files.Get calls. Do not use .Values for file path construction.

### HLM-INJ-007: Hardcoded container registry in template

- **Severity**: MEDIUM
- **CWE**: CWE-829
- **Tier**: 2
- **Detects**: Template files with hardcoded `image:` references (e.g., `image: docker.io/nginx:1.25`) that bypass `values.yaml` configuration. Skips lines with `{{ }}` expressions or comments.
- **Remediation**: Use `{{ .Values.image.repository }}:{{ .Values.image.tag }}` pattern to allow registry redirection.

---

## Trust (HLM-TRUST)

### HLM-TRUST-001: No values.schema.json

- **Severity**: HIGH
- **CWE**: CWE-20
- **Tier**: 1
- **Detects**: Chart has values.yaml but no values.schema.json
- **Remediation**: Add values.schema.json with type constraints

### HLM-TRUST-002: Secrets in values.yaml

- **Severity**: HIGH
- **CWE**: CWE-798
- **Tier**: 1
- **Detects**: Keys matching secret patterns (password, token, secret, apiKey) with non-empty defaults
- **Remediation**: Use empty defaults and set via `--set` or external secrets

### HLM-TRUST-003: Chart dependency from untrusted repository

- **Severity**: HIGH
- **CWE**: CWE-829
- **Tier**: 1
- **Detects**: `dependencies[].repository` not in trusted list. Checks both direct and transitive dependencies.
- **Remediation**: Use charts from trusted repos

### HLM-TRUST-004: hostNetwork/hostPID enabled in values defaults

- **Severity**: HIGH
- **CWE**: CWE-250
- **Tier**: 1
- **Detects**: `hostNetwork: true` or `hostPID: true` anywhere in values.yaml (recursive search). These give pods access to the host network/PID namespace, enabling container escape and network sniffing.
- **Remediation**: Set `hostNetwork: false` and `hostPID: false` as defaults. Users can override when needed.

### HLM-TRUST-005: HTTP URL in values.yaml (cleartext connection)

- **Severity**: MEDIUM
- **CWE**: CWE-319
- **Tier**: 1
- **Detects**: String values starting with `http://` (excluding localhost and 127.0.0.1). Data transmitted over HTTP is visible to network observers.
- **Remediation**: Use HTTPS URLs for all external endpoints.

### HLM-TRUST-006: Permissive NetworkPolicy in templates

- **Severity**: MEDIUM
- **CWE**: CWE-284
- **Tier**: 2
- **Detects**: Templates containing a NetworkPolicy resource with empty `ingress:`, `egress:`, or `spec: {}` blocks. Empty rules allow all traffic.
- **Remediation**: Define explicit ingress/egress rules. Avoid empty spec.

---

## Hooks (HLM-HOOK)

### HLM-HOOK-001: Hook Job without security context reference

- **Severity**: HIGH
- **CWE**: CWE-250
- **Tier**: 2
- **Detects**: Template with `helm.sh/hook` annotation that has no `securityContext` reference
- **Remediation**: Add securityContext to hook Job specs

### HLM-HOOK-002: Hook with before-hook-creation delete policy

- **Severity**: MEDIUM
- **CWE**: CWE-390
- **Tier**: 2
- **Detects**: `helm.sh/hook-delete-policy: before-hook-creation`
- **Remediation**: Use `hook-succeeded` or `hook-failed` delete policies

---

## OLM (HLM-OLM)

!!! note
    OLM checks are not Helm-specific. They scan OLM Subscription CRDs that happen to be in chart templates or values. These are included because production deployments (e.g., odh-gitops) deploy operators via Helm charts containing OLM Subscription CRDs.

### HLM-OLM-001: Automatic install plan without version pin

- **Severity**: HIGH
- **CWE**: CWE-829
- **Tier**: 1 + 2
- **Detects**: `installPlanApproval: Automatic` without `startingCSV` version pin
- **Remediation**: Use Manual approval or pin to CSV version

### HLM-OLM-002: Subscription using community catalog

- **Severity**: MEDIUM
- **CWE**: CWE-829
- **Tier**: 1 + 2
- **Detects**: `source: community-operators`
- **Remediation**: Use certified catalogs

### HLM-OLM-003: Operator in privileged namespace

- **Severity**: MEDIUM
- **CWE**: CWE-269
- **Tier**: 1 + 2
- **Detects**: Operator namespace in configurable `privileged_namespaces` list
- **Remediation**: Use dedicated namespace

### HLM-OLM-004: Automatic approval with unstable channel

- **Severity**: HIGH
- **CWE**: CWE-829
- **Tier**: 1
- **Detects**: OLM subscription with `installPlanApproval: Automatic` combined with an unstable channel (`alpha`, `beta`, `preview`, `dev`, `nightly`, `canary`). Unstable channels can push breaking or vulnerable operator versions automatically.
- **Remediation**: Use Manual approval for unstable channels, or switch to a stable channel.

---

## Provenance (HLM-PROV)

### HLM-PROV-001: Chart not signed

- **Severity**: INFO (disabled by default)
- **CWE**: CWE-345
- **Tier**: 1
- **Detects**: No `.prov` file
- **Remediation**: Sign with `helm package --sign` or Cosign

!!! warning
    This check fires on nearly every chart. It is disabled by default in `skip_checks`. Enable it by removing `HLM-PROV-001` from your skip list.

---

## Namespace (HLM-NS)

### HLM-NS-001: Resource in privileged namespace (render mode)

- **Severity**: HIGH
- **CWE**: CWE-269
- **Tier**: 3 (requires `--render`)
- **Detects**: Rendered resources in configurable `privileged_namespaces` list
- **Remediation**: Deploy to dedicated namespaces

!!! info
    This check only runs when `--render` is used. It is a superset of kube-linter's `use-namespace` check.

### HLM-NS-002: Release namespace without schema restriction

- **Severity**: MEDIUM
- **CWE**: CWE-269
- **Tier**: 2 + 1
- **Detects**: Templates use `.Release.Namespace` but values.schema.json doesn't constrain namespace values
- **Remediation**: Add namespace constraints in values.schema.json

---

## Dependencies (HLM-DEP)

### HLM-DEP-001: Subchart values override of security fields

- **Severity**: MEDIUM
- **CWE**: CWE-1188
- **Tier**: 1
- **Detects**: Parent values.yaml overrides subchart security fields (securityContext, RBAC, serviceAccount)
- **Remediation**: Audit subchart security overrides

### HLM-DEP-002: Dependency version conflict

- **Severity**: LOW
- **CWE**: CWE-1104
- **Tier**: 1
- **Detects**: Chart.lock has different version than Chart.yaml for same dependency (exact version specs only)
- **Remediation**: Run `helm dependency build` to refresh
