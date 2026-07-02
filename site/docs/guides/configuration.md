# Configuration

## Config file

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
  - "HLM-PROV-001"  # fires on nearly every chart

min_severity: "LOW"

privileged_namespaces:
  - "kube-system"
  - "kube-public"
  - "default"
  - "openshift-operators"

secret_key_patterns:
  - "password"
  - "token"
  - "secret"
  - "apiKey"
  - "credentials"
```

## Configuration options

### trusted_chart_repos

List of trusted Helm chart repository URLs. Dependencies from repositories not in this list trigger HLM-TRUST-003.

Matching uses prefix with path boundary checking. `oci://quay.io/opendatahub/` trusts `oci://quay.io/opendatahub/my-chart` but rejects `oci://quay.io/opendatahub-evil/malware`.

### trusted_olm_sources

List of trusted OLM catalog sources. Used by HLM-OLM-002 to identify community catalogs.

### skip_checks

List of check IDs to skip. HLM-PROV-001 is disabled by default because it fires on nearly every chart (most charts are not signed).

### min_severity

Minimum severity level to report. Options: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Default: `LOW`.

### privileged_namespaces

List of namespaces considered privileged. Used by HLM-OLM-003 and HLM-NS-001.

Default: `kube-system`, `kube-public`, `default`, `openshift-operators`.

### secret_key_patterns

List of key name patterns that indicate secret values. Used by HLM-TRUST-002 with word-boundary matching (e.g., `dbPassword` matches `password`, but `passwordPolicy` does not).

## CLI overrides

The `--min-severity` flag overrides the config file value:

```bash
helm-guard /path/to/chart --config .helm-guard.yaml --min-severity HIGH
```

## Type validation

The config loader validates types silently. Invalid types (e.g., a string where a list is expected) are dropped and defaults are used instead.
