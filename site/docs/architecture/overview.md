# Architecture Overview

## Three-tier parser design

Helm templates contain Go template directives (`{{ }}`, `{{- with }}`, `toYaml | nindent`) that make them invalid YAML. helm-guard uses a three-tier parser to handle this:

### Tier 1: Structured YAML

- **Files**: Chart.yaml, Chart.lock, values.yaml, values.schema.json
- **Parser**: `ruamel.yaml` (round-trip mode for line number tracking)
- **Reliability**: High, no false negatives
- **Checks**: PIN-001..005, TRUST-001..005, TRUST-007, OLM-001..004, PROV-001, SEC-001..002, SEC-004, SEC-006, DEP-001..004

### Tier 2: Text/regex heuristics

- **Files**: templates/*.yaml, templates/*.tpl
- **Parser**: Line-by-line text scanning with regex
- **Reliability**: May miss complex patterns (documented FN rate)
- **Checks**: INJ-001..008, HOOK-001..003, TRUST-006, SEC-003, SEC-005, NS-002
- **Limitation**: Cannot determine resolved values (e.g., whether `securityContext.runAsNonRoot` is true after `toYaml`)

### Tier 3: Rendered output

- **Files**: Output of `helm template`
- **Parser**: Standard YAML parsing of rendered K8s manifests
- **Checks**: NS-001
- **Availability**: Opt-in via `--render` flag
- **Risk**: Go template functions execute during rendering, so untrusted charts could run arbitrary code

Static mode (default) = Tier 1 + Tier 2. No external tool dependency.

## Project structure

```
helm_guard/
    parser.py           # Three-tier parser
    checks/
        __init__.py     # importlib auto-discovery, run_checks
        _common.py      # @register_check, _finding, severity
        pinning.py      # HLM-PIN-001..005
        injection.py    # HLM-INJ-001..008
        trust.py        # HLM-TRUST-001..007
        hooks.py        # HLM-HOOK-001..003
        olm.py          # HLM-OLM-001..004
        security.py     # HLM-SEC-001..006
        provenance.py   # HLM-PROV-001
        namespace.py    # HLM-NS-001..002
        deps.py         # HLM-DEP-001..004
    config.py           # Trust lists, configurable thresholds
    formatter.py        # JSON, SARIF, text output
    cli.py              # CLI entry point
```

## Check registration

Checks are registered via the `@register_check` decorator in `_common.py`. The check ID is extracted from the function's docstring at registration time. The `checks/__init__.py` module auto-discovers all check modules using `importlib`.

## Output formats

- **JSON**: Structured report with findings, severity counts, and category breakdown
- **SARIF**: Static Analysis Results Interchange Format for GitHub Code Scanning integration
- **Text**: Human-readable terminal output with severity labels and remediation hints
