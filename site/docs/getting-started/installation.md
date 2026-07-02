# Installation

## From PyPI

```bash
pip install helm-guard
```

## From source

```bash
git clone https://github.com/ugiordan/helm-guard.git
cd helm-guard
pip install -e .
```

## Requirements

- Python 3.10+
- `ruamel.yaml` (installed automatically)

No `helm` CLI dependency required for static analysis (Tier 1 + Tier 2 checks). The optional `--render` flag (Tier 3) requires the `helm` CLI to be installed.

## Verify installation

```bash
helm-guard --help
```
