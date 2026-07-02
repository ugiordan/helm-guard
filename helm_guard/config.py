"""Configuration for helm-guard trust lists and check settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML


@dataclass
class ScannerConfig:
    trusted_chart_repos: list[str] = field(default_factory=lambda: [
        "https://charts.helm.sh/stable",
        "oci://quay.io/opendatahub/",
        "oci://registry.redhat.io/",
    ])

    trusted_olm_sources: list[str] = field(default_factory=lambda: [
        "redhat-operators",
        "certified-operators",
    ])

    skip_checks: list[str] = field(default_factory=lambda: [
        "HLM-PROV-001",  # fires on nearly every chart, disabled by default
    ])

    min_severity: str = "LOW"

    secret_key_patterns: list[str] = field(default_factory=lambda: [
        "password",
        "token",
        "secret",
        "apiKey",
        "apikey",
        "credentials",
    ])

    privileged_namespaces: list[str] = field(default_factory=lambda: [
        "kube-system",
        "kube-public",
        "default",
        "openshift-operators",
    ])

    def is_trusted_chart_repo(self, repo_url: str) -> bool:
        if not repo_url:
            return False
        normalized = repo_url.rstrip("/")
        for trusted in self.trusted_chart_repos:
            prefix = trusted.rstrip("/")
            if normalized.startswith(prefix) or normalized == prefix:
                return True
        return False

    def is_trusted_olm_source(self, source: str) -> bool:
        if not source:
            return False
        return source in self.trusted_olm_sources

    def should_run_check(self, check_id: str) -> bool:
        return check_id not in self.skip_checks


def load_config(config_path: str | Path | None = None) -> ScannerConfig:
    if config_path is None:
        return ScannerConfig()

    path = Path(config_path)
    if not path.exists():
        return ScannerConfig()

    yaml = YAML(typ="safe")
    try:
        with open(path) as f:
            data = yaml.load(f) or {}
    except Exception:
        return ScannerConfig()

    if not isinstance(data, dict):
        return ScannerConfig()

    kwargs: dict[str, Any] = {}
    field_names = [
        "trusted_chart_repos",
        "trusted_olm_sources",
        "skip_checks",
        "min_severity",
        "secret_key_patterns",
        "privileged_namespaces",
    ]
    for name in field_names:
        if name in data:
            kwargs[name] = data[name]

    return ScannerConfig(**kwargs)
