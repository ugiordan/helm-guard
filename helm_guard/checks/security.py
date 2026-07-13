"""Security checks based on real Helm CVEs and attack techniques (HLM-SEC-001..014)."""

from __future__ import annotations

import os
import re
from typing import Any

from helm_guard.checks._common import register_check, _finding
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo


@register_check
def check_sec_001(chart, config) -> list[dict]:
    """HLM-SEC-001: Path traversal in Chart.yaml name field."""
    if not chart.chart_yaml:
        return []
    name = str(chart.chart_yaml.get("name", ""))
    if ".." in name or "/" in name or "\\" in name:
        return [_finding(
            "HLM-SEC-001", "HIGH", "Path traversal in chart name",
            chart.chart_dir, os.path.join(chart.chart_dir, "Chart.yaml"), 0,
            f"Chart.yaml name '{name}' contains path traversal sequences. "
            f"CVE-2024-25620 and CVE-2026-35206 demonstrated that chart names "
            f"with ../ can write files outside intended directories during "
            f"chart archive extraction.",
            cwe="CWE-22",
            remediation="Use a simple chart name without path separators or traversal sequences.",
            extra={"name": name},
        )]
    return []


@register_check
def check_sec_002(chart, config) -> list[dict]:
    """HLM-SEC-002: Chart.lock is a symlink."""
    lock_path = os.path.join(chart.chart_dir, "Chart.lock")
    if os.path.islink(lock_path):
        target = os.readlink(lock_path)
        return [_finding(
            "HLM-SEC-002", "CRITICAL", "Chart.lock is a symlink",
            chart.chart_dir, "Chart.lock", 0,
            f"Chart.lock is a symlink pointing to '{target}'. "
            f"CVE-2025-53547 (CVSS 8.5) demonstrated that a symlinked "
            f"Chart.lock enables arbitrary code execution when Helm writes "
            f"dependency data through the symlink to the target file.",
            cwe="CWE-59",
            remediation="Remove the symlink and create a regular Chart.lock file via helm dependency build.",
            extra={"symlink_target": target},
        )]
    return []


@register_check
def check_sec_003(chart, config) -> list[dict]:
    """HLM-SEC-003: valueFiles with absolute path or traversal."""
    findings = []
    # Check for valueFiles references in templates and values
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if 'valueFiles' not in line and 'valuesFiles' not in line:
                continue
            # Extract values from the line and check each one
            path_items = re.findall(r'["\']([^"\']+)["\']', line)
            has_dangerous_path = False
            for item in path_items:
                item_stripped = item.strip()
                if item_stripped.startswith('/') or item_stripped.startswith('..'):
                    has_dangerous_path = True
                    break
            if has_dangerous_path:
                findings.append(_finding(
                    "HLM-SEC-003", "HIGH", "valueFiles with absolute path or traversal",
                    chart.chart_dir, tmpl.path, i,
                    "Template references valueFiles with an absolute path or "
                    "directory traversal. CVE-2022-24348 demonstrated this enables "
                    "reading sensitive files from Argo CD reposerver, bypassing "
                    "path validation via URI parsing confusion.",
                    cwe="CWE-22",
                    remediation="Use relative paths within the chart directory only. Do not use absolute paths or ../ in valueFiles.",
                ))
    return findings


@register_check
def check_sec_004(chart, config) -> list[dict]:
    """HLM-SEC-004: Plugin version with path traversal."""
    # Check for plugin.yaml files in the chart
    plugin_yaml = os.path.join(chart.chart_dir, "plugin.yaml")
    if not os.path.exists(plugin_yaml):
        return []
    try:
        from ruamel.yaml import YAML
        yaml = YAML(typ="safe")
        with open(plugin_yaml) as f:
            data = yaml.load(f)
        if not data:
            return []
        version = str(data.get("version", ""))
        if ".." in version or "/" in version:
            return [_finding(
                "HLM-SEC-004", "HIGH", "Plugin version with path traversal",
                chart.chart_dir, "plugin.yaml", 0,
                f"plugin.yaml version '{version}' contains path traversal sequences. "
                f"CVE-2026-35204 (CVSS 8.4) demonstrated this enables arbitrary "
                f"filesystem writes during plugin installation.",
                cwe="CWE-22",
                remediation="Use a clean SemVer version string without path separators.",
                extra={"version": version},
            )]
    except Exception:
        pass
    return []


@register_check
def check_sec_005(chart, config) -> list[dict]:
    """HLM-SEC-005: SA token automount not disabled in templates."""
    findings = []
    for tmpl in chart.template_files:
        content = tmpl.content
        if 'ServiceAccount' not in content:
            continue
        if 'kind: ServiceAccount' not in content and "kind: 'ServiceAccount'" not in content and 'kind: "ServiceAccount"' not in content:
            continue
        # Split by YAML document separator to check each SA independently
        documents = re.split(r'^---\s*$', content, flags=re.MULTILINE)
        line_offset = 0
        for doc_idx, doc in enumerate(documents):
            # Strip leading newline left by re.split for documents after the first
            if doc_idx > 0 and doc.startswith('\n'):
                doc = doc[1:]
            doc_lines = doc.splitlines()
            # Find SA resource definitions in this document
            sa_line = 0
            is_sa_resource = False
            for i, line in enumerate(doc_lines, 1):
                stripped = line.strip()
                indent = len(line) - len(line.lstrip())
                if stripped in ('kind: ServiceAccount', "kind: 'ServiceAccount'", 'kind: "ServiceAccount"') and indent <= 2:
                    is_sa_resource = True
                    sa_line = line_offset + i
                    break
            if is_sa_resource:
                # Strip YAML comments from the document before checking
                uncommented = "\n".join(
                    line for line in doc.splitlines()
                    if not line.strip().startswith("#")
                )
                # Also strip Go template comments
                uncommented = re.sub(r'\{\{-?\s*/\*.*?\*/\s*-?\}\}', '', uncommented, flags=re.DOTALL)
                has_automount_false = 'automountServiceAccountToken: false' in uncommented
                has_automount_templated = any(
                    'automountServiceAccountToken:' in uline and '{{' in uline
                    for uline in uncommented.splitlines()
                )
                if not has_automount_false and not has_automount_templated:
                    findings.append(_finding(
                        "HLM-SEC-005", "MEDIUM",
                        "ServiceAccount without automountServiceAccountToken disabled",
                        chart.chart_dir, tmpl.path, sa_line,
                        "Template creates a ServiceAccount without explicitly setting "
                        "automountServiceAccountToken: false. VoidLink malware targets "
                        "/var/run/secrets/ tokens in 22% of cloud environments.",
                        cwe="CWE-269",
                        remediation="Add automountServiceAccountToken: false to ServiceAccount specs.",
                    ))
            # +1 for the --- separator line itself
            line_offset += len(doc_lines) + 1
    return findings


@register_check
def check_sec_006(chart, config) -> list[dict]:
    """HLM-SEC-006: Missing .helmignore file."""
    helmignore = os.path.join(chart.chart_dir, ".helmignore")
    if os.path.exists(helmignore):
        return []
    return [_finding(
        "HLM-SEC-006", "MEDIUM", "Missing .helmignore file",
        chart.chart_dir, chart.chart_dir, 0,
        "Chart has no .helmignore file. When packaged, sensitive files "
        "(.git/, .env, private keys, CI configs) may be included in the "
        "chart archive and distributed to users.",
        cwe="CWE-200",
        remediation="Add a .helmignore file. See helm create for the default template.",
    )]


# ---------------------------------------------------------------------------
# New checks: SEC-007 through SEC-014
# ---------------------------------------------------------------------------

# Full closed Go template comment for stripping (shared with injection.py)
_GO_COMMENT_FULL_RE = re.compile(r'\{\{-?\s*/\*.*?\*/\s*-?\}\}', re.DOTALL)

# Workload kinds that define pod specs
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}

# Dangerous Linux capabilities
_DANGEROUS_CAPS_HIGH = {"SYS_ADMIN", "ALL"}
_DANGEROUS_CAPS_MEDIUM = {"NET_RAW", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE",
                          "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"}
_DANGEROUS_CAPS = _DANGEROUS_CAPS_HIGH | _DANGEROUS_CAPS_MEDIUM


def _split_yaml_documents(content: str) -> list[tuple[str, int]]:
    """Split YAML content by --- separator, returning (doc_text, line_offset) pairs."""
    documents = re.split(r'^---\s*$', content, flags=re.MULTILINE)
    result = []
    line_offset = 0
    for doc_idx, doc in enumerate(documents):
        if doc_idx > 0 and doc.startswith('\n'):
            doc = doc[1:]
        result.append((doc, line_offset))
        line_offset += len(doc.splitlines()) + 1
    return result


def _strip_comments(doc: str) -> str:
    """Strip YAML comments and Go template comments from a document."""
    # Strip Go template comments first
    cleaned = _GO_COMMENT_FULL_RE.sub('', doc)
    # Strip YAML comment lines
    lines = []
    for line in cleaned.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _has_workload_kind(doc: str) -> bool:
    """Check if a YAML document contains a workload kind."""
    for line in doc.splitlines():
        stripped = line.strip()
        for kind in _WORKLOAD_KINDS:
            if stripped == f"kind: {kind}" or stripped == f'kind: "{kind}"' or stripped == f"kind: '{kind}'":
                return True
    return False


@register_check
def check_sec_007(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-007: Wildcard RBAC in templates."""
    findings = []
    for tmpl in chart.template_files:
        for doc, line_offset in _split_yaml_documents(tmpl.content):
            cleaned = _strip_comments(doc)
            # Must find Role or ClusterRole kind in this document
            is_rbac = False
            for line in cleaned.splitlines():
                stripped = line.strip()
                if stripped in (
                    "kind: Role", 'kind: "Role"', "kind: 'Role'",
                    "kind: ClusterRole", 'kind: "ClusterRole"', "kind: 'ClusterRole'",
                ):
                    is_rbac = True
                    break
            if not is_rbac:
                continue
            # Look for wildcard in rules section
            in_rules = False
            for i, line in enumerate(cleaned.splitlines(), 1):
                stripped = line.strip()
                if stripped == "rules:" or stripped.startswith("rules:"):
                    in_rules = True
                    continue
                if not in_rules:
                    continue
                # Detect end of rules block (non-indented, non-list line)
                indent = len(line) - len(line.lstrip()) if line.strip() else 999
                if indent == 0 and stripped and not stripped.startswith("-"):
                    in_rules = False
                    continue
                # Check for wildcard: '- "*"' or "- '*'" or '- "*"' forms
                # Must be a YAML list item with just the wildcard
                wildcard_match = re.match(r"""^\s*-\s*['"]?\*['"]?\s*$""", stripped)
                if wildcard_match:
                    findings.append(_finding(
                        "HLM-SEC-007", "HIGH", "Wildcard RBAC in templates",
                        chart.chart_dir, tmpl.path, line_offset + i,
                        "Role/ClusterRole rule contains wildcard '*' granting "
                        "access to all resources/verbs/apiGroups. This violates "
                        "the principle of least privilege.",
                        cwe="CWE-250",
                        remediation="Replace wildcards with specific resources, verbs, and API groups.",
                    ))
    return findings


@register_check
def check_sec_008(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-008: hostPath volume in templates."""
    findings = []
    for tmpl in chart.template_files:
        for doc, line_offset in _split_yaml_documents(tmpl.content):
            cleaned = _strip_comments(doc)
            if not _has_workload_kind(doc):
                continue
            if "hostPath:" not in cleaned:
                continue
            # Find hostPath: lines and check context
            lines = cleaned.splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("hostPath:") or stripped == "hostPath:":
                    # Check if inside a Go template conditional that could disable it
                    in_conditional = False
                    for j in range(max(0, i - 10), i - 1):
                        prev = lines[j].strip()
                        if re.match(r'\{\{-?\s*if\b', prev):
                            in_conditional = True
                            break
                    # Check for readOnly in nearby volumeMount
                    has_readonly = False
                    for j in range(max(0, i - 15), min(len(lines), i + 15)):
                        check_line = lines[j].strip()
                        if "readOnly: true" in check_line:
                            has_readonly = True
                            break
                    severity = "HIGH" if has_readonly else "CRITICAL"
                    # If inside conditional, downgrade to MEDIUM max
                    if in_conditional:
                        severity = "MEDIUM" if severity == "CRITICAL" else "LOW"
                    findings.append(_finding(
                        "HLM-SEC-008", severity,
                        "hostPath volume in templates",
                        chart.chart_dir, tmpl.path, line_offset + i,
                        "Template mounts a hostPath volume, giving containers "
                        "access to host filesystem paths. Writable hostPath "
                        "mounts enable container escapes.",
                        cwe="CWE-250",
                        remediation="Use PersistentVolumeClaims or emptyDir instead. "
                        "If hostPath is necessary, mount readOnly and restrict the path.",
                    ))
    return findings


@register_check
def check_sec_009(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-009: Dangerous Linux capabilities in templates."""
    findings = []
    for tmpl in chart.template_files:
        for doc, line_offset in _split_yaml_documents(tmpl.content):
            cleaned = _strip_comments(doc)
            if "capabilities:" not in cleaned:
                continue
            lines = cleaned.splitlines()
            in_security_context = False
            in_capabilities = False
            in_add = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if "securityContext:" in stripped:
                    in_security_context = True
                    continue
                if not in_security_context:
                    continue
                if "capabilities:" in stripped:
                    in_capabilities = True
                    continue
                if not in_capabilities:
                    continue
                if stripped == "add:" or stripped.startswith("add:"):
                    in_add = True
                    continue
                if stripped == "drop:" or stripped.startswith("drop:"):
                    in_add = False
                    continue
                # Reset on dedent (new top-level key)
                indent = len(line) - len(line.lstrip()) if stripped else 999
                if indent <= 4 and stripped and not stripped.startswith("-"):
                    in_security_context = False
                    in_capabilities = False
                    in_add = False
                    continue
                if not in_add:
                    continue
                # Check for dangerous capabilities in list items
                cap_match = re.match(r"^\s*-\s*(.+)$", stripped)
                if not cap_match:
                    continue
                cap_val = cap_match.group(1).strip().strip("'\"")
                # FP guard: skip if the capability value is a .Values interpolation
                if "{{" in cap_val and ".Values" in cap_val:
                    continue
                if cap_val in _DANGEROUS_CAPS:
                    severity = "HIGH" if cap_val in _DANGEROUS_CAPS_HIGH else "MEDIUM"
                    findings.append(_finding(
                        "HLM-SEC-009", severity,
                        f"Dangerous capability {cap_val} in template",
                        chart.chart_dir, tmpl.path, line_offset + i,
                        f"Container adds Linux capability '{cap_val}'. "
                        f"This capability grants elevated host access and "
                        f"can be used for container escape.",
                        cwe="CWE-250",
                        remediation=f"Remove '{cap_val}' from capabilities.add. "
                        "Use 'drop: [ALL]' and add only specific caps needed.",
                        extra={"capability": cap_val},
                    ))
    return findings


@register_check
def check_sec_010(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-010: Workload without runAsNonRoot in templates."""
    findings = []
    for tmpl in chart.template_files:
        for doc, line_offset in _split_yaml_documents(tmpl.content):
            if not _has_workload_kind(doc):
                continue
            cleaned = _strip_comments(doc)
            # Accept runAsNonRoot: true (literal or templated)
            has_run_as_non_root = False
            has_run_as_user_nonzero = False
            for line in cleaned.splitlines():
                stripped = line.strip()
                if "runAsNonRoot:" in stripped:
                    has_run_as_non_root = True
                    break
                # Also accept if runAsUser is set to a non-zero value
                run_as_user_match = re.match(r"runAsUser:\s*(\d+)", stripped)
                if run_as_user_match and run_as_user_match.group(1) != "0":
                    has_run_as_user_nonzero = True
            if has_run_as_non_root or has_run_as_user_nonzero:
                continue
            # Find the kind line for reporting
            kind_line = 1
            for i, line in enumerate(doc.splitlines(), 1):
                stripped = line.strip()
                for kind in _WORKLOAD_KINDS:
                    if stripped == f"kind: {kind}" or stripped == f'kind: "{kind}"' or stripped == f"kind: '{kind}'":
                        kind_line = i
                        break
            findings.append(_finding(
                "HLM-SEC-010", "MEDIUM",
                "Workload without runAsNonRoot",
                chart.chart_dir, tmpl.path, line_offset + kind_line,
                "Template defines a workload without setting "
                "runAsNonRoot: true in securityContext. Containers may "
                "run as root, increasing the blast radius of escapes.",
                cwe="CWE-250",
                remediation="Add securityContext.runAsNonRoot: true to pod or container spec.",
            ))
    return findings


@register_check
def check_sec_011(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-011: Container without resource limits in templates."""
    findings = []
    for tmpl in chart.template_files:
        for doc, line_offset in _split_yaml_documents(tmpl.content):
            if not _has_workload_kind(doc):
                continue
            cleaned = _strip_comments(doc)
            # Only flag if there is NO resources: block at all in the document.
            # This avoids noise on charts that have resources but maybe not
            # structured exactly as expected.
            if "resources:" in cleaned:
                continue
            # Find the kind line for reporting
            kind_line = 1
            for i, line in enumerate(doc.splitlines(), 1):
                stripped = line.strip()
                for kind in _WORKLOAD_KINDS:
                    if stripped == f"kind: {kind}" or stripped == f'kind: "{kind}"' or stripped == f"kind: '{kind}'":
                        kind_line = i
                        break
            findings.append(_finding(
                "HLM-SEC-011", "LOW",
                "Container without resource limits",
                chart.chart_dir, tmpl.path, line_offset + kind_line,
                "Template defines a workload without any resource limits. "
                "Without limits, a compromised container can consume all "
                "node resources (CPU/memory), causing denial of service.",
                cwe="CWE-400",
                remediation="Add resources.limits with CPU and memory constraints.",
            ))
    return findings


@register_check
def check_sec_012(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-012: Schema $ref to external resource (CVE-2025-55199)."""
    if chart.values_schema is None:
        return []
    findings = []
    schema_path = os.path.join(chart.chart_dir, "values.schema.json")

    def _walk_refs(data: Any, json_path: str = "$") -> None:
        if isinstance(data, dict):
            for key, val in data.items():
                current = f"{json_path}.{key}"
                if key == "$ref" and isinstance(val, str):
                    val_stripped = val.strip()
                    # Internal refs are fine
                    if val_stripped.startswith("#"):
                        continue
                    # Flag external URLs and /dev/ references
                    if val_stripped.startswith(("http://", "https://", "/dev/")):
                        findings.append(_finding(
                            "HLM-SEC-012", "HIGH",
                            "Schema $ref to external resource",
                            chart.chart_dir, schema_path, 1,
                            f"values.schema.json contains $ref to external "
                            f"resource: '{val_stripped[:100]}'. External schema "
                            f"references can be exploited for SSRF or DoS "
                            f"(CVE-2025-55199).",
                            cwe="CWE-400",
                            remediation="Inline the schema definition or use internal $ref (#/definitions/...).",
                            extra={"ref": val_stripped[:200], "json_path": current},
                        ))
                else:
                    _walk_refs(val, current)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                _walk_refs(item, f"{json_path}[{i}]")

    _walk_refs(chart.values_schema)
    return findings


@register_check
def check_sec_013(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-013: ArgoCD Application with HTTP chart source."""
    findings = []
    for tmpl in chart.template_files:
        for doc, line_offset in _split_yaml_documents(tmpl.content):
            cleaned = _strip_comments(doc)
            # Must be an ArgoCD Application
            has_application_kind = False
            has_argoproj_api = False
            for line in cleaned.splitlines():
                stripped = line.strip()
                if stripped in ("kind: Application", 'kind: "Application"', "kind: 'Application'"):
                    has_application_kind = True
                if "argoproj.io" in stripped and "apiVersion:" in stripped:
                    has_argoproj_api = True
            if not has_application_kind or not has_argoproj_api:
                continue
            # Look for repoURL with http://
            for i, line in enumerate(cleaned.splitlines(), 1):
                stripped = line.strip()
                if "repoURL:" not in stripped:
                    continue
                # Extract the URL value
                url_match = re.search(r"repoURL:\s*['\"]?(http://\S+)", stripped)
                if not url_match:
                    continue
                url = url_match.group(1).strip("'\"")
                # Skip localhost/loopback
                if "localhost" in url or "127.0.0.1" in url:
                    continue
                findings.append(_finding(
                    "HLM-SEC-013", "MEDIUM",
                    "ArgoCD Application with HTTP source",
                    chart.chart_dir, tmpl.path, line_offset + i,
                    f"ArgoCD Application references chart source over HTTP: "
                    f"'{url[:100]}'. HTTP URLs are vulnerable to "
                    f"man-in-the-middle attacks during chart fetching.",
                    cwe="CWE-319",
                    remediation="Use HTTPS for all ArgoCD repository URLs.",
                    extra={"url": url[:200]},
                ))
    return findings


@register_check
def check_sec_014(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-SEC-014: Suspicious chart complexity."""
    findings = []
    templates_dir = os.path.join(chart.chart_dir, "templates")
    # Count template files only
    template_count = len(chart.template_files)
    if template_count > 200:
        findings.append(_finding(
            "HLM-SEC-014", "MEDIUM",
            "Suspicious chart complexity (excessive templates)",
            chart.chart_dir, templates_dir, 0,
            f"Chart contains {template_count} template files, which is "
            f"unusually high (typical charts have <30). This could indicate "
            f"a decompression bomb or obfuscation attempt.",
            cwe="CWE-400",
            remediation="Review chart contents. Consider splitting into subcharts.",
            extra={"template_count": template_count},
        ))
    # Check charts/ subdirectory depth
    charts_dir = os.path.join(chart.chart_dir, "charts")
    if os.path.isdir(charts_dir):
        max_depth = 0
        base_depth = charts_dir.count(os.sep)
        for dirpath, dirnames, _filenames in os.walk(charts_dir, followlinks=False):
            # Only count directories named "charts" in the depth
            depth = dirpath.count(os.sep) - base_depth
            if depth > max_depth:
                max_depth = depth
        if max_depth > 5:
            findings.append(_finding(
                "HLM-SEC-014", "MEDIUM",
                "Suspicious chart complexity (deep nesting)",
                chart.chart_dir, charts_dir, 0,
                f"Chart has subchart nesting depth of {max_depth} levels. "
                f"Deeply nested subcharts may indicate a decompression bomb.",
                cwe="CWE-400",
                remediation="Flatten subchart hierarchy. Most charts need at most 2 levels.",
                extra={"max_depth": max_depth},
            ))
    return findings
