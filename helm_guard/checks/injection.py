"""Template injection checks for Helm charts (Tier 2: text/regex)."""

from __future__ import annotations

import re

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_TPL_RE = re.compile(r"\{\{-?\s*(?:\$?\w+\s*:=\s*)?tpl\b")

# Shell context patterns: lines containing sh -c, bash -c, or script:
# Known limitation (D-05): exec-form shell commands (e.g. ["/bin/sh", "-c", ...]),
# python -c, eval in configmap data, and heredoc patterns (sh <<EOF) are not detected.
_SHELL_CONTEXT_RE = re.compile(r"(sh\s+-c|bash\s+-c|/bin/sh\s+-c|/bin/bash\s+-c|\bscript:)")

# Detect YAML list items that indicate we're entering a shell command block
# e.g., "- sh", "- /bin/sh", "- bash", "- /bin/bash"
_SHELL_CMD_RE = re.compile(r"^\s*-\s+(sh|bash|/bin/sh|/bin/bash)\s*$")
# The -c flag on its own line in a YAML list
_SHELL_FLAG_RE = re.compile(r"^\s*-\s+-c\s*$")

# .Values reference
_VALUES_RE = re.compile(r"\.Values\.[a-zA-Z0-9_.]+")

# name: field pattern
_NAME_FIELD_RE = re.compile(r"^\s*name:")

# trunc 63 pattern
_TRUNC_RE = re.compile(r"trunc\s+63")


@register_check
def check_tpl_function(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-001: tpl function usage in templates."""
    findings = []
    for tmpl in chart.template_files:
        for lineno, line in enumerate(tmpl.content.splitlines(), start=1):
            if _TPL_RE.search(line):
                findings.append(_finding(
                    rule_id="HLM-INJ-001",
                    severity="CRITICAL",
                    title="tpl function usage",
                    chart_dir=chart.chart_dir,
                    file_path=tmpl.path,
                    line=lineno,
                    message=(
                        "Template uses 'tpl' function which executes input as a Go template, "
                        "enabling arbitrary code execution."
                    ),
                    cwe="CWE-94",
                    remediation="Avoid 'tpl' entirely. Use direct value interpolation instead.",
                ))
    return findings


@register_check
def check_values_in_shell_without_quote(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-002: Values in shell script without quote."""
    findings = []
    for tmpl in chart.template_files:
        in_shell_block = False
        saw_shell_cmd = False
        shell_base_indent = -1
        in_block_scalar = False
        block_scalar_indent = -1
        for lineno, line in enumerate(tmpl.content.splitlines(), start=1):
            stripped = line.rstrip()
            current_indent = len(line) - len(line.lstrip()) if stripped else 0

            # Detect inline shell context (sh -c on same line)
            if _SHELL_CONTEXT_RE.search(line):
                in_shell_block = True
                shell_base_indent = current_indent

            # Detect multi-line YAML list shell pattern:
            # - sh / - bash (line N), then - -c (line N+1), then block content
            if _SHELL_CMD_RE.match(stripped):
                saw_shell_cmd = True
            elif saw_shell_cmd and _SHELL_FLAG_RE.match(stripped):
                in_shell_block = True
                # Use indent - 1 so that sibling list items (same indent as
                # "- -c") are still considered inside the shell block.
                shell_base_indent = current_indent - 1
                saw_shell_cmd = False
            elif saw_shell_cmd:
                saw_shell_cmd = False

            # Reset shell block when indentation drops to or below the shell
            # command start level, but only for non-empty lines that aren't
            # block scalar markers (|, >, - |, etc.)
            if in_shell_block and stripped and shell_base_indent >= 0:
                is_block_marker = stripped.endswith("|") or stripped.endswith(">")
                if current_indent <= shell_base_indent and not is_block_marker:
                    if not _SHELL_CONTEXT_RE.search(line) and not _SHELL_FLAG_RE.match(stripped) and not _SHELL_CMD_RE.match(stripped):
                        in_shell_block = False

            # Track block scalar entry (lines ending with | or >)
            if stripped.endswith("|") or stripped.endswith(">") or stripped.endswith("|-") or stripped.endswith(">-"):
                in_block_scalar = True
                block_scalar_indent = current_indent

            # Exit block scalar when indentation drops below the marker
            if in_block_scalar and stripped and current_indent <= block_scalar_indent:
                if not (stripped.endswith("|") or stripped.endswith(">") or stripped.endswith("|-") or stripped.endswith(">-")):
                    in_block_scalar = False

            # Check for .Values in shell contexts
            if in_shell_block and _VALUES_RE.search(line):
                # Check each .Values reference individually for quote protection
                for ref_match in _VALUES_RE.finditer(line):
                    ref_text = ref_match.group(0)
                    ref_start = ref_match.start()
                    # Find the closing }} after this reference
                    closing = line.find("}}", ref_start)
                    if closing == -1:
                        closing = len(line)
                    segment = line[ref_start:closing]
                    if re.search(r'\|\s*(quote|squote)', segment):
                        continue  # This specific ref is quoted
                    findings.append(_finding(
                        rule_id="HLM-INJ-002",
                        severity="HIGH",
                        title="Values in shell context without quote",
                        chart_dir=chart.chart_dir,
                        file_path=tmpl.path,
                        line=lineno,
                        message=(
                            f"'{ref_text}' used in shell context without piping through 'quote'. "
                            "This enables shell injection via crafted values."
                        ),
                        cwe="CWE-78",
                        remediation="Pipe values through 'quote' in shell contexts: {{ .Values.foo | quote }}",
                    ))
                continue  # Don't fall through to later checks for this line

            if stripped == "" or stripped.startswith("---"):
                if stripped.startswith("---"):
                    in_shell_block = False
                    saw_shell_cmd = False
                    shell_base_indent = -1
                    in_block_scalar = False
                elif not in_block_scalar:
                    in_shell_block = False
                    saw_shell_cmd = False
                    shell_base_indent = -1

    return findings


@register_check
def check_values_in_name_without_trunc(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-003: Values in resource name without length control."""
    findings = []
    for tmpl in chart.template_files:
        for lineno, line in enumerate(tmpl.content.splitlines(), start=1):
            # Only check lines with name: field
            if not _NAME_FIELD_RE.search(line):
                continue
            # Check if .Values is used in the name
            if not _VALUES_RE.search(line):
                continue
            # Skip if trunc 63 is present
            if _TRUNC_RE.search(line):
                continue
            # Skip lines with include/template calls (they likely handle truncation)
            if "include" in line or "template" in line:
                continue
            # Skip deeply indented name: fields (likely configMapRef.name,
            # secretRef.name, port name, etc., not K8s metadata names)
            indent = len(line) - len(line.lstrip())
            if indent > 8:
                continue
            findings.append(_finding(
                rule_id="HLM-INJ-003",
                severity="MEDIUM",
                title="Values in resource name without length control",
                chart_dir=chart.chart_dir,
                file_path=tmpl.path,
                line=lineno,
                message=(
                    "'.Values.*' used in 'name:' field without 'trunc 63'. "
                    "K8s names must be <= 63 characters."
                ),
                cwe="CWE-20",
                remediation='Use {{ .Values.name | trunc 63 | trimSuffix "-" }}',
            ))
    return findings


_LOOKUP_RE = re.compile(r"\{\{-?\s*(?:\$?\w+\s*:=\s*)?lookup\b")
# Match sprig env/expandenv function calls, not "env" as a dict key or YAML key.
# Sprig calls look like: {{ env "HOME" }} or {{ expandenv "$PATH" }}
# False positive: dict "env" (list ...) where "env" is a string argument
_ENV_RE = re.compile(r'\{\{-?\s*(?:\$?\w+\s*:=\s*)?(?:env|expandenv)\s+["\'$]')
_ENV_PIPE_RE = re.compile(r'\|\s*(?:env|expandenv)\b')
_FILES_VALUES_RE = re.compile(r"\.Files\.(?:Get|Glob)\s+.*\.Values")
_HARDCODED_IMAGE_RE = re.compile(r"image:\s*[\"']?([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}/\S+)")
# Full closed Go template comment for stripping
_GO_COMMENT_FULL_RE = re.compile(r'\{\{-?\s*/\*.*?\*/\s*-?\}\}', re.DOTALL)


@register_check
def check_inj_004(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-004: lookup function in templates."""
    findings = []
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            cleaned_line = _GO_COMMENT_FULL_RE.sub('', line)
            if _LOOKUP_RE.search(cleaned_line):
                findings.append(_finding(
                    "HLM-INJ-004", "LOW", "lookup function in template",
                    chart.chart_dir, tmpl.path, i,
                    "Template uses the lookup function which queries the live cluster "
                    "API during rendering. This causes different behavior between "
                    "helm template (returns empty) and helm install (queries cluster). "
                    "On Helm < 3.2.0, CVE-2020-11013 allowed cluster access during "
                    "dry-run. On modern Helm, this is a design concern: templates "
                    "should produce consistent output regardless of cluster state.",
                    cwe="CWE-200",
                    remediation="Consider alternatives to lookup. If needed for CRD checks, "
                    "document the usage and ensure skipCrdCheck is available as a fallback.",
                ))
    return findings


@register_check
def check_inj_005(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-005: env or expandenv function in templates."""
    findings = []
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            cleaned_line = _GO_COMMENT_FULL_RE.sub('', line)
            if _ENV_RE.search(cleaned_line) or _ENV_PIPE_RE.search(cleaned_line):
                findings.append(_finding(
                    "HLM-INJ-005", "HIGH", "env/expandenv function in template",
                    chart.chart_dir, tmpl.path, i,
                    "Template uses env/expandenv which leaks host environment "
                    "variables into rendered manifests. CI/CD secrets, tokens, "
                    "and credentials may be exposed.",
                    cwe="CWE-200",
                    remediation="Remove env/expandenv calls. Pass values explicitly via values.yaml.",
                ))
    return findings


@register_check
def check_inj_006(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-006: .Files.Get or .Files.Glob with Values input."""
    findings = []
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            if _FILES_VALUES_RE.search(line):
                findings.append(_finding(
                    "HLM-INJ-006", "HIGH", ".Files access with user-controlled path",
                    chart.chart_dir, tmpl.path, i,
                    "Template reads files using a path derived from .Values. "
                    "An attacker can craft values to read arbitrary files from "
                    "the chart directory.",
                    cwe="CWE-22",
                    remediation="Hardcode file paths in .Files.Get calls. Do not use .Values for file path construction.",
                ))
    return findings


@register_check
def check_inj_007(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-007: Hardcoded container registry in template."""
    findings = []
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = _HARDCODED_IMAGE_RE.search(stripped)
            if match and ".Values" not in stripped and "{{" not in stripped:
                image = match.group(1).rstrip("\"'")
                findings.append(_finding(
                    "HLM-INJ-007", "MEDIUM", "Hardcoded container registry in template",
                    chart.chart_dir, tmpl.path, i,
                    f"Template hardcodes image '{image}' instead of using .Values. "
                    "This bypasses the values.yaml image configuration, preventing "
                    "users from redirecting to trusted registries.",
                    cwe="CWE-829",
                    remediation="Use {{ .Values.image.repository }}:{{ .Values.image.tag }} pattern.",
                    extra={"image": image},
                ))
    return findings


_GETHOSTBYNAME_RE = re.compile(r"\{\{-?\s*.*\bgetHostByName\b")


@register_check
def check_inj_008(chart: ChartInfo, config: ScannerConfig) -> list[dict]:
    """HLM-INJ-008: getHostByName function in templates."""
    findings = []
    for tmpl in chart.template_files:
        for i, line in enumerate(tmpl.content.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            cleaned_line = _GO_COMMENT_FULL_RE.sub('', line)
            if _GETHOSTBYNAME_RE.search(cleaned_line):
                findings.append(_finding(
                    "HLM-INJ-008", "HIGH", "getHostByName function in template",
                    chart.chart_dir, tmpl.path, i,
                    "Template uses getHostByName which performs DNS lookups during "
                    "rendering. CVE-2023-25165 demonstrated this enables exfiltration "
                    "of chart data via DNS queries to attacker-controlled servers.",
                    cwe="CWE-200",
                    remediation="Remove getHostByName calls. Use static hostnames or ConfigMap-based resolution.",
                ))
    return findings
