"""Template injection checks for Helm charts (Tier 2: text/regex)."""

from __future__ import annotations

import re

from helm_guard.checks._common import _finding, register_check
from helm_guard.config import ScannerConfig
from helm_guard.parser import ChartInfo

_TPL_RE = re.compile(r"\{\{-?\s*tpl\b")

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

# Piped to quote or squote (possibly via chained filters like | default "" | quote)
_QUOTE_PIPE_RE = re.compile(r"\.Values\.[a-zA-Z0-9_.]+.*\|\s*(quote|squote)")

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
                shell_base_indent = current_indent
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

            # Check for .Values in shell contexts
            if in_shell_block and _VALUES_RE.search(line):
                # Skip if properly quoted
                if _QUOTE_PIPE_RE.search(line):
                    continue
                findings.append(_finding(
                    rule_id="HLM-INJ-002",
                    severity="HIGH",
                    title="Values in shell context without quote",
                    chart_dir=chart.chart_dir,
                    file_path=tmpl.path,
                    line=lineno,
                    message=(
                        "'.Values.*' used in shell context without piping through 'quote'. "
                        "This enables shell injection via crafted values."
                    ),
                    cwe="CWE-78",
                    remediation="Pipe values through 'quote' in shell contexts: {{ .Values.foo | quote }}",
                ))

            if stripped == "" or stripped.startswith("---"):
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
