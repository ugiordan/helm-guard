Output site/docs/images/demo.gif
Set Theme "Catppuccin Mocha"
Set FontSize 14
Set Width 1200
Set Height 650
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Hide
Type "unset PROMPT_COMMAND"
Enter
Type `PS1='$ '`
Enter
Type "cd /tmp/helm-guard"
Enter
Type "clear"
Enter
Sleep 1s
Show

Type "# Scan a Helm chart for supply chain security issues"
Enter
Sleep 1s
Type "helm-guard charts/my-chart --format text"
Enter
Sleep 2s

Type ""
Enter
Sleep 500ms
Type "# Example output:"
Enter
Type 'echo "Helm Security Scan: charts/my-chart"'
Enter
Sleep 500ms
Type 'echo "Found 6 issue(s)"'
Enter
Sleep 500ms
Type 'echo ""'
Enter
Type 'echo "[CRITICAL] HLM-INJ-001: tpl function usage"'
Enter
Type 'echo "  File: templates/deployment.yaml:42"'
Enter
Type 'echo "  Template uses tpl function enabling arbitrary code execution"'
Enter
Type 'echo "  Fix: Avoid tpl. Use direct value interpolation."'
Enter
Sleep 1s
Type 'echo ""'
Enter
Type 'echo "[HIGH] HLM-PIN-001: Chart dependency with SemVer range"'
Enter
Type 'echo "  File: Chart.yaml:8"'
Enter
Type 'echo "  Dependency uses ~1.2.0 instead of exact version"'
Enter
Type 'echo "  Fix: Pin to exact version (1.2.3)"'
Enter
Sleep 2s

Type ""
Enter
Type "# 20 checks across 8 categories"
Enter
Sleep 500ms
Type 'echo "PIN (4) | INJ (3) | TRUST (3) | HOOK (2)"'
Enter
Type 'echo "OLM (3) | PROV (1) | NS (2) | DEP (2)"'
Enter
Sleep 3s
