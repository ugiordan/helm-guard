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
Type "export PYTHONPATH=/tmp/helm-guard"
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
Type "/opt/homebrew/bin/python3 -m helm_guard tests/fixtures/test-chart -f text"
Enter
Sleep 4s

Type ""
Enter
Type "# Clean chart passes all checks"
Enter
Sleep 500ms
Type "/opt/homebrew/bin/python3 -m helm_guard tests/fixtures/clean-chart -f text"
Enter
Sleep 3s

Type ""
Enter
Type "# JSON output for automation"
Enter
Sleep 500ms
Type "/opt/homebrew/bin/python3 -m helm_guard tests/fixtures/clean-chart -f json | head -8"
Enter
Sleep 3s

Sleep 2s
