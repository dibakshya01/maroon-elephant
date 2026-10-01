# Maroon Elephant — VS Code extension

Runs the `maroon` CLI on your workspace and surfaces AI-era threat findings (OWASP-2026)
as inline diagnostics.

**Requires** the CLI: `pip install maroon-elephant` (ensure `maroon` is on PATH).

- Command: **Maroon Elephant: Scan Workspace** (Cmd/Ctrl-Shift-P).
- Findings show as squiggles with the rule id and OWASP tags; the status bar shows the
  AT×L governance verdict.
- Enable `maroon.scanOnSave` to re-scan on save.

Package with `vsce package` (see HANDOFF.md).
