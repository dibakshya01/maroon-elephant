// Maroon Elephant VS Code extension: runs `maroon scan -f json` and shows findings as
// inline diagnostics (squiggles). Minimal, dependency-free (uses the bundled `vscode` API).
const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");

const SEVMAP = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

function activate(context) {
  const diag = vscode.languages.createDiagnosticCollection("maroon");
  context.subscriptions.push(diag);

  function scan() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || !folders.length) { vscode.window.showWarningMessage("Maroon Elephant: open a folder first."); return; }
    const root = folders[0].uri.fsPath;
    const cmd = vscode.workspace.getConfiguration("maroon").get("command", "maroon");
    vscode.window.setStatusBarMessage("🐘 Maroon Elephant scanning…", 4000);
    cp.execFile(cmd, ["scan", root, "-f", "json"], { cwd: root, maxBuffer: 20 * 1024 * 1024 }, (err, stdout) => {
      if (err && !stdout) { vscode.window.showErrorMessage("Maroon Elephant failed: " + err.message); return; }
      let data; try { data = JSON.parse(stdout); } catch (e) { vscode.window.showErrorMessage("Maroon Elephant: bad output"); return; }
      const byFile = {};
      (data.findings || []).forEach((f) => {
        const file = path.join(root, f.file);
        (byFile[file] = byFile[file] || []).push(f);
      });
      diag.clear();
      Object.keys(byFile).forEach((file) => {
        const items = byFile[file].map((f) => {
          const line = Math.max(0, (f.line || 1) - 1);
          const range = new vscode.Range(line, 0, line, 200);
          const owasp = ((f.frameworks || {}).llm || []).concat((f.frameworks || {}).asi || [], (f.frameworks || {}).dsgai || []).slice(0, 4).join(" ");
          const d = new vscode.Diagnostic(range, (f.message || f.title) + (owasp ? "  [" + owasp + "]" : ""), SEVMAP[f.severity] || vscode.DiagnosticSeverity.Warning);
          d.source = "Maroon Elephant";
          d.code = f.rule_id;
          return d;
        });
        diag.set(vscode.Uri.file(file), items);
      });
      const n = (data.findings || []).length;
      const g = data.governance || {};
      vscode.window.showInformationMessage("🐘 Maroon Elephant: " + n + " findings · " + (g.adoption_tier || "") + " × " + (g.governance_level || "") + " → " + (g.verdict || ""));
    });
  }

  context.subscriptions.push(vscode.commands.registerCommand("maroon.scanWorkspace", scan));
  context.subscriptions.push(vscode.commands.registerCommand("maroon.clear", () => diag.clear()));
  context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(() => {
    if (vscode.workspace.getConfiguration("maroon").get("scanOnSave", false)) scan();
  }));
}

function deactivate() {}
module.exports = { activate, deactivate };
