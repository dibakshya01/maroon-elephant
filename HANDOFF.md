# Handoff — Maroon Elephant

Everything buildable has been built, tested, and hardened locally. What remains needs **your**
accounts/credentials — I can't (and shouldn't) do these for you. Ordered most-important first.
Each item has the exact command or click.

## 1. Push the code to GitHub  ⬅ do this first
The local git repo has all commits on `main`, remote set to `github.com/dibakshya01/maroon-elephant`.
I could not push (no `gh` CLI and no git credentials in this environment). From your machine:

```bash
cd "/Users/dibakshya/Documents/OpenSource Projects/maroon-elephant"
git push -u origin main
```
If the remote already has commits, reconcile first (`git pull --rebase origin main`) then push.

## 2. Enable GitHub Pages (the landing site)
The site lives in `site/` and a deploy workflow is at `.github/workflows/pages.yml`.
- GitHub → repo **Settings → Pages → Build and deployment → Source: GitHub Actions**.
- On the next push to `main`, the site deploys to `https://dibakshya01.github.io/maroon-elephant/`.

## 3. Pin CI actions by commit SHA (security)
`.github/workflows/*.yml` and `action.yml` reference `actions/checkout@v4`, `actions/setup-python@v5`,
`github/codeql-action/upload-sarif@v3`, and the Pages actions by **tag** (TODO comments mark them).
A security tool should pin third-party actions by full commit SHA. Replace each `@vN` with the
pinned `@<40-char-sha>` (find SHAs on each action's releases page).

## 4. Publish the Python package to PyPI (needs your PyPI token)
The wheel builds clean with zero runtime deps.
```bash
python -m build            # creates dist/*.whl and *.tar.gz
python -m twine upload dist/*   # prompts for your PyPI token
```
Consider a TestPyPI dry-run first (`twine upload --repository testpypi dist/*`).

## 5. Publish the GitHub Action to the Marketplace
`action.yml` is at the repo root with `branding`. After pushing: open it on GitHub → **"Draft a
release" → check "Publish this Action to the GitHub Marketplace" → pick a category → tag `v1`**.
(Requires 2FA on the account and accepting the Marketplace Developer Agreement.)

## 6. Publish the VS Code extension (optional)
```bash
cd vscode-extension && npx @vscode/vsce package      # creates maroon-elephant-0.1.0.vsix
npx @vscode/vsce publish                              # needs a VS Code Marketplace publisher + PAT
```

## 7. Register the GitHub App (for org-wide scanning — advanced)
The App *client code* (JWT, installation tokens, SARIF upload, Checks, webhook verification) is
implemented and unit-tested, but a live App needs: (a) registering the App in your GitHub org with
the least-privilege permissions documented in `maroon/github/app.py` (`metadata:read`,
`contents:read`, `code scanning alerts:write`, `checks:write`, `pull requests:read`), (b) a hosted
HTTPS webhook endpoint with the webhook secret, and (c) private-key storage in a KMS. This is a
deploy effort, not a one-liner — pursue it when you want the hosted multi-repo product.
> Note: third-party SARIF on **private** repos requires the customer to hold a GitHub **Code
> Security** license; public repos are free; the **Checks API** path works everywhere without it.

## 8. Decisions only you can make
- **Trademark/name check** for "Maroon Elephant" before any public launch.
- **OWASP project submission** (Incubator) — see the governance path in `Build Plan.md §15`.
- Whether to enable the optional **hosted control-plane** later (kept out of scope deliberately).

## 9. Launch copy (when you're ready)
Ask me to draft HN/Reddit/X launch posts into a git-ignored `LAUNCH.md` (never committed) — I'll
keep them in your voice, with the honest "what it can & cannot do" framing.

---
### What's already done (no action needed)
Working Core CLI + MCP server + Enterprise UI + orchestrator + GitHub client + VS Code extension +
pre-commit hook; 57 tests green; **self-scan clean**; zero-dependency wheel; brand + landing site +
social card; `Findings.md`, `Build Plan.md`, `BUILD_LOG.md`, docs, governance files. Spec reviewed
(3 cycles → APPROVE) and adversarially hardened (3 rounds → clean).
