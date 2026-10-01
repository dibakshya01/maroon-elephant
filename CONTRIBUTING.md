# Contributing to Maroon Elephant

Thanks for helping build open, standards-anchored AI threat modeling.

## Ground rules
- **Deterministic-first.** New detection logic must produce findings with `file:line` evidence.
  The LLM layer only *enriches* existing deterministic findings — never invents them.
- **Zero runtime dependencies in the core.** Anything heavier goes behind an optional extra.
- **Every rule ships with fixtures.** A positive fixture (must fire) and a negative fixture (must stay silent).
- **Map to the frameworks.** New rules reference one or more OWASP control ids and inherit the crosswalk.

## Dev setup
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
maroon scan .            # dogfood: the self-scan must stay clean
```

## Adding a rule
1. Add a JSON rule object under `maroon/knowledge/rules/<family>/`.
2. Add positive + negative fixtures under `benchmarks/fixtures/` and label them in `benchmarks/LABELS.json`.
3. `pytest` — the rule-coverage test enforces that every rule has both fixtures.

## DCO
Commits must be signed off (`git commit -s`) under the Developer Certificate of Origin.
By contributing you agree your contribution is licensed under Apache-2.0.
