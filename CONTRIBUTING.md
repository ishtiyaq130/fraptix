# Contributing to Fraptix

Thanks for your interest in contributing! Fraptix is an early-stage project,
so every contribution — bug reports, new rules, tests, docs — makes a real
difference.

## Getting started

1. **Fork** the repository on GitHub.
2. **Clone** your fork:

   ```bash
   git clone https://github.com/<your-username>/fraptix.git
   cd fraptix
   ```

3. **Set up a development environment:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

4. **Run the tests** to make sure everything works:

   ```bash
   pytest
   ```

5. Create a branch, make your changes, and open a pull request against `main`.

## Project structure

```
fraptix/
├── cli.py            # Command-line interface
├── core/
│   ├── engine.py     # Runs rules over parsed files
│   ├── models.py     # Finding, Severity, RuleCategory
│   ├── parser.py     # Python → AST parser
│   ├── rule.py       # Rule base class
│   └── filter.py     # Severity / category / rule filters
├── project/          # Frappe bench + app detection, file scanning
├── reporters/        # Console and JSON output
└── rules/            # One module per rule, grouped by category
    ├── security/
    ├── performance/
    └── refactor/
tests/
├── security/         # One test module per security rule
├── performance/      # One test module per performance rule
└── ...               # Engine, parser, filter, detector tests
```

## Writing a new rule

Rules are plain classes that subclass `Rule` and walk the AST of each Python
file. Here is the complete recipe:

### 1. Create the rule

Create a new module in the right category package, e.g.
`fraptix/rules/security/sql_interpolation.py`:

```python
import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class SQLInterpolationRule(Rule):
    rule_id = "SEC001"
    name = "SQL query uses string interpolation"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: Path) -> list[Finding]:
        findings = []

        for node in ast.walk(tree):
            # ... detect the pattern, append Finding(...) objects ...

        return findings
```

Guidelines:

- **Rule IDs** are prefixed by category — `SEC`, `PERF`, `REF` — followed by a
  sequential number.
- Each rule module contains exactly one rule class.
- Keep detection code self-contained; shared helpers can go into the module.
- `line` / `column` come from `node.lineno` / `node.col_offset`.
- Write a `message` that explains the problem **and** how to fix it.

### 2. Register the rule

Add the class to the category's `get_rules()` list in
`fraptix/rules/<category>/__init__.py`. That is all — the registry picks it up
automatically.

### 3. Write tests

Every rule needs tests. Add a module in `tests/<category>/` (e.g.
`tests/security/test_sql_interpolation.py`) that:

- Asserts findings are raised for code that should trigger the rule.
- Asserts **no** findings for safe code (avoid false positives).
- Asserts the reported `line` when practical.

The existing test files in `tests/security/` and `tests/performance/` are the
best reference for the project's test style.

### 4. Update the README

Add your rule to the rules table in [README.md](README.md).

## Style conventions

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Match the surrounding code's formatting (short lines, double quotes,
  minimal comments).
- Use type hints — the codebase targets Python 3.10+.
- Keep messages user-facing and actionable.

## Testing

```bash
# Full suite
pytest

# One file
pytest tests/security/test_sql_interpolation.py
```

CI runs the full suite against Python 3.10–3.13 on every pull request.

## Commit messages

Use the [Conventional Commits](https://www.conventionalcommits.org/) style,
e.g.:

```
feat: add SEC007 SSRF detection rule
fix: false positive in PERF001 for generator loops
docs: document JSON output schema
```

## Pull request checklist

Before opening a PR, make sure:

- [ ] All tests pass (`pytest`)
- [ ] New rules have tests covering both positive and negative cases
- [ ] The README rules table is updated
- [ ] Your branch is up to date with `main`

## Questions?

Open a [discussion](https://github.com/ishtiyaq130/fraptix/discussions) or an
issue — we are happy to help.
