# Fraptix

> Static analysis for [Frappe](https://frappeframework.com/) applications — find security
> vulnerabilities, performance bottlenecks, and code quality issues before they reach production.

[![CI](https://github.com/ishtiyaq130/fraptix/actions/workflows/ci.yml/badge.svg)](https://github.com/ishtiyaq130/fraptix/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-lightgrey.svg)](CHANGELOG.md)

Fraptix scans the source code of Frappe / ERPNext applications and reports issues it
finds — no runtime required. It understands Frappe-specific APIs such as
`frappe.db.sql()`, `frappe.get_doc()`, `frappe.get_all()`, and `ignore_permissions`,
so it catches problems generic linters miss.

## Features

- 🔒 **Security analysis** — SQL injection, dangerous `eval`/`exec`, command
  execution, hardcoded secrets, permission bypass, and path traversal.
- ⚡ **Performance analysis** — N+1 query patterns, repeated database queries,
  unbounded retrievals, and redundant document loads.
- 🧩 **Frappe-aware** — built around Frappe/ERPNext conventions, not just generic Python.
- 📊 **Two output formats** — human-friendly console output (with severity colors)
  or machine-readable JSON for CI pipelines.
- 🪶 **Lightweight** — pure Python, only `rich` as a runtime dependency.
- 🔌 **Extensible** — new rules are simple classes; see
  [CONTRIBUTING.md](CONTRIBUTING.md#writing-a-new-rule).

## Requirements

- Python 3.10 or newer
- Run from inside a **frappe-bench** directory (the directory that contains `apps/`)

## Installation

```bash
# From source (recommended for now)
git clone https://github.com/ishtiyaq130/fraptix.git
cd fraptix
pip install .

# Or, for development:
pip install -e ".[dev]"
```

A PyPI package is planned — see the [roadmap](#roadmap).

## Quick start

Run from anywhere inside your frappe-bench:

```bash
cd ~/frappe-bench

# Scan one application
fraptix scan my_app

# Scan several applications at once
fraptix scan my_app other_app

# Only show high and critical findings
fraptix scan my_app --severity high

# Only security findings
fraptix scan my_app --category security

# Only a single rule
fraptix scan my_app --rule SEC001

# Machine-readable output (for CI or scripts)
fraptix scan my_app --format json > report.json
```

### Example output

```
╭────────────────────────────────────────────────────────────╮
│                                                            │
│    FRAPTIX                                                 │
│    Frappe Security • Performance • Refactoring Analyzer    │
│                                                            │
╰────────────────────────────────────────────────────────────╯
Findings

SECURITY
────────────────────────────────────────────────────────────
✗ HIGH  SEC001  SQL query uses string interpolation
  apps/demo_app/demo_app/example.py:11
  SQL query uses string interpolation. Use parameterized query values instead.

✗ HIGH  SEC004  Hardcoded secret detected
  apps/demo_app/demo_app/example.py:14
  Possible hardcoded secret assigned to 'API_KEY'. Move secrets to environment
variables or secure configuration.

PERFORMANCE
────────────────────────────────────────────────────────────
✗ MEDIUM  PERF001  Database query inside loop
  apps/demo_app/demo_app/example.py:7
  Database query executed inside a loop. This may cause an N+1 query pattern and
degrade performance for large datasets. Consider fetching the required data in
bulk before or outside the loop.

✗ MEDIUM  PERF006  Unbounded database retrieval
  apps/demo_app/demo_app/example.py:7
  Database records are retrieved without an explicit limit or pagination. This
may load a large number of records into memory and degrade performance. Consider
using limit_page_length or pagination.

  Bench                 ~/frappe-bench
  Application           demo_app
  Path                  ~/frappe-bench/apps/demo_app
  Python files          1
  Parsed                1
  Parse errors          0

✓ Application analysis completed
```

### JSON output

`--format json` prints a single JSON document:

```json
{
  "tool": "fraptix",
  "version": "0.1.0",
  "application": "demo_app",
  "bench": "/home/you/frappe-bench",
  "path": "/home/you/frappe-bench/apps/demo_app",
  "summary": {
    "python_files": 1,
    "parsed": 1,
    "parse_errors": 0,
    "findings": 4
  },
  "findings": [
    {
      "rule_id": "SEC001",
      "name": "SQL query uses string interpolation",
      "category": "security",
      "severity": "high",
      "file": "/home/you/frappe-bench/apps/demo_app/demo_app/example.py",
      "line": 11,
      "column": 18,
      "message": "SQL query uses string interpolation. Use parameterized query values instead."
    }
  ]
}
```

## CLI reference

```
fraptix scan APP [APP ...] [options]
```

| Option            | Description                                             |
| ----------------- | ------------------------------------------------------- |
| `APP...`          | One or more Frappe application names (folders under `apps/`) |
| `--severity LEVEL`| Only show findings at or above `critical`, `high`, `medium`, or `low` |
| `--category NAME` | Only show findings of category `security`, `performance`, or `refactoring` |
| `--rule ID`       | Only show findings for one rule, e.g. `--rule PERF001`   |
| `--format FORMAT` | Output format: `console` (default) or `json`            |
| `--version`       | Print the Fraptix version and exit                      |

## Rules

### Security

| ID     | Rule                                  | Severity |
| ------ | ------------------------------------- | -------- |
| SEC001 | SQL query uses string interpolation   | high     |
| SEC002 | Dangerous `eval` or `exec` usage      | high     |
| SEC003 | Dangerous command execution           | high     |
| SEC004 | Hardcoded secret detected             | high     |
| SEC005 | Potential Frappe permission bypass    | high     |
| SEC006 | Potential path traversal              | high     |

### Performance

| ID      | Rule                                        | Severity |
| ------- | ------------------------------------------- | -------- |
| PERF001 | Database query inside loop                  | medium   |
| PERF002 | Repeated database query                     | medium   |
| PERF003 | `frappe.get_doc()` inside loop              | medium   |
| PERF004 | Repeated `frappe.get_doc()`                 | medium   |
| PERF005 | Redundant database retrieval                | medium   |
| PERF006 | Unbounded database retrieval                | medium   |
| PERF007 | Database existence check before `get_doc`   | medium   |

### Refactoring

Planned — not implemented yet.

## Development

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run the tests
pytest
```

### Project structure

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

### Adding a rule

See [CONTRIBUTING.md](CONTRIBUTING.md#writing-a-new-rule) for a step-by-step guide.

## Contributing

Contributions are welcome! Bug reports, feature requests, new rules, and
documentation improvements are all appreciated.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) to get started, and follow our
[Code of Conduct](CODE_OF_CONDUCT.md). If you find a security vulnerability,
please report it privately as described in [SECURITY.md](SECURITY.md).

## Roadmap

- [ ] Refactoring rules
- [ ] More security rules (XSS, SSRF, SQL identifier escaping)
- [ ] Configuration file (`fraptix.toml`) for enabling/disabling rules
- [ ] PyPI release
- [ ] SARIF output format
- [ ] Diff-aware scanning (only analyze changed files)

## License

[MIT](LICENSE) © Fraptix Contributors
