# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Nothing yet.

## [0.1.0] - 2026-09-18

### Added

- Command-line interface (`fraptix scan`) with severity, category, and rule filters.
- Console reporter with colorized severity output.
- JSON reporter for machine-readable output.
- Frappe bench and application detection.
- 6 security rules: SQL interpolation, dangerous `eval`/`exec`, command
  execution, hardcoded secrets, permission bypass, and path traversal.
- 7 performance rules: queries and `frappe.get_doc()` in loops, repeated
  queries, redundant and unbounded retrievals, and `exists()`-before-`get_doc()`.
- Extensible rule engine with a registry for custom rules.
- Test suite (125 tests) covering the engine, rules, and edge cases.

[Unreleased]: https://github.com/ishtiyaq130/fraptix/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ishtiyaq130/fraptix/releases/tag/v0.1.0
