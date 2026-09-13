import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class UnboundedDatabaseRetrievalRule(Rule):
    rule_id = "PERF006"
    name = "Unbounded database retrieval"
    category = RuleCategory.PERFORMANCE
    severity = Severity.MEDIUM

    DATABASE_METHODS = {
        "get_all",
        "get_list",
    }

    def check(self, tree, file_path):
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not self._is_unbounded_retrieval(node):
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    name=self.name,
                    category=self.category,
                    severity=self.severity,
                    file_path=file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    message=(
                        "Database records are retrieved without an explicit "
                        "limit or pagination. This may load a large number "
                        "of records into memory and degrade performance. "
                        "Consider using limit_page_length or pagination."
                    ),
                )
            )

        return findings

    def _is_unbounded_retrieval(self, node):
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr not in self.DATABASE_METHODS:
            return False

        db = node.func.value

        if not isinstance(db, ast.Attribute):
            return False

        if db.attr != "db":
            return False

        if not isinstance(db.value, ast.Name):
            return False

        if db.value.id != "frappe":
            return False

        return not self._has_limit(node) and not self._has_filters(node)

    def _has_limit(self, node):
        for keyword in node.keywords:
            if keyword.arg in {
                "limit_page_length",
                "limit",
                "page_length",
            }:
                return True

        return False

    def _has_filters(self, node):
        if len(node.args) >= 2:
            return True
        for keyword in node.keywords:
            if keyword.arg in {
                "filters",
                "or_filters",
            }:
                return True

        return False