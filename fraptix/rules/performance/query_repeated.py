import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class RepeatedDatabaseQueryRule(Rule):
    rule_id = "PERF002"
    name = "Repeated database query"
    category = RuleCategory.PERFORMANCE
    severity = Severity.MEDIUM

    DATABASE_METHODS = {
        "get_value",
        "get_all",
        "get_list",
        "get_single_value",
        "exists",
        "count",
        "sql",
    }

    def check(self, tree, file_path):
        findings = []

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            queries = {}

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if not self._is_database_query(child):
                    continue

                query_key = ast.dump(
                    child,
                    annotate_fields=True,
                    include_attributes=False,
                )

                queries.setdefault(query_key, []).append(child)

            for query_nodes in queries.values():
                if len(query_nodes) < 2:
                    continue

                first_query = query_nodes[0]

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=file_path,
                        line=first_query.lineno,
                        column=first_query.col_offset,
                        message=(
                            "The same database query is executed "
                            "multiple times in this function. "
                            "Consider reusing the result or caching "
                            "the data to avoid unnecessary database "
                            "queries."
                        ),
                    )
                )

        return findings

    def _is_database_query(self, node):
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr not in self.DATABASE_METHODS:
            return False

        parent = node.func.value

        if not isinstance(parent, ast.Attribute):
            return False

        if parent.attr != "db":
            return False

        return (
            isinstance(parent.value, ast.Name)
            and parent.value.id == "frappe"
        )