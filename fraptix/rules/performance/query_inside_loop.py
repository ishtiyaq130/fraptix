import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class QueryInsideLoopRule(Rule):
    rule_id = "PERF001"
    name = "Database query inside loop"
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

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:

        findings = []
        reported_queries = set()

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.For, ast.While),
            ):
                continue

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if not self._is_database_query(child):
                    continue

                query_location = (
                    child.lineno,
                    child.col_offset,
                )

                if query_location in reported_queries:
                    continue

                reported_queries.add(query_location)

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=file_path,
                        line=child.lineno,
                        column=child.col_offset,
                        message=(
                            "Database query executed inside a loop. "
                            "This may cause an N+1 query pattern and "
                            "degrade performance for large datasets. "
                            "Consider fetching the required data in "
                            "bulk before or outside the loop."
                        ),
                    )
                )

        return findings

    def _is_database_query(self, node: ast.Call) -> bool:

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