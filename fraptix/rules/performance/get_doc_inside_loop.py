import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class GetDocInsideLoopRule(Rule):
    rule_id = "PERF003"
    name = "frappe.get_doc() inside loop"
    category = RuleCategory.PERFORMANCE
    severity = Severity.MEDIUM

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:

        findings = []
        reported_calls = set()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While)):
                continue

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if not self._is_get_doc_call(child):
                    continue

                location = (
                    child.lineno,
                    child.col_offset,
                )

                if location in reported_calls:
                    continue

                reported_calls.add(location)

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
                            "frappe.get_doc() is called inside a loop. "
                            "This may cause repeated database access and "
                            "degrade performance for large datasets. "
                            "Consider fetching the required records in "
                            "bulk before or outside the loop when possible."
                        ),
                    )
                )

        return findings

    def _is_get_doc_call(
        self,
        node: ast.Call,
    ) -> bool:

        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr != "get_doc":
            return False

        return (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "frappe"
        )