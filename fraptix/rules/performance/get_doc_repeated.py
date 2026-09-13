import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class RepeatedGetDocRule(Rule):
    rule_id = "PERF004"
    name = "Repeated frappe.get_doc()"
    category = RuleCategory.PERFORMANCE
    severity = Severity.MEDIUM

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:

        findings = []
        reported_locations = set()

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            calls = {}

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue

                if not self._is_get_doc_call(child):
                    continue

                key = ast.dump(
                    child,
                    annotate_fields=True,
                    include_attributes=False,
                )

                calls.setdefault(key, []).append(child)

            for call_nodes in calls.values():
                if len(call_nodes) < 2:
                    continue

                first_call = call_nodes[0]

                location = (
                    first_call.lineno,
                    first_call.col_offset,
                )

                if location in reported_locations:
                    continue

                reported_locations.add(location)

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=file_path,
                        line=first_call.lineno,
                        column=first_call.col_offset,
                        message=(
                            "The same frappe.get_doc() call is executed "
                            "multiple times in this function. "
                            "Consider reusing the fetched document "
                            "instead of loading it repeatedly."
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