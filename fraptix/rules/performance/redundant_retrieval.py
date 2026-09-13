import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class RedundantDatabaseRetrievalRule(Rule):
    rule_id = "PERF005"
    name = "Redundant database retrieval"
    category = RuleCategory.PERFORMANCE
    severity = Severity.MEDIUM

    DATABASE_METHODS = {
        "get_value",
        "get_all",
        "get_list",
        "get_single_value",
        "exists",
        "count",
    }

    def check(self, tree, file_path):
        findings = []

        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            loaded_documents = {}

            calls = [
                child
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
            ]

            calls.sort(key=lambda call: (call.lineno, call.col_offset))

            for call in calls:
                if self._is_get_doc(call):
                    key = self._get_document_key(call)

                    if key is not None:
                        loaded_documents[key] = call

                    continue

                if not self._is_database_retrieval(call):
                    continue

                key = self._get_database_retrieval_key(call)

                if key is None:
                    continue

                if key not in loaded_documents:
                    continue

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=file_path,
                        line=call.lineno,
                        column=call.col_offset,
                        message=(
                            "A database retrieval is performed for a "
                            "document that was already loaded with "
                            "frappe.get_doc(). Consider using the loaded "
                            "document instead of performing another "
                            "database query."
                        ),
                    )
                )

        return self._remove_duplicate_findings(findings)

    def _is_get_doc(self, node):
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr != "get_doc":
            return False

        return (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "frappe"
        )

    def _is_database_retrieval(self, node):
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

    def _get_document_key(self, node):
        if len(node.args) < 2:
            return None

        return (
            self._expression_key(node.args[0]),
            self._expression_key(node.args[1]),
        )

    def _get_database_retrieval_key(self, node):
        if len(node.args) < 2:
            return None

        return (
            self._expression_key(node.args[0]),
            self._expression_key(node.args[1]),
        )

    def _expression_key(self, node):
        return ast.dump(
            node,
            annotate_fields=True,
            include_attributes=False,
        )

    def _remove_duplicate_findings(self, findings):
        unique_findings = []
        locations = set()

        for finding in findings:
            location = (
                finding.file_path,
                finding.line,
                finding.column,
            )

            if location in locations:
                continue

            locations.add(location)
            unique_findings.append(finding)

        return unique_findings