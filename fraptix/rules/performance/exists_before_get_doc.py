import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class ExistsBeforeGetDocRule(Rule):
    rule_id = "PERF007"
    name = "Database existence check before get_doc"
    category = RuleCategory.PERFORMANCE
    severity = Severity.MEDIUM

    def check(self, tree, file_path):
        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            existence_checks = {}

            calls = [
                child
                for child in ast.walk(node)
                if isinstance(child, ast.Call)
            ]

            calls.sort(key=lambda call: (call.lineno, call.col_offset))

            for call in calls:
                if self._is_exists_call(call):
                    key = self._get_document_key(call)

                    if key is not None:
                        existence_checks[key] = call

                    continue

                if not self._is_get_doc_call(call):
                    continue

                key = self._get_document_key(call)

                if key is None:
                    continue

                if key not in existence_checks:
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
                            "frappe.db.exists() is followed by "
                            "frappe.get_doc() for the same document. "
                            "This may cause redundant database queries. "
                            "Consider using frappe.get_doc() directly "
                            "and handling the missing-document case."
                        ),
                    )
                )

        return self._remove_duplicate_findings(findings)

    def _is_exists_call(self, node):
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr != "exists":
            return False

        db = node.func.value

        if not isinstance(db, ast.Attribute):
            return False

        if db.attr != "db":
            return False

        frappe = db.value

        return (
            isinstance(frappe, ast.Name)
            and frappe.id == "frappe"
        )

    def _is_get_doc_call(self, node):
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr != "get_doc":
            return False

        frappe = node.func.value

        return (
            isinstance(frappe, ast.Name)
            and frappe.id == "frappe"
        )

    def _get_document_key(self, node):
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