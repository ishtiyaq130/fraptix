import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class SQLInterpolationRule(Rule):
    rule_id = "SEC001"
    name = "SQL query uses string interpolation"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

    DB_METHODS = {
        "sql",
        "sql_list",
    }

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:

        findings = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            if not self._is_frappe_db_call(node):
                continue

            if not node.args:
                continue

            query = node.args[0]

            severity = self._get_interpolation_severity(query)

            if severity:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=severity,
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        message=(
                            "SQL query uses string interpolation. "
                            "Use parameterized query values instead."
                        ),
                    )
                )

        return findings

    def _is_frappe_db_call(self, node: ast.Call) -> bool:
        """Check for frappe.db.sql(...) or frappe.db.sql_list(...)."""

        func = node.func

        if not isinstance(func, ast.Attribute):
            return False

        if func.attr not in self.DB_METHODS:
            return False

        db_object = func.value

        if not isinstance(db_object, ast.Attribute):
            return False

        return (
            db_object.attr == "db"
            and isinstance(db_object.value, ast.Name)
            and db_object.value.id == "frappe"
        )

    def _contains_string_concatenation(self, node: ast.BinOp) -> bool:
        """Check whether a + expression contains a string component."""

        if isinstance(node.left, ast.Constant):
            if isinstance(node.left.value, str):
                return True

        if isinstance(node.right, ast.Constant):
            if isinstance(node.right.value, str):
                return True

        if isinstance(node.left, ast.BinOp):
            if isinstance(node.left.op, ast.Add):
                if self._contains_string_concatenation(node.left):
                    return True

        if isinstance(node.right, ast.BinOp):
            if isinstance(node.right.op, ast.Add):
                if self._contains_string_concatenation(node.right):
                    return True

        return False

    def _get_interpolation_severity(
        self,
        node: ast.AST,
    ) -> Severity | None:
        """Return severity when unsafe SQL interpolation is detected."""

        # f"SELECT ... {value}"
        if isinstance(node, ast.JoinedStr):
            return Severity.HIGH

        # "SELECT ..." % value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return Severity.HIGH

        # "SELECT ...".format(value)
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
            ):
                if not node.args:
                    return None

                # Get the SQL template
                if not isinstance(node.func.value, ast.Constant):
                    return Severity.MEDIUM

                query = node.func.value.value

                if not isinstance(query, str):
                    return Severity.MEDIUM

                # SQL identifier interpolation:
                # "ALTER TABLE `{}` ...".format(column_name)
                #
                # These are identifiers (table/column names), not SQL values.
                if self._is_identifier_interpolation(query):
                    return None

                argument = node.args[0]

                # Dynamic SQL fragment
                if isinstance(argument, ast.Name):
                    if "condition" in argument.id.lower():
                        return Severity.MEDIUM

                return Severity.HIGH

        # "SELECT ..." + value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if self._contains_string_concatenation(node):
                return Severity.HIGH

        return None
    
    def _is_identifier_interpolation(self, query: str) -> bool:
        """Check whether .format() placeholders are used as SQL identifiers."""

        return "`{}`" in query