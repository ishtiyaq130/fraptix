import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class DangerousEvalRule(Rule):
    rule_id = "SEC002"
    name = "Dangerous eval or exec usage"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

    DANGEROUS_FUNCTIONS = {
        "eval",
        "exec",
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

            function_name = self._get_function_name(node)

            if function_name not in self.DANGEROUS_FUNCTIONS:
                continue

            if not node.args:
                continue

            severity = self._get_severity(node.args[0])

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
                        f"Use of {function_name}() can execute arbitrary "
                        "Python code. Avoid dynamic code execution."
                    ),
                )
            )

        return findings

    def _get_function_name(
        self,
        node: ast.Call,
    ) -> str | None:

        if isinstance(node.func, ast.Name):
            return node.func.id

        return None

    def _get_severity(
        self,
        argument: ast.AST,
    ) -> Severity:

        if isinstance(argument, ast.Constant):
            if isinstance(argument.value, str):
                return Severity.LOW

        return Severity.HIGH