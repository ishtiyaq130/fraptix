import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class DummyRule(Rule):
    rule_id = "TEST001"
    name = "Test rule"
    category = RuleCategory.SECURITY
    severity = Severity.LOW

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        name=self.name,
                        category=self.category,
                        severity=self.severity,
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        message=f"Function '{node.name}' found",
                    )
                )

        return findings