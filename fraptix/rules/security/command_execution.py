import ast
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class CommandExecutionRule(Rule):
    rule_id = "SEC003"
    name = "Dangerous command execution"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

    OS_FUNCTIONS = {
        "system",
        "popen",
    }

    SUBPROCESS_FUNCTIONS = {
        "run",
        "call",
        "Popen",
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

            result = self._analyze_call(node)

            if result is None:
                continue

            severity, function_name = result

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
                        f"Use of {function_name} can execute "
                        "operating-system commands. Avoid executing "
                        "dynamic shell commands."
                    ),
                )
            )

        return findings

    def _analyze_call(
        self,
        node: ast.Call,
    ) -> tuple[Severity, str] | None:

        # os.system(...) / os.popen(...)
        if self._is_os_command(node):
            if not node.args:
                return None

            if self._is_dynamic(node.args[0]):
                return Severity.CRITICAL, self._get_call_name(node)

            return Severity.HIGH, self._get_call_name(node)

        # subprocess.run/call/Popen(..., shell=True)
        if self._is_subprocess_call(node):
            if not self._has_shell_true(node):
                return None

            if not node.args:
                return None

            if self._is_dynamic(node.args[0]):
                return Severity.CRITICAL, self._get_call_name(node)

            return Severity.HIGH, self._get_call_name(node)

        return None

    def _is_os_command(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr not in self.OS_FUNCTIONS:
            return False

        return (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        )

    def _is_subprocess_call(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr not in self.SUBPROCESS_FUNCTIONS:
            return False

        return (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
        )

    def _has_shell_true(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg != "shell":
                continue

            return (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            )

        return False

    def _is_dynamic(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Constant):
            return True

        if isinstance(node.value, str):
            return False

        return True

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"

            return node.func.attr

        if isinstance(node.func, ast.Name):
            return node.func.id

        return "command execution"