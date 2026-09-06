import ast
import re
from pathlib import Path

from fraptix.core.models import Finding, RuleCategory, Severity
from fraptix.core.rule import Rule


class HardcodedSecretsRule(Rule):
    rule_id = "SEC004"
    name = "Hardcoded secret detected"
    category = RuleCategory.SECURITY
    severity = Severity.HIGH

    SECRET_NAME_PATTERN = re.compile(
        r"^(?:"
        r"password|"
        r"passwd|"
        r"pwd|"
        r"token|"
        r"api[_-]?key|"
        r"api[_-]?secret|"
        r"access[_-]?key|"
        r"access[_-]?token|"
        r"auth[_-]?token|"
        r"client[_-]?secret|"
        r"db[_-]?password|"
        r"database[_-]?password|"
        r"private[_-]?key|"
        r"secret[_-]?key"
        r")$",
        re.IGNORECASE,
    )

    SECRET_PATTERNS = [
        # AWS Access Key
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),

        # GitHub tokens
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),

        # JWT
        re.compile(
            r"\beyJ[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\."
            r"[A-Za-z0-9_-]+\b"
        ),

        # PEM private keys
        re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH |DSA )?"
            r"PRIVATE KEY-----"
        ),
    ]

    PLACEHOLDER_VALUES = {
        "",
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "api-key",
        "your_password",
        "your_secret",
        "your_token",
        "change_me",
        "changeme",
        "example",
        "example_key",
        "example_secret",
        "test",
        "testing",
        "dummy",
        "placeholder",
        "xxx",
        "xxxx",
        "xxxxx",
        "none",
        "null",
    }

    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:

        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                findings.extend(
                    self._check_assignment(node, file_path)
                )

            elif isinstance(node, ast.AnnAssign):
                findings.extend(
                    self._check_annotated_assignment(node, file_path)
                )

        return findings

    def _check_assignment(
        self,
        node: ast.Assign,
        file_path: Path,
    ) -> list[Finding]:

        findings = []

        for target in node.targets:
            name = self._get_target_name(target)

            if not name:
                continue

            finding = self._analyze_value(
                name=name,
                value=node.value,
                node=node,
                file_path=file_path,
            )

            if finding:
                findings.append(finding)

        return findings

    def _check_annotated_assignment(
        self,
        node: ast.AnnAssign,
        file_path: Path,
    ) -> list[Finding]:

        name = self._get_target_name(node.target)

        if not name:
            return []

        finding = self._analyze_value(
            name=name,
            value=node.value,
            node=node,
            file_path=file_path,
        )

        return [finding] if finding else []

    def _analyze_value(
        self,
        name: str,
        value: ast.AST | None,
        node: ast.AST,
        file_path: Path,
    ) -> Finding | None:

        if value is None:
            return None

        if not isinstance(value, ast.Constant):
            return None

        if not isinstance(value.value, str):
            return None

        secret_value = value.value.strip()

        if self._is_placeholder(secret_value):
            return None

        # High-confidence secret formats.
        if self._matches_secret_pattern(secret_value):
            return self._create_finding(
                node,
                file_path,
                name,
            )

        # Generic secret variable names require a strong-looking value.
        if self._looks_like_secret_name(name):
            if self._looks_like_secret_value(secret_value):
                return self._create_finding(
                    node,
                    file_path,
                    name,
                )

        return None

    def _looks_like_secret_name(self, name: str) -> bool:
        normalized = name.replace("-", "_")

        return bool(
            self.SECRET_NAME_PATTERN.fullmatch(normalized)
        )

    def _looks_like_secret_value(self, value: str) -> bool:
        if len(value) < 12:
            return False

        normalized = value.lower()

        # Avoid obvious natural-language placeholders.
        placeholder_words = {
            "password",
            "secret",
            "token",
            "example",
            "testing",
            "test",
            "dummy",
            "placeholder",
            "changeme",
        }

        if normalized in placeholder_words:
            return False

        # A secret-like value should contain some variation.
        has_upper = bool(re.search(r"[A-Z]", value))
        has_lower = bool(re.search(r"[a-z]", value))
        has_digit = bool(re.search(r"\d", value))
        has_special = bool(re.search(r"[^A-Za-z0-9]", value))

        character_classes = sum(
            [
                has_upper,
                has_lower,
                has_digit,
                has_special,
            ]
        )

        # Long values with at least two character classes are suspicious.
        return character_classes >= 2

    def _matches_secret_pattern(self, value: str) -> bool:
        return any(
            pattern.search(value)
            for pattern in self.SECRET_PATTERNS
        )

    def _is_placeholder(self, value: str) -> bool:
        normalized = value.lower()

        if normalized in self.PLACEHOLDER_VALUES:
            return True

        return False

    def _get_target_name(
        self,
        target: ast.AST,
    ) -> str | None:

        if isinstance(target, ast.Name):
            return target.id

        return None

    def _create_finding(
        self,
        node: ast.AST,
        file_path: Path,
        name: str,
    ) -> Finding:

        return Finding(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            severity=self.severity,
            file_path=file_path,
            line=node.lineno,
            column=node.col_offset,
            message=(
                f"Possible hardcoded secret assigned to '{name}'. "
                "Move secrets to environment variables or secure "
                "configuration."
            ),
        )