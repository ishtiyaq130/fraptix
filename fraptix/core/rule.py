import ast
from abc import ABC, abstractmethod
from pathlib import Path

from .models import Finding, RuleCategory, Severity


class Rule(ABC):
    """Base class for all Fraptix rules."""

    rule_id: str
    name: str
    category: RuleCategory
    severity: Severity

    @abstractmethod
    def check(
        self,
        tree: ast.AST,
        file_path: Path,
    ) -> list[Finding]:
        """Analyze an AST and return findings."""
        raise NotImplementedError