from pathlib import Path

from .rule import Rule


class RuleEngine:

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def analyze(
        self,
        tree,
        file_path: Path,
    ):
        findings = []

        for rule in self.rules:
            findings.extend(
                rule.check(
                    tree,
                    file_path,
                )
            )

        return findings