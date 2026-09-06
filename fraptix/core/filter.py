from fraptix.core.models import Finding


SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def filter_findings(
    findings: list[Finding],
    severity: str | None = None,
    category: str | None = None,
    rule_id: str | None = None,
) -> list[Finding]:

    filtered = findings

    if severity:
        minimum = SEVERITY_ORDER[severity]

        filtered = [
            finding
            for finding in filtered
            if SEVERITY_ORDER[finding.severity.value] >= minimum
        ]

    if category:
        filtered = [
            finding
            for finding in filtered
            if finding.category.value == category
        ]

    if rule_id:
        filtered = [
            finding
            for finding in filtered
            if finding.rule_id == rule_id
        ]

    return filtered