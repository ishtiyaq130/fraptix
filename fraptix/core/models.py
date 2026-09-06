from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleCategory(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    REFACTOR = "refactor"


@dataclass
class Finding:
    rule_id: str
    name: str
    category: RuleCategory
    severity: Severity

    file_path: Path
    line: int
    column: int | None

    message: str
    description: str | None = None