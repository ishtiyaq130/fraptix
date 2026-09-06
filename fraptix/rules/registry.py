from fraptix.core.rule import Rule

from .security import get_rules as get_security_rules
from .performance import get_rules as get_performance_rules
from .refactor import get_rules as get_refactor_rules


def get_all_rules() -> list[Rule]:
    rules = []

    rules.extend(get_security_rules())
    rules.extend(get_performance_rules())
    rules.extend(get_refactor_rules())

    return rules