from .sql_interpolation import SQLInterpolationRule
from .dangerous_eval import DangerousEvalRule
from .command_execution import CommandExecutionRule
from .hardcoded_secrets import HardcodedSecretsRule

def get_rules():
    return [
        SQLInterpolationRule(),
        DangerousEvalRule(),
        CommandExecutionRule(),
        HardcodedSecretsRule(),
    ]