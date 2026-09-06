import ast
from pathlib import Path

from fraptix.rules.security.dangerous_eval import DangerousEvalRule


RULE = DangerousEvalRule()
FILE = Path("test.py")


def analyze(source):
    tree = ast.parse(source)
    return RULE.check(tree, FILE)


def test_detects_eval():
    findings = analyze(
        """
value = eval(user_input)
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC002"
    assert findings[0].severity.value == "high"


def test_detects_exec():
    findings = analyze(
        """
exec(user_input)
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC002"
    assert findings[0].severity.value == "high"


def test_detects_dynamic_function_call():
    findings = analyze(
        """
code = get_code()
exec(code)
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_static_eval_is_low():
    findings = analyze(
        """
value = eval("1 + 1")
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "low"


def test_static_exec_is_low():
    findings = analyze(
        """
exec("x = 1")
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "low"


def test_does_not_detect_literal_eval():
    findings = analyze(
        """
value = ast.literal_eval(data)
"""
    )

    assert len(findings) == 0


def test_does_not_detect_ast_parse():
    findings = analyze(
        """
tree = ast.parse(source)
"""
    )

    assert len(findings) == 0


def test_does_not_detect_method_named_eval():
    findings = analyze(
        """
obj.eval(value)
"""
    )

    assert len(findings) == 0