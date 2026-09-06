import ast
from pathlib import Path

from fraptix.core.engine import RuleEngine
from tests.helpers.dummy_rule import DummyRule


def test_rule_engine():
    source = """
def hello():
    pass

def world():
    pass
"""

    tree = ast.parse(source)

    engine = RuleEngine(
        rules=[DummyRule()]
    )

    findings = engine.analyze(
        tree,
        Path("test.py"),
    )

    assert len(findings) == 2

    assert findings[0].rule_id == "TEST001"
    assert findings[0].message == "Function 'hello' found"

    assert findings[1].rule_id == "TEST001"
    assert findings[1].message == "Function 'world' found"