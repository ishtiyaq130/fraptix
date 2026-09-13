import ast
from pathlib import Path

from fraptix.rules.performance.get_doc_inside_loop import (
    GetDocInsideLoopRule,
)


def parse_code(code):
    return ast.parse(code)


def test_detects_get_doc_inside_for_loop():
    code = """
def process(employees):
    for employee in employees:
        employee_doc = frappe.get_doc("Employee", employee.name)
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF003"


def test_detects_get_doc_inside_while_loop():
    code = """
def process(employee_ids):
    while employee_ids:
        employee_id = employee_ids.pop()
        employee = frappe.get_doc("Employee", employee_id)
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1


def test_detects_multiple_get_doc_calls_inside_loop():
    code = """
def process(employees):
    for employee in employees:
        employee_doc = frappe.get_doc("Employee", employee.name)
        department = frappe.get_doc("Department", employee.department)
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 2


def test_ignores_get_doc_outside_loop():
    code = """
def process(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_ignores_non_get_doc_call_inside_loop():
    code = """
def process(employees):
    for employee in employees:
        process_employee(employee)
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_ignores_other_object_get_doc():
    code = """
def process(items):
    for item in items:
        document = custom_api.get_doc("Item", item.name)
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_detects_get_doc_inside_nested_loop_only_once():
    code = """
def process(data):
    for group in data:
        for employee in group:
            employee_doc = frappe.get_doc(
                "Employee",
                employee.name,
            )
"""

    rule = GetDocInsideLoopRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1