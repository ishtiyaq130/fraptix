import ast
from pathlib import Path

from fraptix.rules.performance.get_doc_repeated import (
    RepeatedGetDocRule,
)


def parse_code(code):
    return ast.parse(code)


def test_detects_repeated_get_doc():
    code = """
def process(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
    employee_again = frappe.get_doc("Employee", employee_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF004"


def test_detects_repeated_get_doc_three_times():
    code = """
def process(employee_id):
    frappe.get_doc("Employee", employee_id)
    frappe.get_doc("Employee", employee_id)
    frappe.get_doc("Employee", employee_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1


def test_ignores_different_documents():
    code = """
def process(employee_id, department_id):
    employee = frappe.get_doc("Employee", employee_id)
    department = frappe.get_doc("Department", department_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_ignores_single_get_doc():
    code = """
def process(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_ignores_other_object_get_doc():
    code = """
def process(employee_id):
    employee = custom_api.get_doc("Employee", employee_id)
    employee_again = custom_api.get_doc("Employee", employee_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_does_not_compare_across_functions():
    code = """
def first(employee_id):
    employee = frappe.get_doc("Employee", employee_id)

def second(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_detects_repeated_get_doc_inside_loop():
    code = """
def process(employee_id):
    for i in range(2):
        employee = frappe.get_doc("Employee", employee_id)
        employee_again = frappe.get_doc("Employee", employee_id)
"""

    rule = RepeatedGetDocRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1