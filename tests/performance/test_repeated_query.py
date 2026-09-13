import ast
from pathlib import Path

from fraptix.rules.performance.query_repeated import (
    RepeatedDatabaseQueryRule,
)


def parse_code(code):
    return ast.parse(code)


def test_detects_repeated_get_value():
    code = """
def process(employee_id):
    department = frappe.db.get_value(
        "Employee",
        employee_id,
        "department",
    )

    department_again = frappe.db.get_value(
        "Employee",
        employee_id,
        "department",
    )
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF002"


def test_detects_repeated_get_all():
    code = """
def process():
    first = frappe.db.get_all(
        "Employee",
        filters={"status": "Active"},
    )

    second = frappe.db.get_all(
        "Employee",
        filters={"status": "Active"},
    )
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1


def test_detects_repeated_get_list():
    code = """
def process():
    first = frappe.db.get_list(
        "Employee",
        filters={"status": "Active"},
    )

    second = frappe.db.get_list(
        "Employee",
        filters={"status": "Active"},
    )
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert len(findings) == 1


def test_ignores_different_queries():
    code = """
def process(employee_id):
    department = frappe.db.get_value(
        "Employee",
        employee_id,
        "department",
    )

    salary = frappe.db.get_value(
        "Employee",
        employee_id,
        "salary",
    )
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_ignores_single_query():
    code = """
def process(employee_id):
    department = frappe.db.get_value(
        "Employee",
        employee_id,
        "department",
    )
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_ignores_non_database_calls():
    code = """
def process(employee_id):
    first = get_employee(employee_id)
    second = get_employee(employee_id)
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []


def test_does_not_compare_queries_across_functions():
    code = """
def first(employee_id):
    return frappe.db.get_value(
        "Employee",
        employee_id,
        "department",
    )


def second(employee_id):
    return frappe.db.get_value(
        "Employee",
        employee_id,
        "department",
    )
"""

    rule = RepeatedDatabaseQueryRule()

    findings = rule.check(
        parse_code(code),
        Path("test.py"),
    )

    assert findings == []