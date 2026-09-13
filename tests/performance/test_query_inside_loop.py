import ast
from pathlib import Path

from fraptix.rules.performance.query_inside_loop import QueryInsideLoopRule


def run_rule(code: str):
    tree = ast.parse(code)

    rule = QueryInsideLoopRule()

    return rule.check(
        tree,
        Path("test.py"),
    )


def test_detects_db_query_inside_for_loop():
    code = """
def process_items(items):
    for item in items:
        frappe.db.get_value("Employee", item.name, "employee_name")
"""

    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF001"


def test_detects_db_query_inside_while_loop():
    code = """
def process_items(items):
    while items:
        frappe.db.get_value("Employee", items.pop(), "employee_name")
"""

    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF001"


def test_detects_multiple_queries_inside_loop():
    code = """
def process_items(items):
    for item in items:
        frappe.db.get_value("Employee", item.name, "employee_name")
        frappe.db.get_value("Employee", item.name, "department")
"""

    findings = run_rule(code)

    assert len(findings) == 2


def test_ignores_query_outside_loop():
    code = """
def get_employee(name):
    return frappe.db.get_value(
        "Employee",
        name,
        "employee_name",
    )
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_non_database_function_inside_loop():
    code = """
def process_items(items):
    for item in items:
        print(item.name)
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_detects_get_all_inside_loop():
    code = """
def process_items(items):
    for item in items:
        frappe.db.get_all(
            "Employee",
            filters={"department": item.department},
        )
"""

    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF001"


def test_detects_sql_inside_loop():
    code = """
def process_items(items):
    for item in items:
        frappe.db.sql(
            "SELECT name FROM tabEmployee WHERE department = %s",
            item.department,
        )
"""

    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF001"