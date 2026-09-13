import ast

from fraptix.rules.performance.unbounded_retrieval import (
    UnboundedDatabaseRetrievalRule,
)


def run_rule(code):
    tree = ast.parse(code)
    rule = UnboundedDatabaseRetrievalRule()
    return rule.check(tree, "test.py")


def test_detects_unbounded_get_all():
    code = """
def get_employees():
    employees = frappe.db.get_all("Employee")
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF006"


def test_detects_unbounded_get_list():
    code = """
def get_employees():
    employees = frappe.db.get_list("Employee")
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF006"


def test_ignores_get_all_with_limit_page_length():
    code = """
def get_employees():
    employees = frappe.db.get_all(
        "Employee",
        limit_page_length=20
    )
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_get_list_with_limit_page_length():
    code = """
def get_employees():
    employees = frappe.db.get_list(
        "Employee",
        limit_page_length=20
    )
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_get_value():
    code = """
def get_employee(employee_id):
    return frappe.db.get_value(
        "Employee",
        employee_id,
        "employee_name"
    )
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_non_frappe_get_all():
    code = """
def get_employees():
    employees = db.get_all("Employee")
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_detects_retrieval_assigned_to_variable():
    code = """
def get_employees():
    employees = frappe.db.get_all("Employee")
    process(employees)
"""
    findings = run_rule(code)

    assert len(findings) == 1


def test_detects_retrieval_used_in_loop():
    code = """
def process_employees():
    for employee in frappe.db.get_all("Employee"):
        process(employee)
"""
    findings = run_rule(code)

    assert len(findings) == 1

def test_ignores_get_all_with_filters():
    code = """
def get_employees(company):
    employees = frappe.db.get_all(
        "Employee",
        filters={"company": company}
    )
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_get_list_with_filters():
    code = """
def get_employees(employee):
    employees = frappe.db.get_list(
        "Employee",
        filters={"employee": employee}
    )
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0

def test_ignores_get_all_with_positional_filters():
    code = """
def get_employees():
    employees = frappe.db.get_all(
        "Employee",
        {"status": "Active"}
    )
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0

def test_ignores_get_list_with_positional_filters():
    code = """
def get_employees():
    employees = frappe.db.get_list(
        "Employee",
        {"company": "Test Company"}
    )
    return employees
"""
    findings = run_rule(code)

    assert len(findings) == 0