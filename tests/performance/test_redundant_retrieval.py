import ast

from fraptix.rules.performance.redundant_retrieval import (
    RedundantDatabaseRetrievalRule,
)


def run_rule(code):
    tree = ast.parse(code)
    rule = RedundantDatabaseRetrievalRule()
    return rule.check(tree, "test.py")


def test_detects_get_doc_followed_by_get_value():
    code = """
def get_employee(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
    name = frappe.db.get_value("Employee", employee_id, "employee_name")
    return name
"""

    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF005"


def test_ignores_different_document_names():
    code = """
def get_employees(employee_id, manager_id):
    employee = frappe.get_doc("Employee", employee_id)
    manager = frappe.db.get_value("Employee", manager_id, "employee_name")
    return manager
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_different_doctypes():
    code = """
def get_employee(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
    company = frappe.db.get_value("Company", employee_id, "company_name")
    return company
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_different_database_field():
    code = """
def get_employee(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
    department = frappe.db.get_value("Employee", employee_id, "department")
    return department
"""

    findings = run_rule(code)

    assert len(findings) == 1


def test_ignores_get_doc_without_followup_query():
    code = """
def get_employee(employee_id):
    employee = frappe.get_doc("Employee", employee_id)
    return employee
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_get_value_without_get_doc():
    code = """
def get_employee(employee_id):
    name = frappe.db.get_value("Employee", employee_id, "employee_name")
    return name
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_does_not_compare_across_functions():
    code = """
def get_employee(employee_id):
    employee = frappe.get_doc("Employee", employee_id)


def get_name(employee_id):
    name = frappe.db.get_value("Employee", employee_id, "employee_name")
    return name
"""

    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_non_frappe_get_doc():
    code = """
def get_employee(employee_id):
    employee = employee_service.get_doc("Employee", employee_id)
    name = frappe.db.get_value("Employee", employee_id, "employee_name")
    return name
"""

    findings = run_rule(code)

    assert len(findings) == 0

def test_ignores_database_retrieval_before_get_doc():
    code = """
def get_employee(employee_id):
    name = frappe.db.get_value("Employee", employee_id, "employee_name")
    employee = frappe.get_doc("Employee", employee_id)
    return employee
"""

    findings = run_rule(code)

    assert len(findings) == 0