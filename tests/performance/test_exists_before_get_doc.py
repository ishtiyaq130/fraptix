import ast

from fraptix.rules.performance.exists_before_get_doc import (
    ExistsBeforeGetDocRule,
)


def run_rule(code):
    tree = ast.parse(code)
    rule = ExistsBeforeGetDocRule()
    return rule.check(tree, "test.py")


def test_detects_exists_followed_by_get_doc():
    code = """
def get_employee(employee):
    if frappe.db.exists("Employee", employee):
        return frappe.get_doc("Employee", employee)
"""
    findings = run_rule(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PERF007"


def test_ignores_different_documents():
    code = """
def get_employee(employee):
    if frappe.db.exists("Employee", employee):
        return frappe.get_doc("Employee", "EMP-001")
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_get_doc_without_exists():
    code = """
def get_employee(employee):
    return frappe.get_doc("Employee", employee)
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_exists_without_get_doc():
    code = """
def employee_exists(employee):
    return frappe.db.exists("Employee", employee)
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_exists_after_get_doc():
    code = """
def get_employee(employee):
    doc = frappe.get_doc("Employee", employee)
    frappe.db.exists("Employee", employee)
    return doc
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_ignores_different_expression():
    code = """
def get_employee(employee):
    if frappe.db.exists("Employee", employee):
        return frappe.get_doc("Employee", employee + "-COPY")
"""
    findings = run_rule(code)

    assert len(findings) == 0


def test_detects_repeated_same_document():
    code = """
def get_employee(employee):
    if frappe.db.exists("Employee", employee):
        first = frappe.get_doc("Employee", employee)
        second = frappe.get_doc("Employee", employee)
        return second
"""
    findings = run_rule(code)

    assert len(findings) == 2