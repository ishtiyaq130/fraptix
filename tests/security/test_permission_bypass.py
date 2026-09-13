import ast
from pathlib import Path

from fraptix.rules.security.permission_bypass import (
    PermissionBypassRule,
)
from fraptix.core.models import Severity


def analyze(source: str):
    tree = ast.parse(source)

    rule = PermissionBypassRule()

    return rule.check(
        tree,
        Path("test.py"),
    )


def test_detects_parameter_as_user_input():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_salary(employee):
    return frappe.db.get_value(
        "Employee",
        employee,
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"


def test_detects_parameter_in_get_all_filters():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employees(company):
    return frappe.db.get_all(
        "Employee",
        filters={"company": company}
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"


def test_detects_parameter_in_get_single_value():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_company(company):
    return frappe.db.get_single_value(
        "Company",
        company
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"


def test_detects_frappe_form_dict():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employee():
    employee = frappe.form_dict.employee

    return frappe.db.get_value(
        "Employee",
        employee,
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"


def test_detects_request_attribute():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employee():
    return frappe.db.get_value(
        "Employee",
        frappe.request.args.get("employee"),
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"


def test_ignores_constant_value():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_country():
    return frappe.db.get_value(
        "System Settings",
        None,
        "country"
    )
"""
    )

    assert len(findings) == 0


def test_ignores_constant_document_name():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_company():
    return frappe.db.get_value(
        "Company",
        "Dawateislami India",
        "company_name"
    )
"""
    )

    assert len(findings) == 0


def test_ignores_non_whitelisted_function():
    findings = analyze(
        """
import frappe

def get_salary(employee):
    return frappe.db.get_value(
        "Employee",
        employee,
        "salary"
    )
"""
    )

    assert len(findings) == 0


def test_ignores_unrelated_object():
    findings = analyze(
        """
@frappe.whitelist()
def get_data(employee):
    return database.get_value(
        "Employee",
        employee
    )
"""
    )

    assert len(findings) == 0


def test_detects_nested_parameter_expression():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employee(employee):
    return frappe.db.get_value(
        "Employee",
        employee.strip(),
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"

def test_detects_permission_check():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employee(doctype, name):
    if not frappe.has_permission(doctype):
        frappe.throw("No permission")

    return frappe.db.get_value(
        doctype,
        name,
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"
    assert findings[0].severity == Severity.MEDIUM

def test_detects_read_permission_check():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employee(doctype, name):
    if not frappe.has_permission(doctype, "read"):
        frappe.throw("No permission")

    return frappe.db.get_value(
        doctype,
        name,
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"

def test_no_permission_check():
    findings = analyze(
        """
import frappe

@frappe.whitelist()
def get_employee(doctype, name):
    return frappe.db.get_value(
        doctype,
        name,
        "salary"
    )
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC005"
    assert findings[0].severity == Severity.HIGH

def test_has_permission_check_returns_true():
    tree = ast.parse(
        """
import frappe

@frappe.whitelist()
def get_employee(doctype):
    if not frappe.has_permission(doctype):
        frappe.throw("No permission")
"""
    )

    function = tree.body[1]

    rule = PermissionBypassRule()

    assert rule._has_permission_check(function) is True

def test_has_permission_check_returns_false():
    tree = ast.parse(
        """
import frappe

@frappe.whitelist()
def get_employee(doctype):
    return frappe.db.get_value(
        doctype,
        "test",
        "name"
    )
"""
    )

    function = tree.body[1]

    rule = PermissionBypassRule()

    assert rule._has_permission_check(function) is False