import ast
from pathlib import Path

from fraptix.core.models import Severity
from fraptix.rules.security.path_traversal import PathTraversalRule


def get_findings(code):
    tree = ast.parse(code)
    rule = PathTraversalRule()

    return rule.check(tree, Path("test.py"))


def test_detects_open_with_parameter():
    code = """
import frappe

@frappe.whitelist()
def read_file(path):
    with open(path, "r") as file:
        return file.read()
"""

    findings = get_findings(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC006"
    assert findings[0].severity == Severity.HIGH


def test_detects_open_with_request_input():
    code = """
import frappe

@frappe.whitelist()
def read_file():
    path = frappe.form_dict.path
    return open(path, "r").read()
"""

    findings = get_findings(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC006"


def test_detects_os_path_with_user_input():
    code = """
import frappe
import os

@frappe.whitelist()
def read_file(filename):
    path = os.path.join("/tmp", filename)
    return open(path).read()
"""

    findings = get_findings(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC006"


def test_ignores_constant_file_path():
    code = """
import frappe

@frappe.whitelist()
def read_config():
    return open("/etc/app/config.json").read()
"""

    findings = get_findings(code)

    assert len(findings) == 0


def test_ignores_non_whitelisted_function():
    code = """
def read_file(path):
    return open(path, "r").read()
"""

    findings = get_findings(code)

    assert len(findings) == 0


def test_detects_parameter_inside_path_expression():
    code = """
import frappe

@frappe.whitelist()
def read_file(filename):
    path = "/tmp/" + filename
    return open(path).read()
"""

    findings = get_findings(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC006"


def test_ignores_safe_literal_join():
    code = """
import frappe
import os

@frappe.whitelist()
def read_file():
    path = os.path.join("/tmp", "report.txt")
    return open(path).read()
"""

    findings = get_findings(code)

    assert len(findings) == 0