import ast
from pathlib import Path
from fraptix.core.models import Severity

from fraptix.rules.security.sql_interpolation import (
    SQLInterpolationRule,
)


RULE = SQLInterpolationRule()
FILE = Path("test.py")


def analyze(source):
    tree = ast.parse(source)
    return RULE.check(tree, FILE)


def test_detects_f_string_sql():
    source = """
import frappe

employee = "EMP-001"

frappe.db.sql(
    f"SELECT * FROM `tabEmployee` WHERE name = '{employee}'"
)
"""

    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.HIGH


def test_detects_percent_formatting():
    source = """
import frappe

employee = "EMP-001"

frappe.db.sql(
    "SELECT * FROM `tabEmployee` WHERE name = '%s'" % employee
)
"""

    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.HIGH


def test_detects_format_method():
    source = """
import frappe

employee = "EMP-001"

frappe.db.sql(
    "SELECT * FROM `tabEmployee` WHERE name = '{}'".format(employee)
)
"""

    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.HIGH


def test_detects_string_concatenation():
    source = """
import frappe

employee = "EMP-001"

frappe.db.sql(
    "SELECT * FROM `tabEmployee` WHERE name = '" + employee + "'"
)
"""

    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.HIGH

def test_allows_parameterized_query():
    source = """
import frappe

employee = "EMP-001"

frappe.db.sql(
    '''
    SELECT *
    FROM `tabEmployee`
    WHERE name = %(name)s
    ''',
    {"name": employee},
)
"""

    findings = analyze(source)

    assert len(findings) == 0


def test_allows_positional_parameters():
    source = """
import frappe

employee = "EMP-001"

frappe.db.sql(
    '''
    SELECT *
    FROM `tabEmployee`
    WHERE name = %s
    ''',
    (employee,),
)
"""

    findings = analyze(source)

    assert len(findings) == 0


def test_allows_static_query():
    source = """
import frappe

frappe.db.sql(
    "SELECT * FROM `tabEmployee`"
)
"""

    findings = analyze(source)

    assert len(findings) == 0

def test_allows_non_sql_f_string():
    source = """
employee = "EMP-001"

message = f"Employee: {employee}"
"""

    findings = analyze(source)

    assert len(findings) == 0

def test_detects_dynamic_sql_fragment():
    source = """
import frappe

where_condition = "company = %(company)s"

frappe.db.sql(
    "SELECT * FROM `tabGL Entry` WHERE {}".format(where_condition)
)
"""

    findings = analyze(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.MEDIUM

def test_allows_static_sql_identifier_interpolation():
    source = """
import frappe

COLUMN_RENAMES = [
    ("old_field", "new_field"),
]

existing_columns = frappe.db.get_table_columns("Appointment Letter")

for old_name, new_name in COLUMN_RENAMES:
    if old_name in existing_columns and new_name in existing_columns:
        frappe.db.sql(
            "UPDATE `tabAppointment Letter` SET `{}` = `{}`".format(
                new_name,
                old_name,
            )
        )

        frappe.db.sql(
            "ALTER TABLE `tabAppointment Letter` DROP COLUMN `{}`".format(
                old_name
            )
        )
"""

    findings = analyze(source)

    assert len(findings) == 0