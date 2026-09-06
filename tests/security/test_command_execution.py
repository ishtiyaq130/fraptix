import ast
from pathlib import Path

from fraptix.rules.security.command_execution import CommandExecutionRule


RULE = CommandExecutionRule()
FILE = Path("test.py")


def analyze(source):
    tree = ast.parse(source)
    return RULE.check(tree, FILE)


def test_detects_dynamic_os_system():
    findings = analyze(
        """
command = user_input
os.system(command)
"""
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC003"
    assert findings[0].severity.value == "critical"


def test_detects_static_os_system():
    findings = analyze(
        """
os.system("ls -la")
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_detects_dynamic_os_popen():
    findings = analyze(
        """
command = get_command()
os.popen(command)
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_detects_subprocess_run_shell_true():
    findings = analyze(
        """
command = user_input
subprocess.run(command, shell=True)
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_detects_subprocess_call_shell_true():
    findings = analyze(
        """
subprocess.call("ls -la", shell=True)
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_detects_subprocess_popen_shell_true():
    findings = analyze(
        """
command = get_command()
subprocess.Popen(command, shell=True)
"""
    )

    assert len(findings) == 1
    assert findings[0].severity.value == "critical"


def test_allows_subprocess_without_shell():
    findings = analyze(
        """
subprocess.run(["git", "status"])
"""
    )

    assert len(findings) == 0


def test_allows_subprocess_shell_false():
    findings = analyze(
        """
command = user_input
subprocess.run(command, shell=False)
"""
    )

    assert len(findings) == 0


def test_ignores_unrelated_method():
    findings = analyze(
        """
obj.system(command)
"""
    )

    assert len(findings) == 0