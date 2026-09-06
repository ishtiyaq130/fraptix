import ast

from fraptix.core.parser import PythonParser


def test_parse_valid_python(tmp_path):
    file_path = tmp_path / "valid.py"

    file_path.write_text(
        """
def hello():
    return "world"
""",
        encoding="utf-8",
    )

    result = PythonParser().parse(file_path)

    assert result.success is True
    assert result.tree is not None
    assert isinstance(result.tree, ast.Module)
    assert result.error is None


def test_parse_invalid_python(tmp_path):
    file_path = tmp_path / "invalid.py"

    file_path.write_text(
        """
def hello(
    return "world"
""",
        encoding="utf-8",
    )

    result = PythonParser().parse(file_path)

    assert result.success is False
    assert result.tree is None
    assert result.error is not None
    assert result.line is not None


def test_parse_missing_file(tmp_path):
    file_path = tmp_path / "missing.py"

    result = PythonParser().parse(file_path)

    assert result.success is False
    assert result.tree is None
    assert result.error is not None