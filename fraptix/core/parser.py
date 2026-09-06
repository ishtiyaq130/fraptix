import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ParseResult:
    path: Path
    tree: ast.AST | None
    error: str | None = None
    line: int | None = None
    column: int | None = None

    @property
    def success(self) -> bool:
        return self.tree is not None


class PythonParser:
    """Parse Python source files into AST trees."""

    def parse(self, path: Path) -> ParseResult:
        try:
            source = path.read_text(encoding="utf-8")

            tree = ast.parse(
                source,
                filename=str(path),
            )

            return ParseResult(
                path=path,
                tree=tree,
            )

        except SyntaxError as error:
            return ParseResult(
                path=path,
                tree=None,
                error=error.msg,
                line=error.lineno,
                column=error.offset,
            )

        except UnicodeDecodeError as error:
            return ParseResult(
                path=path,
                tree=None,
                error=f"Unable to decode file: {error}",
            )

        except OSError as error:
            return ParseResult(
                path=path,
                tree=None,
                error=f"Unable to read file: {error}",
            )