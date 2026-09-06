from pathlib import Path


class FileScanner:
    """Find source files inside a Frappe application."""

    DEFAULT_EXCLUDED_DIRS = {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        ".venv",
        "venv",
    }

    def __init__(self, excluded_dirs=None):
        self.excluded_dirs = (
            set(excluded_dirs)
            if excluded_dirs is not None
            else self.DEFAULT_EXCLUDED_DIRS
        )

    def scan(self, app_path: Path) -> list[Path]:
        app_path = app_path.resolve()

        if not app_path.is_dir():
            raise ValueError(
                f"Application path does not exist: {app_path}"
            )

        files = []

        for path in app_path.rglob("*.py"):
            if self._should_exclude(path, app_path):
                continue

            files.append(path)

        return sorted(files)

    def _should_exclude(
        self,
        path: Path,
        root: Path,
    ) -> bool:
        relative_path = path.relative_to(root)

        return any(
            part in self.excluded_dirs
            for part in relative_path.parts
        )