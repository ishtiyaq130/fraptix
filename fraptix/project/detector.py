from pathlib import Path

from .context import ProjectContext


class ProjectDetector:

    def detect(self, path: Path) -> ProjectContext:
        path = path.resolve()

        apps_path = path / "apps"

        if not apps_path.is_dir():
            raise ValueError(
                f"Frappe bench not found: {path}"
            )

        return ProjectContext(
            root=path,
            apps_path=apps_path,
        )

    def get_app_path(
        self,
        project: ProjectContext,
        app_name: str,
    ) -> Path:

        app_path = project.apps_path / app_name

        if not app_path.is_dir():
            raise ValueError(
                f"Frappe application '{app_name}' was not found."
            )

        return app_path