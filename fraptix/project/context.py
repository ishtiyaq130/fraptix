from dataclasses import dataclass
from pathlib import Path


@dataclass
class ProjectContext:
    root: Path
    apps_path: Path