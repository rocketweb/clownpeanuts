from __future__ import annotations

from pathlib import Path
import tomllib


def test_api_extra_includes_uvicorn_standard() -> None:
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    api_dependencies = pyproject.get("project", {}).get("optional-dependencies", {}).get("api", [])
    assert any(str(item).startswith("uvicorn[standard]") for item in api_dependencies)
