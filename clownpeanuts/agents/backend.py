"""Shared backend-loader helpers for optional agent modules."""

from __future__ import annotations

from importlib import import_module
from typing import Any, Iterable


class AgentBackendLoadError(RuntimeError):
    """Raised when an agent backend class cannot be loaded or validated."""


def load_backend(
    *,
    backend_path: str,
    module_name: str,
    required_methods: Iterable[str],
    init_kwargs: dict[str, Any] | None = None,
) -> Any | None:
    normalized_path = backend_path.strip()
    if not normalized_path:
        return None
    module_path, class_name = _split_backend_path(normalized_path)
    try:
        module = import_module(module_path)
    except Exception as exc:
        raise AgentBackendLoadError(
            f"failed to import {module_name} backend module '{module_path}': {exc}"
        ) from exc
    try:
        backend_factory = getattr(module, class_name)
    except AttributeError as exc:
        raise AgentBackendLoadError(
            f"{module_name} backend '{normalized_path}' does not expose '{class_name}'"
        ) from exc
    if not callable(backend_factory):
        raise AgentBackendLoadError(f"{module_name} backend '{normalized_path}' is not callable")
    kwargs = dict(init_kwargs or {})
    try:
        backend = backend_factory(**kwargs)
    except Exception as exc:
        raise AgentBackendLoadError(f"failed to instantiate {module_name} backend '{normalized_path}': {exc}") from exc
    missing_methods = [name for name in required_methods if not callable(getattr(backend, name, None))]
    if missing_methods:
        missing = ", ".join(sorted(missing_methods))
        raise AgentBackendLoadError(f"{module_name} backend '{normalized_path}' is missing methods: {missing}")
    return backend


def _split_backend_path(path: str) -> tuple[str, str]:
    if ":" in path:
        module_path, class_name = path.rsplit(":", 1)
    else:
        module_path, _sep, class_name = path.rpartition(".")
    module_path = module_path.strip()
    class_name = class_name.strip()
    if not module_path or not class_name:
        raise AgentBackendLoadError(
            "backend path must be 'package.module:ClassName' or 'package.module.ClassName'"
        )
    return module_path, class_name
