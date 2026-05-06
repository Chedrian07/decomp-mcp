from __future__ import annotations

import os
import re
from pathlib import Path


SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def input_root() -> Path:
    return Path(os.environ.get("DECOMP_MCP_INPUT_ROOT", "/input"))


def output_root() -> Path:
    return Path(os.environ.get("DECOMP_MCP_OUTPUT_ROOT", "/output"))


def artifacts_root(base_output: Path | None = None) -> Path:
    return (base_output or output_root()) / "artifacts"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def ghidra_script_dir() -> Path:
    configured = os.environ.get("DECOMP_MCP_GHIDRA_SCRIPT_DIR")
    if configured:
        return Path(configured)
    local = repo_root() / "ghidra_scripts"
    if local.exists():
        return local
    return Path("/app/ghidra_scripts")


def resolve_binary_path(binary_path: str, root: Path | None = None) -> Path:
    if not binary_path:
        raise ValueError("binary_path is required")

    input_base = (root or input_root()).resolve(strict=True)
    candidate = Path(binary_path)
    if not candidate.is_absolute():
        candidate = input_base / candidate

    resolved = candidate.resolve(strict=True)
    if not _is_relative_to(resolved, input_base):
        raise ValueError(f"binary_path must resolve under {input_base}")
    if not resolved.is_file():
        raise ValueError("binary_path must be a regular file")
    return resolved


def sanitize_name(value: str | None, default: str = "artifact", max_len: int = 80) -> str:
    base = (value or default).strip()
    if not base:
        base = default
    sanitized = SAFE_NAME_RE.sub("_", base)
    sanitized = sanitized.strip("._-")
    if not sanitized:
        sanitized = default
    return sanitized[:max_len]


def ensure_artifact_dirs(root: Path) -> None:
    (root / ".tmp").mkdir(parents=True, exist_ok=True)
    (root / ".locks").mkdir(parents=True, exist_ok=True)


def display_container_path(path: Path, mounted_root: Path, container_root: str) -> str:
    try:
        rel = path.resolve().relative_to(mounted_root.resolve())
        return str(Path(container_root) / rel)
    except ValueError:
        return str(path)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False

