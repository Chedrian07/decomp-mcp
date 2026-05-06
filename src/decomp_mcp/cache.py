from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import shutil
import time
from pathlib import Path
from typing import Any

from .paths import ensure_artifact_dirs


class ArtifactLock:
    def __init__(self, artifacts_dir: Path, artifact_id: str):
        ensure_artifact_dirs(artifacts_dir)
        self.path = artifacts_dir / ".locks" / f"{artifact_id}.lock"
        self._fd: int | None = None

    def __enter__(self) -> "ArtifactLock":
        self._fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        os.write(self._fd, str(os.getpid()).encode("ascii"))
        os.ftruncate(self._fd, len(str(os.getpid())))
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
            os.close(self._fd)
            self._fd = None


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")
    tmp.replace(path)


def check_cache(artifact_dir: Path, binary_sha256: str, options_hash: str) -> dict[str, Any] | None:
    manifest_path = artifact_dir / "manifest.json"
    index_path = artifact_dir / "index.json"
    if not manifest_path.exists() or not index_path.exists():
        return None
    try:
        manifest = read_json(manifest_path)
    except (OSError, json.JSONDecodeError):
        return None
    if manifest.get("status") not in {"ok", "partial"}:
        return None
    if manifest.get("input", {}).get("sha256") != binary_sha256:
        return None
    if manifest.get("options_hash") != options_hash:
        return None
    return manifest


def make_tmp_artifact_dir(artifacts_dir: Path, artifact_id: str) -> Path:
    ensure_artifact_dirs(artifacts_dir)
    tmp = artifacts_dir / ".tmp" / f"{artifact_id}.{os.getpid()}.{secrets.token_hex(6)}"
    tmp.mkdir(parents=True, exist_ok=False)
    return tmp


def finalize_artifact(tmp_dir: Path, final_dir: Path, force: bool = False) -> None:
    if final_dir.exists():
        if not force:
            raise FileExistsError(errno.EEXIST, "artifact already exists", str(final_dir))
        shutil.rmtree(final_dir)
    tmp_dir.replace(final_dir)


def discard_tmp(tmp_dir: Path) -> None:
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir, ignore_errors=True)


def clear_artifacts(artifacts_dir: Path, target: str = "failed", older_than_days: int | None = None) -> dict[str, object]:
    if target not in {"failed", "all"}:
        raise ValueError("target must be 'failed' or 'all'")
    if not artifacts_dir.exists():
        return {"target": target, "removed": 0, "artifact_ids": []}

    cutoff = None
    if older_than_days is not None:
        cutoff = time.time() - older_than_days * 86400

    removed: list[str] = []
    for child in artifacts_dir.iterdir():
        if child.name.startswith(".") or not child.is_dir():
            continue
        if cutoff is not None and child.stat().st_mtime >= cutoff:
            continue
        if target == "failed":
            manifest_path = child / "manifest.json"
            try:
                status = read_json(manifest_path).get("status")
            except (OSError, json.JSONDecodeError):
                status = "failed"
            if status != "failed":
                continue
        shutil.rmtree(child)
        removed.append(child.name)

    return {"target": target, "removed": len(removed), "artifact_ids": removed}

