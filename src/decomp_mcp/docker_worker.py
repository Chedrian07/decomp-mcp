from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .hashing import sha256_file
from .models import DecompileRequest, JadxRequest
from .paths import _is_relative_to


DEFAULT_DOCKER_IMAGE = "decomp-mcp:0.1.0"
DEFAULT_DOCKER_PLATFORM = "linux/amd64"


class DockerWorkerRunner:
    def __init__(self) -> None:
        self.docker = os.environ.get("DECOMP_MCP_DOCKER_COMMAND", "docker")
        self.image = os.environ.get("DECOMP_MCP_DOCKER_IMAGE", DEFAULT_DOCKER_IMAGE)
        self.platform = os.environ.get("DECOMP_MCP_DOCKER_PLATFORM", DEFAULT_DOCKER_PLATFORM)
        self.output_root = host_output_root()
        self.allowed_roots = allowed_input_roots()

    def decompile(self, request: DecompileRequest) -> dict[str, Any]:
        return self._run_engine(
            engine="ghidra",
            request_payload=request.normalized(),
            host_binary_path=request.binary_path,
            total_timeout_sec=request.effective_total_timeout_sec(),
        )

    def decompile_apk(self, request: JadxRequest) -> dict[str, Any]:
        return self._run_engine(
            engine="jadx",
            request_payload=request.normalized(),
            host_binary_path=request.binary_path,
            total_timeout_sec=request.effective_total_timeout_sec(),
        )

    def _run_engine(
        self,
        engine: str,
        request_payload: dict[str, Any],
        host_binary_path: str,
        total_timeout_sec: int,
    ) -> dict[str, Any]:
        binary = resolve_host_binary_path(host_binary_path, self.allowed_roots)
        self.output_root.mkdir(parents=True, exist_ok=True)

        if shutil.which(self.docker) is None:
            return _worker_start_failure(
                binary=binary,
                output_root=self.output_root,
                warning=f"Docker command not found: {self.docker}",
            )

        container_binary_path = Path("/input") / binary.name
        worker_request = dict(request_payload)
        worker_request["binary_path"] = str(container_binary_path)
        if worker_request.get("output_name") is None:
            worker_request["output_name"] = binary.stem
        worker_request["engine"] = engine

        command = self._docker_command(binary)
        timeout = total_timeout_sec + int(os.environ.get("DECOMP_MCP_DOCKER_STARTUP_TIMEOUT_SEC", "120"))
        try:
            completed = subprocess.run(
                command,
                input=json.dumps(worker_request),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return _worker_start_failure(
                binary=binary,
                output_root=self.output_root,
                warning=f"Docker worker timed out after {timeout} seconds",
            )

        if completed.stdout.strip():
            try:
                result = json.loads(completed.stdout)
            except json.JSONDecodeError:
                result = None
            if isinstance(result, dict) and completed.returncode == 0:
                result["execution_mode"] = "docker-worker"
                result["host_binary_path"] = str(binary)
                return result
            if isinstance(result, dict) and result.get("status") == "failed":
                result.setdefault("execution_mode", "docker-worker")
                result.setdefault("host_binary_path", str(binary))
                return result

        warning = f"Docker worker exited with code {completed.returncode}: {_short_stderr(completed.stderr)}"
        return _worker_start_failure(binary=binary, output_root=self.output_root, warning=warning)

    def _docker_command(self, binary: Path) -> list[str]:
        command = [
            self.docker,
            "run",
            "-i",
            "--rm",
            "--platform",
            self.platform,
            "--network",
            os.environ.get("DECOMP_MCP_DOCKER_NETWORK", "none"),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            os.environ.get("DECOMP_MCP_DOCKER_PIDS_LIMIT", "512"),
            "--memory",
            os.environ.get("DECOMP_MCP_DOCKER_MEMORY", "8g"),
            "--cpus",
            os.environ.get("DECOMP_MCP_DOCKER_CPUS", "4"),
            "-e",
            "DECOMP_MCP_EXECUTION_MODE=direct",
            "-e",
            f"DECOMP_MCP_HOST_OUTPUT_ROOT={self.output_root}",
            "-v",
            f"{binary.parent}:/input:ro",
            "-v",
            f"{self.output_root}:/output:rw",
            "--entrypoint",
            "decomp-mcp-worker",
            self.image,
        ]
        return command


def host_output_root() -> Path:
    configured = os.environ.get("DECOMP_MCP_HOST_OUTPUT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()

    output = os.environ.get("DECOMP_MCP_OUTPUT_ROOT")
    if output and output != "/output":
        return Path(output).expanduser().resolve()

    return (Path.cwd() / "decompiled").resolve()


def allowed_input_roots() -> list[Path]:
    configured = os.environ.get("DECOMP_MCP_ALLOWED_INPUT_ROOTS")
    if not configured:
        return [Path.cwd().resolve()]

    roots: list[Path] = []
    for item in configured.replace(os.pathsep, ",").split(","):
        value = item.strip()
        if not value:
            continue
        roots.append(Path(value).expanduser().resolve())
    if not roots:
        raise ValueError("DECOMP_MCP_ALLOWED_INPUT_ROOTS did not contain any usable paths")
    return roots


def resolve_host_binary_path(binary_path: str, roots: list[Path]) -> Path:
    if not binary_path:
        raise ValueError("binary_path is required")

    candidate = Path(binary_path).expanduser()
    if not candidate.is_absolute():
        candidate = roots[0] / candidate

    resolved = candidate.resolve(strict=True)
    if not any(_is_relative_to(resolved, root) for root in roots):
        allowed = ", ".join(str(root) for root in roots)
        raise ValueError(f"binary_path must resolve under one of: {allowed}")
    if not resolved.is_file():
        raise ValueError("binary_path must be a regular file")
    return resolved


def _worker_start_failure(binary: Path, output_root: Path, warning: str) -> dict[str, Any]:
    binary_sha256 = ""
    try:
        binary_sha256 = sha256_file(binary)
    except OSError:
        pass
    return {
        "status": "failed",
        "artifact_id": None,
        "artifact_dir": str(output_root / "artifacts"),
        "manifest_path": None,
        "index_path": None,
        "binary_sha256": binary_sha256,
        "cache_hit": False,
        "stats": {},
        "warnings": [warning],
        "execution_mode": "docker-worker",
        "host_binary_path": str(binary),
    }


def _short_stderr(stderr: str) -> str:
    text = " ".join(stderr.strip().split())
    if not text:
        return "no stderr"
    return text[:1000]
