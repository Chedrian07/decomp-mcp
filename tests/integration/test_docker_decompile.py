from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from decomp_mcp.clients.direct_mcp_smoke import call_decompile


IMAGE = "decomp-mcp:test"


def test_docker_mcp_decompiles_hello_and_reuses_cache(tmp_path: Path) -> None:
    _require_docker()
    project_root = Path.cwd()
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    tmp_path.chmod(0o777)
    input_dir.chmod(0o777)
    output_dir.chmod(0o777)

    subprocess.run(["docker", "build", "--platform", "linux/amd64", "-t", IMAGE, "."], cwd=project_root, check=True)
    subprocess.run(
        [
            sys.executable,
            str(project_root / "tests" / "samples" / "build_hello_elf.py"),
            str(input_dir / "hello"),
        ],
        check=True,
    )

    server_args = [
        "run",
        "-i",
        "--rm",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-e",
        f"DECOMP_MCP_HOST_OUTPUT_ROOT={output_dir}",
        "-v",
        f"{input_dir}:/input:ro",
        "-v",
        f"{output_dir}:/output:rw",
        IMAGE,
    ]
    first = asyncio.run(call_decompile("docker", server_args, {"binary_path": "/input/hello", "total_timeout_sec": 900}))
    second = asyncio.run(call_decompile("docker", server_args, {"binary_path": "/input/hello", "total_timeout_sec": 900}))

    artifact_dir = output_dir / "artifacts" / first["artifact_id"]
    manifest = json.loads((artifact_dir / "manifest.json").read_text(encoding="utf-8"))
    index = json.loads((artifact_dir / "index.json").read_text(encoding="utf-8"))
    sections = json.loads((artifact_dir / "sections.json").read_text(encoding="utf-8"))
    symbols = json.loads((artifact_dir / "symbols.json").read_text(encoding="utf-8"))
    function_files = list((artifact_dir / "functions").glob("*main*.c"))

    assert first["status"] in {"ok", "partial"}
    assert first["artifact_dir"].startswith(str(output_dir))
    assert first["container_artifact_dir"].startswith("/output/")
    assert first["cache_hit"] is False
    assert second["status"] == "cached"
    assert second["cache_hit"] is True
    assert (artifact_dir / "manifest.json").exists()
    assert index["functions"]
    assert (artifact_dir / "index.jsonl").read_text(encoding="utf-8").strip()
    assert sections["sections"]
    assert any(symbol["name"] == "main" for symbol in symbols["symbols"])
    assert manifest["paths"]["sections"] == "sections.json"
    assert manifest["stats"]["sections_total"] >= 1
    assert function_files


def test_docker_mcp_handles_invalid_binary(tmp_path: Path) -> None:
    _require_docker()
    project_root = Path.cwd()
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    tmp_path.chmod(0o777)
    input_dir.chmod(0o777)
    output_dir.chmod(0o777)
    (input_dir / "invalid").write_bytes(os.urandom(32))

    if not _image_exists(IMAGE):
        subprocess.run(["docker", "build", "--platform", "linux/amd64", "-t", IMAGE, "."], cwd=project_root, check=True)

    server_args = [
        "run",
        "-i",
        "--rm",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-e",
        f"DECOMP_MCP_HOST_OUTPUT_ROOT={output_dir}",
        "-v",
        f"{input_dir}:/input:ro",
        "-v",
        f"{output_dir}:/output:rw",
        IMAGE,
    ]
    result = asyncio.run(call_decompile("docker", server_args, {"binary_path": "/input/invalid", "total_timeout_sec": 300}))

    assert result["status"] == "failed"
    assert Path(output_dir / "artifacts" / result["artifact_id"] / "manifest.json").exists()


def test_host_mcp_docker_worker_decompiles_host_path(tmp_path: Path, monkeypatch) -> None:
    _require_docker()
    project_root = Path.cwd()
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    input_dir.mkdir()
    output_dir.mkdir()
    tmp_path.chmod(0o777)
    input_dir.chmod(0o777)
    output_dir.chmod(0o777)

    subprocess.run(["docker", "build", "--platform", "linux/amd64", "-t", IMAGE, "."], cwd=project_root, check=True)
    subprocess.run(
        [
            sys.executable,
            str(project_root / "tests" / "samples" / "build_hello_elf.py"),
            str(input_dir / "hello"),
        ],
        check=True,
    )

    monkeypatch.setenv("DECOMP_MCP_EXECUTION_MODE", "docker-worker")
    monkeypatch.setenv("DECOMP_MCP_DOCKER_IMAGE", IMAGE)
    monkeypatch.setenv("DECOMP_MCP_ALLOWED_INPUT_ROOTS", str(input_dir))
    monkeypatch.setenv("DECOMP_MCP_HOST_OUTPUT_ROOT", str(output_dir))

    server_env = dict(os.environ)
    first = asyncio.run(
        call_decompile(
            "uv",
            ["run", "decomp-mcp"],
            {"binary_path": str(input_dir / "hello"), "total_timeout_sec": 900},
            env=server_env,
        )
    )
    second = asyncio.run(
        call_decompile(
            "uv",
            ["run", "decomp-mcp"],
            {"binary_path": str(input_dir / "hello"), "total_timeout_sec": 900},
            env=server_env,
        )
    )

    artifact_dir = output_dir / "artifacts" / first["artifact_id"]
    index = json.loads((artifact_dir / "index.json").read_text(encoding="utf-8"))

    assert first["execution_mode"] == "docker-worker"
    assert first["host_binary_path"] == str(input_dir / "hello")
    assert first["artifact_dir"].startswith(str(output_dir))
    assert first["container_artifact_dir"].startswith("/output/")
    assert first["status"] in {"ok", "partial"}
    assert second["status"] == "cached"
    assert second["cache_hit"] is True
    assert any(function["name"] == "main" for function in index["functions"])


def _require_docker() -> None:
    if shutil.which("docker") is None:
        raise AssertionError("docker is required for integration tests")
    subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def _image_exists(image: str) -> bool:
    result = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0
