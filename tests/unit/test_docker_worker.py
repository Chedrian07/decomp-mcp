from __future__ import annotations

import json
from pathlib import Path

import pytest

from decomp_mcp.docker_worker import DockerWorkerRunner, allowed_input_roots, host_output_root, resolve_host_binary_path
from decomp_mcp.ghidra_runner import decompile_binary
from decomp_mcp.models import DecompileRequest


def test_docker_worker_mounts_host_binary_and_returns_worker_result(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"fake binary")
    capture_path = tmp_path / "capture.json"
    fake_docker = _write_fake_docker(tmp_path, capture_path)

    monkeypatch.setenv("DECOMP_MCP_DOCKER_COMMAND", str(fake_docker))
    monkeypatch.setenv("DECOMP_MCP_DOCKER_IMAGE", "decomp-mcp:test")
    monkeypatch.setenv("DECOMP_MCP_HOST_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("DECOMP_MCP_ALLOWED_INPUT_ROOTS", str(input_root))

    result = DockerWorkerRunner().decompile(DecompileRequest(binary_path=str(binary), total_timeout_sec=1))
    capture = json.loads(capture_path.read_text(encoding="utf-8"))

    assert result["status"] == "ok"
    assert result["execution_mode"] == "docker-worker"
    assert result["host_binary_path"] == str(binary)
    assert capture["payload"]["binary_path"] == "/input/hello"
    assert f"{input_root}:/input:ro" in capture["argv"]
    assert f"{output_root}:/output:rw" in capture["argv"]
    assert "DECOMP_MCP_EXECUTION_MODE=direct" in capture["argv"]
    assert "decomp-mcp:test" in capture["argv"]


def test_decompile_binary_defaults_to_docker_worker(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"fake binary")
    capture_path = tmp_path / "capture.json"
    fake_docker = _write_fake_docker(tmp_path, capture_path)

    monkeypatch.delenv("DECOMP_MCP_EXECUTION_MODE", raising=False)
    monkeypatch.setenv("DECOMP_MCP_DOCKER_COMMAND", str(fake_docker))
    monkeypatch.setenv("DECOMP_MCP_HOST_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("DECOMP_MCP_ALLOWED_INPUT_ROOTS", str(input_root))

    result = decompile_binary(binary_path=str(binary), total_timeout_sec=1)

    assert result["status"] == "ok"
    assert result["execution_mode"] == "docker-worker"


def test_docker_worker_defaults_to_launch_cwd_for_claude_code(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DECOMP_MCP_ALLOWED_INPUT_ROOTS", raising=False)
    monkeypatch.delenv("DECOMP_MCP_HOST_OUTPUT_ROOT", raising=False)
    monkeypatch.delenv("DECOMP_MCP_OUTPUT_ROOT", raising=False)

    assert allowed_input_roots() == [tmp_path.resolve()]
    assert host_output_root() == (tmp_path / "decompiled").resolve()


def test_docker_worker_blocks_paths_outside_allowed_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    binary = outside / "hello"
    binary.write_bytes(b"fake binary")

    with pytest.raises(ValueError, match="binary_path must resolve under"):
        resolve_host_binary_path(str(binary), [allowed.resolve()])


def test_docker_worker_returns_failed_when_docker_missing(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"fake binary")

    monkeypatch.setenv("DECOMP_MCP_DOCKER_COMMAND", str(tmp_path / "missing-docker"))
    monkeypatch.setenv("DECOMP_MCP_HOST_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("DECOMP_MCP_ALLOWED_INPUT_ROOTS", str(input_root))

    result = DockerWorkerRunner().decompile(DecompileRequest(binary_path=str(binary), total_timeout_sec=1))

    assert result["status"] == "failed"
    assert result["artifact_id"] is None
    assert "Docker command not found" in result["warnings"][0]


def _write_fake_docker(tmp_path: Path, capture_path: Path) -> Path:
    docker = tmp_path / "fake_docker.py"
    docker.write_text(
        f"""#!/usr/bin/env python3
import json
import pathlib
import sys

payload = json.load(sys.stdin)
pathlib.Path({str(capture_path)!r}).write_text(json.dumps({{"argv": sys.argv[1:], "payload": payload}}))
json.dump({{
    "status": "ok",
    "artifact_id": "hello-deadbeef-cafebabe",
    "artifact_dir": "/tmp/out/artifacts/hello-deadbeef-cafebabe",
    "manifest_path": "/tmp/out/artifacts/hello-deadbeef-cafebabe/manifest.json",
    "index_path": "/tmp/out/artifacts/hello-deadbeef-cafebabe/index.json",
    "binary_sha256": "abc",
    "cache_hit": False,
    "stats": {{"functions_total": 1}},
    "warnings": []
}}, sys.stdout)
sys.stdout.write("\\n")
""",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return docker
