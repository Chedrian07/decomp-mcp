from __future__ import annotations

import json
import os
from pathlib import Path

from decomp_mcp.clients.llm_e2e import run_llm_check


def test_live_llm_e2e_reads_artifact_and_returns_content(tmp_path: Path) -> None:
    for name in ("DECOMP_MCP_LLM_API_KEY", "DECOMP_MCP_LLM_BASE_URL"):
        assert os.environ.get(name), f"{name} is required for mandatory LLM E2E tests"

    artifact_dir = _write_synthetic_artifact(tmp_path)
    content = run_llm_check(artifact_dir)

    assert content.strip()
    assert "sk-" not in content


def _write_synthetic_artifact(tmp_path: Path) -> Path:
    artifact = tmp_path / "artifact"
    functions = artifact / "functions"
    functions.mkdir(parents=True)
    (functions / "00401120_main.c").write_text(
        "/* fake decompiler output */\nint main(int argc, char **argv) { return argc == 2 ? 0 : 1; }\n",
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "1.0",
        "artifact_id": "hello-abc123-def456",
        "status": "ok",
        "input": {"path": "/input/hello", "sha256": "abc", "size_bytes": 1},
        "environment": {"decomp_mcp_version": "0.1.0", "ghidra_version": "12.0.4"},
        "options": {"profile": "default"},
        "paths": {"index": "index.json", "functions_dir": "functions"},
        "stats": {"functions_total": 1, "decompiled_ok": 1, "failed": 0, "skipped": 0},
    }
    index = {
        "schema_version": "1.0",
        "artifact_id": "hello-abc123-def456",
        "functions": [
            {
                "name": "main",
                "address": "0x00401120",
                "size": 64,
                "file": "functions/00401120_main.c",
                "status": "ok",
                "is_auto_named": False,
                "is_thunk": False,
                "is_external": False,
            }
        ],
    }
    (artifact / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (artifact / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return artifact

