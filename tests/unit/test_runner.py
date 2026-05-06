from __future__ import annotations

import json
from pathlib import Path

from decomp_mcp.ghidra_runner import GhidraRunner
from decomp_mcp.models import DecompileRequest


def test_runner_creates_artifact_and_cache_with_fake_analyzer(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"fake binary")
    fake_analyzer = _write_fake_analyzer(tmp_path)

    monkeypatch.setenv("GHIDRA_ANALYZE_HEADLESS", str(fake_analyzer))
    monkeypatch.setenv("DECOMP_MCP_GHIDRA_SCRIPT_DIR", str(Path.cwd() / "ghidra_scripts"))
    runner = GhidraRunner(base_input=input_root, base_output=output_root)

    first = runner.decompile(
        _request(
            binary_path="hello",
        )
    )
    second = runner.decompile(
        _request(
            binary_path="hello",
        )
    )

    artifact_dir = Path(first["artifact_dir"])
    assert first["status"] == "ok"
    assert first["cache_hit"] is False
    assert (artifact_dir / "manifest.json").exists()
    assert (artifact_dir / "index.json").exists()
    assert (artifact_dir / "index.jsonl").exists()
    assert (artifact_dir / "imports.json").exists()
    assert (artifact_dir / "exports.json").exists()
    assert (artifact_dir / "strings.json").exists()
    assert (artifact_dir / "sections.json").exists()
    assert (artifact_dir / "symbols.json").exists()
    assert (artifact_dir / "functions" / "00401120_main.c").exists()
    assert second["status"] == "cached"
    assert second["cache_hit"] is True


def test_runner_returns_failed_artifact_when_analyzer_missing(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    binary = input_root / "invalid"
    binary.write_bytes(b"invalid")

    monkeypatch.setenv("GHIDRA_ANALYZE_HEADLESS", str(tmp_path / "missing-analyzer"))
    monkeypatch.setenv("DECOMP_MCP_GHIDRA_SCRIPT_DIR", str(Path.cwd() / "ghidra_scripts"))
    runner = GhidraRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(_request(binary_path="invalid"))

    assert result["status"] == "failed"
    assert Path(result["manifest_path"]).exists()
    assert "analyzeHeadless not found" in result["warnings"][0]


def test_runner_maps_response_paths_to_host_output_root(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    host_output = tmp_path / "host-output"
    input_root.mkdir()
    output_root.mkdir()
    host_output.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"fake binary")
    fake_analyzer = _write_fake_analyzer(tmp_path)

    monkeypatch.setenv("GHIDRA_ANALYZE_HEADLESS", str(fake_analyzer))
    monkeypatch.setenv("DECOMP_MCP_GHIDRA_SCRIPT_DIR", str(Path.cwd() / "ghidra_scripts"))
    monkeypatch.setenv("DECOMP_MCP_HOST_OUTPUT_ROOT", str(host_output))
    runner = GhidraRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(_request(binary_path="hello"))

    assert result["artifact_dir"].startswith(str(host_output))
    assert result["manifest_path"].startswith(str(host_output))
    assert result["container_artifact_dir"].startswith(str(output_root))


def test_runner_uses_profile_default_timeouts(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"fake binary")
    capture_path = tmp_path / "capture.json"
    fake_analyzer = _write_fake_analyzer(tmp_path, capture_path)

    monkeypatch.setenv("GHIDRA_ANALYZE_HEADLESS", str(fake_analyzer))
    monkeypatch.setenv("DECOMP_MCP_GHIDRA_SCRIPT_DIR", str(Path.cwd() / "ghidra_scripts"))
    runner = GhidraRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(DecompileRequest(binary_path="hello", profile="fast"))
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    argv = capture["argv"]
    analysis_timeout_index = argv.index("-analysisTimeoutPerFile")
    manifest = json.loads(Path(result["manifest_path"]).read_text(encoding="utf-8"))

    assert argv[analysis_timeout_index + 1] == "300"
    assert capture["options"]["function_timeout_sec"] == 20
    assert manifest["options"]["total_timeout_sec"] == 300
    assert manifest["options"]["function_timeout_sec"] == 20


def _request(**overrides):
    base = {
        "binary_path": "/hello",
        "output_name": None,
        "force": False,
        "profile": "default",
        "include_autonamed": True,
        "filter_regex": None,
        "min_function_size": 0,
        "max_functions": None,
        "single_file": False,
        "total_timeout_sec": 30,
        "function_timeout_sec": 5,
    }
    base.update(overrides)
    return DecompileRequest(**base)


def _write_fake_analyzer(tmp_path: Path, capture_path: Path | None = None) -> Path:
    analyzer = tmp_path / "fake_analyze_headless.py"
    capture_literal = repr(str(capture_path)) if capture_path is not None else "None"
    analyzer.write_text(
        f"""#!/usr/bin/env python3
import json
import pathlib
import sys

post = sys.argv.index("-postScript")
artifact_dir = pathlib.Path(sys.argv[post + 2])
options_path = pathlib.Path(sys.argv[post + 3])
options = json.loads(options_path.read_text())
capture_path = {capture_literal}
if capture_path is not None:
    pathlib.Path(capture_path).write_text(json.dumps({{"argv": sys.argv, "options": options}}))
(artifact_dir / "functions").mkdir(parents=True, exist_ok=True)
(artifact_dir / "functions" / "00401120_main.c").write_text("/* fake */\\nint main(void) {{ return 0; }}\\n")
(artifact_dir / "index.json").write_text(json.dumps({{
    "schema_version": "1.0",
    "artifact_id": options["artifact_id"],
    "functions": [{{
        "name": "main",
        "address": "0x00401120",
        "size": 32,
        "file": "functions/00401120_main.c",
        "status": "ok",
        "is_auto_named": False,
        "is_thunk": False,
        "is_external": False
    }}]
}}))
(artifact_dir / "failures.json").write_text(json.dumps({{"artifact_id": options["artifact_id"], "failures": []}}))
""",
        encoding="utf-8",
    )
    analyzer.chmod(0o755)
    return analyzer
