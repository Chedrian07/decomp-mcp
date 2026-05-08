from __future__ import annotations

import json
from pathlib import Path

from decomp_mcp.jadx_runner import JadxRunner
from decomp_mcp.models import JadxRequest


def test_jadx_runner_creates_artifact_and_caches(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    apk = input_root / "hello.apk"
    apk.write_bytes(b"PK\x03\x04 fake apk")
    fake_jadx = _write_fake_jadx(tmp_path)

    monkeypatch.setenv("JADX_BIN", str(fake_jadx))
    monkeypatch.setenv("JADX_VERSION", "1.5.4")
    runner = JadxRunner(base_input=input_root, base_output=output_root)

    first = runner.decompile(_request(binary_path="hello.apk"))
    second = runner.decompile(_request(binary_path="hello.apk"))

    artifact_dir = Path(first["artifact_dir"])
    assert first["status"] == "ok"
    assert first["cache_hit"] is False
    assert first["engine"] == "jadx"
    assert (artifact_dir / "manifest.json").exists()
    assert (artifact_dir / "index.json").exists()
    assert (artifact_dir / "index.jsonl").exists()
    assert (artifact_dir / "failures.json").exists()
    assert (artifact_dir / "sources" / "com" / "example" / "Hello.java").exists()

    manifest = json.loads((artifact_dir / "manifest.json").read_text())
    assert manifest["engine"] == "jadx"
    assert manifest["status"] == "ok"
    assert manifest["environment"]["jadx_version"] == "1.5.4"
    assert manifest["options"]["deobf"] is True

    index = json.loads((artifact_dir / "index.json").read_text())
    assert index["engine"] == "jadx"
    names = sorted(item["name"] for item in index["classes"])
    assert names == ["Hello", "World"]
    hello = next(item for item in index["classes"] if item["name"] == "Hello")
    assert hello["package"] == "com.example"
    assert hello["status"] == "ok"
    assert hello["is_inner"] is False

    assert second["status"] == "cached"
    assert second["cache_hit"] is True


def test_jadx_runner_returns_failed_when_jadx_missing(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    apk = input_root / "missing.apk"
    apk.write_bytes(b"PK")

    monkeypatch.setenv("JADX_BIN", str(tmp_path / "no-such-jadx"))
    runner = JadxRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(_request(binary_path="missing.apk"))

    assert result["status"] == "failed"
    assert "jadx not found" in result["warnings"][0]
    assert Path(result["manifest_path"]).exists()


def test_jadx_runner_records_failures_from_log(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    apk = input_root / "noisy.apk"
    apk.write_bytes(b"PK")
    fake_jadx = _write_fake_jadx(
        tmp_path,
        log_lines=[
            "ERROR - Class com.example.Hello was not loaded, NoClassDefFoundError",
            "ERROR - Method com.example.World.run failed to be decompiled with reason xyz",
        ],
    )

    monkeypatch.setenv("JADX_BIN", str(fake_jadx))
    runner = JadxRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(_request(binary_path="noisy.apk"))
    artifact_dir = Path(result["artifact_dir"])

    failures = json.loads((artifact_dir / "failures.json").read_text())
    classes = {entry["class"]: entry for entry in failures["failures"]}
    assert "com.example.Hello" in classes
    assert classes["com.example.Hello"]["kind"] == "class"
    assert "com.example.World" in classes
    assert classes["com.example.World"]["kind"] == "method"

    index = json.loads((artifact_dir / "index.json").read_text())
    statuses = {item["name"]: item["status"] for item in index["classes"]}
    assert statuses["Hello"] == "failed"
    assert statuses["World"] == "partial"
    assert result["status"] == "partial"


def test_jadx_runner_indexes_failed_class_without_source_file(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    input_root.mkdir()
    output_root.mkdir()
    apk = input_root / "missing-class.apk"
    apk.write_bytes(b"PK")
    fake_jadx = _write_fake_jadx(
        tmp_path,
        log_lines=[
            "ERROR - Class com.example.Missing was not loaded, DecodeException",
        ],
    )

    monkeypatch.setenv("JADX_BIN", str(fake_jadx))
    runner = JadxRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(_request(binary_path="missing-class.apk"))
    artifact_dir = Path(result["artifact_dir"])
    index = json.loads((artifact_dir / "index.json").read_text())
    missing = next(item for item in index["classes"] if item["name"] == "Missing")

    assert missing["package"] == "com.example"
    assert missing["file"] is None
    assert missing["status"] == "failed"
    assert result["status"] == "partial"
    assert result["stats"]["failed"] == 1


def test_jadx_runner_maps_response_to_host_output_root(tmp_path: Path, monkeypatch) -> None:
    input_root = tmp_path / "input"
    output_root = tmp_path / "output"
    host_output = tmp_path / "host-output"
    input_root.mkdir()
    output_root.mkdir()
    host_output.mkdir()
    apk = input_root / "hello.apk"
    apk.write_bytes(b"PK")
    fake_jadx = _write_fake_jadx(tmp_path)

    monkeypatch.setenv("JADX_BIN", str(fake_jadx))
    monkeypatch.setenv("DECOMP_MCP_HOST_OUTPUT_ROOT", str(host_output))
    runner = JadxRunner(base_input=input_root, base_output=output_root)

    result = runner.decompile(_request(binary_path="hello.apk"))

    assert result["artifact_dir"].startswith(str(host_output))
    assert result["manifest_path"].startswith(str(host_output))
    assert result["container_artifact_dir"].startswith(str(output_root))


def _request(**overrides):
    base = {
        "binary_path": "hello.apk",
        "output_name": None,
        "force": False,
        "profile": "default",
        "deobf": True,
        "show_bad_code": False,
        "include_resources": False,
        "classes_filter": None,
        "max_classes": None,
        "single_file": False,
        "total_timeout_sec": 30,
    }
    base.update(overrides)
    return JadxRequest(**base)


def _write_fake_jadx(tmp_path: Path, log_lines: list[str] | None = None) -> Path:
    log_repr = repr(log_lines or [])
    script = tmp_path / "fake_jadx.py"
    script.write_text(
        f"""#!/usr/bin/env python3
import pathlib
import sys

argv = sys.argv[1:]

if "--version" in argv:
    print("1.5.4")
    raise SystemExit(0)


def get_value(flag):
    if flag in argv:
        return argv[argv.index(flag) + 1]
    return None


sources_dir = pathlib.Path(get_value("--output-dir-src"))
sources_dir.mkdir(parents=True, exist_ok=True)
pkg = sources_dir / "com" / "example"
pkg.mkdir(parents=True, exist_ok=True)
(pkg / "Hello.java").write_text("package com.example;\\nclass Hello {{}}\\n", encoding="utf-8")
(pkg / "World.java").write_text("package com.example;\\nclass World {{}}\\n", encoding="utf-8")

for line in {log_repr}:
    print(line)
""",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script
