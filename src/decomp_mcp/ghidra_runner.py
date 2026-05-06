from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from . import __version__
from .cache import (
    ArtifactLock,
    atomic_write_json,
    check_cache,
    clear_artifacts,
    finalize_artifact,
    make_tmp_artifact_dir,
    read_json,
)
from .hashing import artifact_id as make_artifact_id
from .hashing import canonical_json_hash, sha256_file
from .models import (
    ArtifactOptions,
    ArtifactStats,
    DecompileRequest,
)
from .paths import artifacts_root, ghidra_script_dir, input_root, output_root, resolve_binary_path


SCHEMA_VERSION = "1.0"
DEFAULT_GHIDRA_VERSION = "12.0.4"


def decompile_binary(**kwargs: Any) -> dict[str, Any]:
    request = DecompileRequest(**kwargs)
    if _execution_mode() == "docker-worker":
        from .docker_worker import DockerWorkerRunner

        return DockerWorkerRunner().decompile(request)
    return GhidraRunner().decompile(request)


def clear_cache(target: str = "failed", older_than_days: int | None = None) -> dict[str, object]:
    if _execution_mode() == "docker-worker":
        from .docker_worker import host_output_root

        return clear_artifacts(artifacts_root(host_output_root()), target=target, older_than_days=older_than_days)
    return clear_artifacts(artifacts_root(), target=target, older_than_days=older_than_days)


class GhidraRunner:
    def __init__(self, base_input: Path | None = None, base_output: Path | None = None):
        self.base_input = base_input or input_root()
        self.base_output = base_output or output_root()
        self.artifacts_dir = artifacts_root(self.base_output)

    def decompile(self, request: DecompileRequest) -> dict[str, Any]:
        started = time.monotonic()
        binary = resolve_binary_path(request.binary_path, self.base_input)
        binary_sha256 = sha256_file(binary)
        total_timeout_sec = request.effective_total_timeout_sec()
        function_timeout_sec = request.effective_function_timeout_sec()
        script_path = ghidra_script_dir() / "DecompileArtifacts.java"
        script_sha256 = sha256_file(script_path) if script_path.exists() else "missing"
        ghidra_version = os.environ.get("GHIDRA_VERSION", DEFAULT_GHIDRA_VERSION)
        java_version = os.environ.get("JAVA_VERSION", platform.java_ver()[0] or "unknown")

        artifact_options = ArtifactOptions(
            ghidra_version=ghidra_version,
            decomp_mcp_version=__version__,
            script_sha256=script_sha256,
            profile=request.profile,
            include_autonamed=request.include_autonamed,
            filter_regex=request.filter_regex,
            min_function_size=request.min_function_size,
            max_functions=request.max_functions,
            single_file=request.single_file,
            function_timeout_sec=function_timeout_sec,
        )
        options_hash = canonical_json_hash(artifact_options.to_hash_payload())
        display_name = request.output_name or binary.stem
        artifact_id = make_artifact_id(display_name, binary_sha256, options_hash)
        final_dir = self.artifacts_dir / artifact_id

        with ArtifactLock(self.artifacts_dir, artifact_id):
            if not request.force:
                cached_manifest = check_cache(final_dir, binary_sha256, options_hash)
                if cached_manifest is not None:
                    return self._response(
                        status="cached",
                        artifact_id=artifact_id,
                        artifact_dir=final_dir,
                        binary_sha256=binary_sha256,
                        cache_hit=True,
                        stats=cached_manifest.get("stats", {}),
                        warnings=[],
                    )

            tmp_dir = make_tmp_artifact_dir(self.artifacts_dir, artifact_id)
            try:
                result = self._run_into_tmp(
                    request=request,
                    binary=binary,
                    binary_sha256=binary_sha256,
                    artifact_id=artifact_id,
                    tmp_dir=tmp_dir,
                    artifact_options=artifact_options,
                    options_hash=options_hash,
                    total_timeout_sec=total_timeout_sec,
                    function_timeout_sec=function_timeout_sec,
                    started=started,
                    ghidra_version=ghidra_version,
                    java_version=java_version,
                    script_path=script_path,
                )
                finalize_artifact(tmp_dir, final_dir, force=True)
                return self._response(
                    status=result["status"],
                    artifact_id=artifact_id,
                    artifact_dir=final_dir,
                    binary_sha256=binary_sha256,
                    cache_hit=False,
                    stats=result["stats"],
                    warnings=result["warnings"],
                )
            except Exception as exc:
                failure = self._write_runner_failure(
                    request=request,
                    binary=binary,
                    binary_sha256=binary_sha256,
                    artifact_id=artifact_id,
                    tmp_dir=tmp_dir,
                    artifact_options=artifact_options,
                    options_hash=options_hash,
                    started=started,
                    ghidra_version=ghidra_version,
                    java_version=java_version,
                    error=str(exc),
                )
                finalize_artifact(tmp_dir, final_dir, force=True)
                return self._response(
                    status="failed",
                    artifact_id=artifact_id,
                    artifact_dir=final_dir,
                    binary_sha256=binary_sha256,
                    cache_hit=False,
                    stats=failure["stats"],
                    warnings=failure["warnings"],
                )

    def _run_into_tmp(
        self,
        request: DecompileRequest,
        binary: Path,
        binary_sha256: str,
        artifact_id: str,
        tmp_dir: Path,
        artifact_options: ArtifactOptions,
        options_hash: str,
        total_timeout_sec: int,
        function_timeout_sec: int,
        started: float,
        ghidra_version: str,
        java_version: str,
        script_path: Path,
    ) -> dict[str, Any]:
        self._prepare_artifact_dirs(tmp_dir)
        runner_log = tmp_dir / "logs" / "runner.log"
        ghidra_log = tmp_dir / "logs" / "ghidra.log"
        script_options_path = tmp_dir / "options.json"
        atomic_write_json(
            script_options_path,
            {
                "artifact_id": artifact_id,
                "binary_sha256": binary_sha256,
                "ghidra_version": ghidra_version,
                "include_autonamed": request.include_autonamed,
                "filter_regex": request.filter_regex,
                "min_function_size": request.min_function_size,
                "max_functions": request.max_functions,
                "single_file": request.single_file,
                "function_timeout_sec": function_timeout_sec,
            },
        )

        analyze_headless = _analyze_headless_path()
        if not analyze_headless.exists():
            raise FileNotFoundError(f"analyzeHeadless not found at {analyze_headless}")
        if not script_path.exists():
            raise FileNotFoundError(f"Ghidra script not found at {script_path}")

        analysis_timeout = total_timeout_sec
        project_root = Path(os.environ.get("DECOMP_MCP_GHIDRA_PROJECT_ROOT", "/tmp/ghidra-projects"))
        project_root.mkdir(parents=True, exist_ok=True)
        project_name = artifact_id[:80]

        command = [
            str(analyze_headless),
            str(project_root),
            project_name,
            "-import",
            str(binary),
            "-scriptPath",
            str(script_path.parent),
            "-postScript",
            "DecompileArtifacts.java",
            str(tmp_dir),
            str(script_options_path),
            "-analysisTimeoutPerFile",
            str(analysis_timeout),
            "-deleteProject",
        ]
        _append_log(runner_log, f"running: {_redacted_command(command)}\n")

        timeout_error = None
        completed = None
        with ghidra_log.open("ab") as ghidra_handle:
            try:
                completed = subprocess.run(
                    command,
                    stdout=ghidra_handle,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=total_timeout_sec,
                )
            except subprocess.TimeoutExpired as exc:
                timeout_error = f"Ghidra timed out after {total_timeout_sec} seconds"
                _append_log(runner_log, f"{timeout_error}: {exc}\n")

        if timeout_error:
            warnings = [timeout_error]
            stats = ArtifactStats(duration_sec=round(time.monotonic() - started, 3))
            self._write_manifest_and_minimal_outputs(
                tmp_dir=tmp_dir,
                request=request,
                binary=binary,
                binary_sha256=binary_sha256,
                artifact_id=artifact_id,
                artifact_options=artifact_options,
                options_hash=options_hash,
                ghidra_version=ghidra_version,
                java_version=java_version,
                status="failed",
                stats=stats,
                warnings=warnings,
            )
            return {"status": "failed", "stats": stats.to_dict(), "warnings": warnings}

        if completed is None:
            raise RuntimeError("Ghidra did not return a subprocess result")

        index_path = tmp_dir / "index.json"
        failures_path = tmp_dir / "failures.json"
        warnings: list[str] = []
        if completed.returncode != 0:
            warnings.append(f"Ghidra exited with code {completed.returncode}; see logs/ghidra.log")

        if not index_path.exists():
            warnings.append("Ghidra did not produce index.json")
            atomic_write_json(index_path, {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "functions": []})
        if not failures_path.exists():
            atomic_write_json(failures_path, {"artifact_id": artifact_id, "failures": []})
        self._write_empty_metadata_outputs(tmp_dir, artifact_id)

        stats = _stats_from_artifact(tmp_dir, duration_sec=round(time.monotonic() - started, 3))
        status = _status_from_stats(stats, completed.returncode, warnings)
        if stats.failed:
            warnings.append(f"{stats.failed} functions failed to decompile; see failures.json")

        self._write_manifest(
            tmp_dir=tmp_dir,
            request=request,
            binary=binary,
            binary_sha256=binary_sha256,
            artifact_id=artifact_id,
            artifact_options=artifact_options,
            options_hash=options_hash,
            ghidra_version=ghidra_version,
            java_version=java_version,
            status=status,
            stats=stats,
            warnings=warnings,
        )
        return {"status": status, "stats": stats.to_dict(), "warnings": warnings}

    def _write_runner_failure(
        self,
        request: DecompileRequest,
        binary: Path,
        binary_sha256: str,
        artifact_id: str,
        tmp_dir: Path,
        artifact_options: ArtifactOptions,
        options_hash: str,
        started: float,
        ghidra_version: str,
        java_version: str,
        error: str,
    ) -> dict[str, Any]:
        self._prepare_artifact_dirs(tmp_dir)
        _append_log(tmp_dir / "logs" / "runner.log", f"runner failure: {error}\n")
        stats = ArtifactStats(duration_sec=round(time.monotonic() - started, 3))
        warnings = [error]
        self._write_manifest_and_minimal_outputs(
            tmp_dir=tmp_dir,
            request=request,
            binary=binary,
            binary_sha256=binary_sha256,
            artifact_id=artifact_id,
            artifact_options=artifact_options,
            options_hash=options_hash,
            ghidra_version=ghidra_version,
            java_version=java_version,
            status="failed",
            stats=stats,
            warnings=warnings,
        )
        return {"stats": stats.to_dict(), "warnings": warnings}

    def _write_manifest_and_minimal_outputs(self, **kwargs: Any) -> None:
        tmp_dir: Path = kwargs["tmp_dir"]
        artifact_id: str = kwargs["artifact_id"]
        index = tmp_dir / "index.json"
        failures = tmp_dir / "failures.json"
        if not index.exists():
            atomic_write_json(index, {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "functions": []})
        if not failures.exists():
            atomic_write_json(failures, {"artifact_id": artifact_id, "failures": []})
        self._write_empty_metadata_outputs(tmp_dir, artifact_id)
        self._write_manifest(**kwargs)

    def _write_manifest(
        self,
        tmp_dir: Path,
        request: DecompileRequest,
        binary: Path,
        binary_sha256: str,
        artifact_id: str,
        artifact_options: ArtifactOptions,
        options_hash: str,
        ghidra_version: str,
        java_version: str,
        status: str,
        stats: ArtifactStats,
        warnings: list[str],
    ) -> None:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "status": status,
            "created_at": _utc_now(),
            "options_hash": options_hash,
            "input": {
                "path": str(binary),
                "sha256": binary_sha256,
                "size_bytes": binary.stat().st_size,
            },
            "environment": {
                "decomp_mcp_version": __version__,
                "ghidra_version": ghidra_version,
                "java_version": java_version,
                "script_sha256": artifact_options.script_sha256,
            },
            "options": {
                "profile": request.profile,
                "include_autonamed": request.include_autonamed,
                "filter_regex": request.filter_regex,
                "min_function_size": request.min_function_size,
                "max_functions": request.max_functions,
                "single_file": request.single_file,
                "total_timeout_sec": request.effective_total_timeout_sec(),
                "function_timeout_sec": request.effective_function_timeout_sec(),
            },
            "paths": {
                "index": "index.json",
                "index_jsonl": "index.jsonl",
                "functions_dir": "functions",
                "failures": "failures.json",
                "imports": "imports.json",
                "exports": "exports.json",
                "strings": "strings.json",
                "sections": "sections.json",
                "symbols": "symbols.json",
                "logs_dir": "logs",
            },
            "stats": stats.to_dict(),
            "warnings": warnings,
        }
        atomic_write_json(tmp_dir / "manifest.json", manifest)

    def _prepare_artifact_dirs(self, tmp_dir: Path) -> None:
        (tmp_dir / "functions").mkdir(parents=True, exist_ok=True)
        (tmp_dir / "combined").mkdir(parents=True, exist_ok=True)
        (tmp_dir / "logs").mkdir(parents=True, exist_ok=True)

    def _write_empty_metadata_outputs(self, tmp_dir: Path, artifact_id: str) -> None:
        empty_files = {
            "index.jsonl": "",
            "imports.json": {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "imports": []},
            "exports.json": {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "exports": []},
            "strings.json": {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "strings": []},
            "sections.json": {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "sections": []},
            "symbols.json": {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "symbols": []},
        }
        for name, payload in empty_files.items():
            path = tmp_dir / name
            if path.exists():
                continue
            if isinstance(payload, str):
                path.write_text(payload, encoding="utf-8")
            else:
                atomic_write_json(path, payload)

    def _response(
        self,
        status: str,
        artifact_id: str,
        artifact_dir: Path,
        binary_sha256: str,
        cache_hit: bool,
        stats: dict[str, Any],
        warnings: list[str],
    ) -> dict[str, Any]:
        response_artifact_dir = _host_mapped_path(artifact_dir, self.base_output)
        return {
            "status": status,
            "artifact_id": artifact_id,
            "artifact_dir": str(response_artifact_dir),
            "manifest_path": str(response_artifact_dir / "manifest.json"),
            "index_path": str(response_artifact_dir / "index.json"),
            "container_artifact_dir": str(artifact_dir),
            "container_manifest_path": str(artifact_dir / "manifest.json"),
            "container_index_path": str(artifact_dir / "index.json"),
            "binary_sha256": binary_sha256,
            "cache_hit": cache_hit,
            "stats": stats,
            "warnings": warnings,
        }


def _analyze_headless_path() -> Path:
    configured = os.environ.get("GHIDRA_ANALYZE_HEADLESS")
    if configured:
        return Path(configured)
    ghidra_home = Path(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
    return ghidra_home / "support" / "analyzeHeadless"


def _stats_from_artifact(artifact_dir: Path, duration_sec: float) -> ArtifactStats:
    index_path = artifact_dir / "index.json"
    try:
        index = read_json(index_path)
    except (OSError, json.JSONDecodeError):
        return ArtifactStats(duration_sec=duration_sec)

    functions = index.get("functions", [])
    ok = 0
    failed = 0
    skipped = 0
    for function in functions:
        status = function.get("status")
        if status == "ok":
            ok += 1
        elif status == "failed":
            failed += 1
        elif isinstance(status, str) and status.startswith("skipped"):
            skipped += 1
    return ArtifactStats(
        functions_total=len(functions),
        decompiled_ok=ok,
        failed=failed,
        skipped=skipped,
        imports_total=_count_json_array(artifact_dir / "imports.json", "imports"),
        exports_total=_count_json_array(artifact_dir / "exports.json", "exports"),
        strings_total=_count_json_array(artifact_dir / "strings.json", "strings"),
        sections_total=_count_json_array(artifact_dir / "sections.json", "sections"),
        symbols_total=_count_json_array(artifact_dir / "symbols.json", "symbols"),
        duration_sec=duration_sec,
    )


def _count_json_array(path: Path, key: str) -> int:
    try:
        value = read_json(path).get(key, [])
    except (OSError, json.JSONDecodeError):
        return 0
    return len(value) if isinstance(value, list) else 0


def _status_from_stats(stats: ArtifactStats, returncode: int, warnings: list[str]) -> str:
    if returncode != 0:
        return "failed"
    if stats.failed > 0:
        return "partial"
    if any("did not produce index.json" in warning for warning in warnings):
        return "failed"
    return "ok"


def _append_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


def _redacted_command(command: list[str]) -> str:
    return " ".join(command)


def _host_mapped_path(path: Path, container_output_root: Path) -> Path:
    host_root = os.environ.get("DECOMP_MCP_HOST_OUTPUT_ROOT")
    if not host_root:
        return path
    try:
        relative = path.resolve().relative_to(container_output_root.resolve())
    except ValueError:
        return path
    return Path(host_root) / relative


def _execution_mode() -> str:
    return os.environ.get("DECOMP_MCP_EXECUTION_MODE", "docker-worker").strip().lower()


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
