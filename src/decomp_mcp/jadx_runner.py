from __future__ import annotations

import os
import platform
import re
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
    finalize_artifact,
    make_tmp_artifact_dir,
)
from .hashing import artifact_id as make_artifact_id
from .hashing import canonical_json_hash, sha256_file
from .models import (
    JadxArtifactOptions,
    JadxArtifactStats,
    JadxRequest,
)
from .paths import artifacts_root, input_root, output_root, resolve_binary_path


SCHEMA_VERSION = "1.0"
DEFAULT_JADX_VERSION = "unknown"


def decompile_apk(**kwargs: Any) -> dict[str, Any]:
    request = JadxRequest(**kwargs)
    if _execution_mode() == "docker-worker":
        from .docker_worker import DockerWorkerRunner

        return DockerWorkerRunner().decompile_apk(request)
    return JadxRunner().decompile(request)


class JadxRunner:
    def __init__(self, base_input: Path | None = None, base_output: Path | None = None):
        self.base_input = base_input or input_root()
        self.base_output = base_output or output_root()
        self.artifacts_dir = artifacts_root(self.base_output)

    def decompile(self, request: JadxRequest) -> dict[str, Any]:
        started = time.monotonic()
        binary = resolve_binary_path(request.binary_path, self.base_input)
        binary_sha256 = sha256_file(binary)
        total_timeout_sec = request.effective_total_timeout_sec()
        jadx_bin = _jadx_bin_path()
        jadx_version = _detect_jadx_version(jadx_bin)
        java_version = os.environ.get("JAVA_VERSION", platform.java_ver()[0] or "unknown")

        artifact_options = JadxArtifactOptions(
            jadx_version=jadx_version,
            decomp_mcp_version=__version__,
            java_version=java_version,
            profile=request.profile,
            deobf=request.deobf,
            show_bad_code=request.show_bad_code,
            include_resources=request.include_resources,
            classes_filter=request.classes_filter,
            max_classes=request.max_classes,
            single_file=request.single_file,
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
                    started=started,
                    jadx_version=jadx_version,
                    java_version=java_version,
                    jadx_bin=jadx_bin,
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
                    jadx_version=jadx_version,
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
        request: JadxRequest,
        binary: Path,
        binary_sha256: str,
        artifact_id: str,
        tmp_dir: Path,
        artifact_options: JadxArtifactOptions,
        options_hash: str,
        total_timeout_sec: int,
        started: float,
        jadx_version: str,
        java_version: str,
        jadx_bin: Path,
    ) -> dict[str, Any]:
        self._prepare_artifact_dirs(tmp_dir)
        runner_log = tmp_dir / "logs" / "runner.log"
        jadx_log = tmp_dir / "logs" / "jadx.log"
        sources_dir = tmp_dir / "sources"
        resources_dir = tmp_dir / "resources"

        if not jadx_bin.exists():
            raise FileNotFoundError(f"jadx not found at {jadx_bin}")

        command = [
            str(jadx_bin),
            "--output-dir-src",
            str(sources_dir),
            "--output-dir-res",
            str(resources_dir),
            "--log-level",
            "error",
            "--deobf-cfg-file-mode",
            "ignore",
        ]
        if request.deobf:
            command.append("--deobf")
        if request.show_bad_code:
            command.append("--show-bad-code")
        if not request.include_resources:
            command.append("--no-res")
        command.append(str(binary))

        _append_log(runner_log, f"running: {' '.join(command)}\n")

        timeout_error = None
        completed = None
        with jadx_log.open("ab") as jadx_handle:
            try:
                completed = subprocess.run(
                    command,
                    stdout=jadx_handle,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=total_timeout_sec,
                )
            except subprocess.TimeoutExpired as exc:
                timeout_error = f"jadx timed out after {total_timeout_sec} seconds"
                _append_log(runner_log, f"{timeout_error}: {exc}\n")

        if timeout_error:
            warnings = [timeout_error]
            stats = JadxArtifactStats(duration_sec=round(time.monotonic() - started, 3))
            self._write_manifest_and_minimal_outputs(
                tmp_dir=tmp_dir,
                request=request,
                binary=binary,
                binary_sha256=binary_sha256,
                artifact_id=artifact_id,
                artifact_options=artifact_options,
                options_hash=options_hash,
                jadx_version=jadx_version,
                java_version=java_version,
                status="failed",
                stats=stats,
                warnings=warnings,
            )
            return {"status": "failed", "stats": stats.to_dict(), "warnings": warnings}

        if completed is None:
            raise RuntimeError("jadx did not return a subprocess result")

        warnings: list[str] = []
        if completed.returncode != 0:
            warnings.append(f"jadx exited with code {completed.returncode}; see logs/jadx.log")

        failures_by_class, generic_errors = _parse_jadx_log(jadx_log)
        warnings.extend(generic_errors[:10])

        classes = _enumerate_classes(
            sources_dir,
            failures_by_class=failures_by_class,
            classes_filter=request.classes_filter,
            max_classes=request.max_classes,
        )

        atomic_write_json(
            tmp_dir / "index.json",
            {
                "schema_version": SCHEMA_VERSION,
                "artifact_id": artifact_id,
                "engine": "jadx",
                "classes": classes,
            },
        )
        _write_index_jsonl(tmp_dir / "index.jsonl", classes)

        failures = [
            {"class": cls, "method": entry.get("method"), "kind": entry["kind"], "message": entry["message"]}
            for cls, entries in sorted(failures_by_class.items())
            for entry in entries
        ]
        atomic_write_json(
            tmp_dir / "failures.json",
            {"artifact_id": artifact_id, "failures": failures},
        )

        if request.single_file:
            self._write_combined(tmp_dir, classes)

        if request.include_resources:
            self._write_resource_outputs(tmp_dir, resources_dir, artifact_id)

        stats = _stats_from_classes(classes, started)
        if stats.failed:
            warnings.append(f"{stats.failed} classes failed to decompile; see failures.json")
        status = _status_from_stats(stats, completed.returncode)
        if status == "failed" and stats.classes_total == 0 and not warnings:
            warnings.append("jadx produced no .java sources")

        self._write_manifest(
            tmp_dir=tmp_dir,
            request=request,
            binary=binary,
            binary_sha256=binary_sha256,
            artifact_id=artifact_id,
            artifact_options=artifact_options,
            options_hash=options_hash,
            jadx_version=jadx_version,
            java_version=java_version,
            status=status,
            stats=stats,
            warnings=warnings,
        )
        return {"status": status, "stats": stats.to_dict(), "warnings": warnings}

    def _write_runner_failure(
        self,
        request: JadxRequest,
        binary: Path,
        binary_sha256: str,
        artifact_id: str,
        tmp_dir: Path,
        artifact_options: JadxArtifactOptions,
        options_hash: str,
        started: float,
        jadx_version: str,
        java_version: str,
        error: str,
    ) -> dict[str, Any]:
        self._prepare_artifact_dirs(tmp_dir)
        _append_log(tmp_dir / "logs" / "runner.log", f"runner failure: {error}\n")
        stats = JadxArtifactStats(duration_sec=round(time.monotonic() - started, 3))
        warnings = [error]
        self._write_manifest_and_minimal_outputs(
            tmp_dir=tmp_dir,
            request=request,
            binary=binary,
            binary_sha256=binary_sha256,
            artifact_id=artifact_id,
            artifact_options=artifact_options,
            options_hash=options_hash,
            jadx_version=jadx_version,
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
            atomic_write_json(
                index,
                {
                    "schema_version": SCHEMA_VERSION,
                    "artifact_id": artifact_id,
                    "engine": "jadx",
                    "classes": [],
                },
            )
        if not failures.exists():
            atomic_write_json(failures, {"artifact_id": artifact_id, "failures": []})
        index_jsonl = tmp_dir / "index.jsonl"
        if not index_jsonl.exists():
            index_jsonl.write_text("", encoding="utf-8")
        self._write_manifest(**kwargs)

    def _write_manifest(
        self,
        tmp_dir: Path,
        request: JadxRequest,
        binary: Path,
        binary_sha256: str,
        artifact_id: str,
        artifact_options: JadxArtifactOptions,
        options_hash: str,
        jadx_version: str,
        java_version: str,
        status: str,
        stats: JadxArtifactStats,
        warnings: list[str],
    ) -> None:
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "engine": "jadx",
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
                "jadx_version": jadx_version,
                "java_version": java_version,
            },
            "options": {
                "profile": request.profile,
                "deobf": request.deobf,
                "show_bad_code": request.show_bad_code,
                "include_resources": request.include_resources,
                "classes_filter": request.classes_filter,
                "max_classes": request.max_classes,
                "single_file": request.single_file,
                "total_timeout_sec": request.effective_total_timeout_sec(),
            },
            "paths": {
                "index": "index.json",
                "index_jsonl": "index.jsonl",
                "sources_dir": "sources",
                "failures": "failures.json",
                "logs_dir": "logs",
            },
            "stats": stats.to_dict(),
            "warnings": warnings,
        }
        if request.include_resources:
            manifest["paths"]["resources"] = "resources.json"
            manifest["paths"]["strings"] = "strings.json"
        atomic_write_json(tmp_dir / "manifest.json", manifest)

    def _prepare_artifact_dirs(self, tmp_dir: Path) -> None:
        (tmp_dir / "sources").mkdir(parents=True, exist_ok=True)
        (tmp_dir / "logs").mkdir(parents=True, exist_ok=True)

    def _write_combined(self, tmp_dir: Path, classes: list[dict[str, Any]]) -> None:
        combined_dir = tmp_dir / "combined"
        combined_dir.mkdir(parents=True, exist_ok=True)
        with (combined_dir / "all.java").open("w", encoding="utf-8") as out:
            for record in classes:
                file_rel = record.get("file")
                if not file_rel:
                    continue
                source_path = tmp_dir / file_rel
                if not source_path.exists():
                    continue
                out.write(f"// {record.get('package') or '(default)'}.{record['name']}\n")
                out.write(source_path.read_text(encoding="utf-8", errors="replace"))
                out.write("\n\n")

    def _write_resource_outputs(self, tmp_dir: Path, resources_dir: Path, artifact_id: str) -> None:
        resources_summary: list[dict[str, Any]] = []
        strings: list[dict[str, Any]] = []
        if resources_dir.exists():
            for path in sorted(resources_dir.rglob("*")):
                if not path.is_file():
                    continue
                resources_summary.append(
                    {
                        "file": str(path.relative_to(tmp_dir)),
                        "size_bytes": path.stat().st_size,
                    }
                )
        atomic_write_json(
            tmp_dir / "resources.json",
            {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "resources": resources_summary},
        )
        atomic_write_json(
            tmp_dir / "strings.json",
            {"schema_version": SCHEMA_VERSION, "artifact_id": artifact_id, "strings": strings},
        )

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
            "engine": "jadx",
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


_CLASS_NOT_LOADED_RE = re.compile(r"^ERROR\s*-\s*Class\s+(\S+)\s+was not loaded(?:,\s*(.+))?$")
_METHOD_FAILED_RE = re.compile(r"^ERROR\s*-\s*Method\s+(\S+)\s+failed to be decompiled(?:.*)$")
_GENERIC_ERROR_RE = re.compile(r"^ERROR\s*-\s*(.+)$")


def _parse_jadx_log(log_path: Path) -> tuple[dict[str, list[dict[str, str]]], list[str]]:
    failures: dict[str, list[dict[str, str]]] = {}
    generic: list[str] = []
    if not log_path.exists():
        return failures, generic
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return failures, generic

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = _CLASS_NOT_LOADED_RE.match(stripped)
        if match:
            cls = match.group(1)
            detail = match.group(2) or ""
            failures.setdefault(cls, []).append({"kind": "class", "message": detail.strip()})
            continue
        match = _METHOD_FAILED_RE.match(stripped)
        if match:
            qualified = match.group(1)
            cls, _, method = qualified.rpartition(".")
            failures.setdefault(cls or qualified, []).append(
                {"kind": "method", "method": method or qualified, "message": stripped}
            )
            continue
        match = _GENERIC_ERROR_RE.match(stripped)
        if match:
            generic.append(match.group(1).strip())
    return failures, generic


def _enumerate_classes(
    sources_dir: Path,
    failures_by_class: dict[str, list[dict[str, str]]],
    classes_filter: str | None,
    max_classes: int | None,
) -> list[dict[str, Any]]:
    pattern = re.compile(classes_filter) if classes_filter else None
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    java_files = sorted(sources_dir.rglob("*.java")) if sources_dir.exists() else []
    for java_path in java_files:
        rel = java_path.relative_to(sources_dir.parent)
        package_parts = java_path.parent.relative_to(sources_dir).parts
        package = ".".join(package_parts)
        stem = java_path.stem
        is_inner, is_anonymous = _class_name_flags(stem)
        qualified = f"{package}.{stem}" if package else stem
        if pattern is not None and not pattern.search(qualified):
            continue
        seen.add(qualified)
        cls_failures = failures_by_class.get(qualified) or failures_by_class.get(stem)
        status = "ok"
        error_summary: str | None = None
        if cls_failures:
            status, error_summary = _status_from_class_failures(cls_failures)

        records.append(
            {
                "name": stem,
                "package": package,
                "file": str(rel),
                "size_bytes": java_path.stat().st_size,
                "status": status,
                "is_inner": is_inner,
                "is_anonymous": is_anonymous,
                "error_summary": error_summary,
            }
        )
        if max_classes is not None and len(records) >= max_classes:
            break

    for qualified, cls_failures in sorted(failures_by_class.items()):
        if qualified in seen:
            continue
        if pattern is not None and not pattern.search(qualified):
            continue
        package, _, name = qualified.rpartition(".")
        if not name:
            name = qualified
            package = ""
        is_inner, is_anonymous = _class_name_flags(name)
        status, error_summary = _status_from_class_failures(cls_failures)
        records.append(
            {
                "name": name,
                "package": package,
                "file": None,
                "size_bytes": 0,
                "status": status,
                "is_inner": is_inner,
                "is_anonymous": is_anonymous,
                "error_summary": error_summary,
            }
        )
    return records


def _status_from_class_failures(cls_failures: list[dict[str, str]]) -> tuple[str, str]:
    for entry in cls_failures:
        if entry.get("kind") == "class":
            return "failed", entry.get("message") or "class not loaded"
    return "partial", "method decompilation errors"


def _class_name_flags(name: str) -> tuple[bool, bool]:
    is_inner = "$" in name
    is_anonymous = False
    if is_inner:
        inner_part = name.split("$", 1)[1]
        is_anonymous = inner_part.split("$", 1)[0].isdigit()
    return is_inner, is_anonymous


def _write_index_jsonl(path: Path, classes: list[dict[str, Any]]) -> None:
    import json

    lines = [json.dumps(record, sort_keys=False) for record in classes]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _stats_from_classes(classes: list[dict[str, Any]], started: float) -> JadxArtifactStats:
    ok = 0
    failed = 0
    sources_bytes = 0
    for record in classes:
        if record["status"] == "ok":
            ok += 1
        elif record["status"] in ("failed", "partial"):
            failed += 1
        sources_bytes += int(record.get("size_bytes") or 0)
    return JadxArtifactStats(
        classes_total=len(classes),
        decompiled_ok=ok,
        failed=failed,
        sources_bytes=sources_bytes,
        duration_sec=round(time.monotonic() - started, 3),
    )


def _status_from_stats(stats: JadxArtifactStats, returncode: int) -> str:
    if returncode != 0 and stats.classes_total == 0:
        return "failed"
    if stats.classes_total == 0:
        return "failed"
    if stats.failed > 0 or returncode != 0:
        return "partial"
    return "ok"


def _jadx_bin_path() -> Path:
    configured = os.environ.get("JADX_BIN")
    if configured:
        return Path(configured)
    jadx_home = os.environ.get("JADX_HOME")
    if jadx_home:
        return Path(jadx_home) / "bin" / "jadx"
    discovered = shutil.which("jadx")
    if discovered:
        return Path(discovered)
    return Path("/opt/jadx/bin/jadx")


def _detect_jadx_version(jadx_bin: Path) -> str:
    fallback = os.environ.get("JADX_VERSION", DEFAULT_JADX_VERSION)
    if not jadx_bin.exists():
        return fallback
    try:
        completed = subprocess.run(
            [str(jadx_bin), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return fallback
    text = (completed.stdout or completed.stderr).strip()
    if not text:
        return fallback
    return text.splitlines()[0].strip() or fallback


def _append_log(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)


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
