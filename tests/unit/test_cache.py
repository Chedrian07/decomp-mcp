from __future__ import annotations

from pathlib import Path

from decomp_mcp.cache import atomic_write_json, check_cache, clear_artifacts, finalize_artifact, make_tmp_artifact_dir
from decomp_mcp.paths import ensure_artifact_dirs


def test_check_cache_requires_manifest_index_status_and_hashes(tmp_path: Path) -> None:
    artifact = tmp_path / "artifacts" / "sample"
    artifact.mkdir(parents=True)
    atomic_write_json(
        artifact / "manifest.json",
        {
            "status": "ok",
            "input": {"sha256": "abc"},
            "options_hash": "def",
            "stats": {"functions_total": 1},
        },
    )
    atomic_write_json(artifact / "index.json", {"functions": []})

    assert check_cache(artifact, "abc", "def") is not None
    assert check_cache(artifact, "xxx", "def") is None
    assert check_cache(artifact, "abc", "xxx") is None


def test_tmp_finalize_and_clear_failed(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    ensure_artifact_dirs(artifacts)
    tmp = make_tmp_artifact_dir(artifacts, "failed-one")
    atomic_write_json(tmp / "manifest.json", {"status": "failed"})
    final = artifacts / "failed-one"
    finalize_artifact(tmp, final, force=True)

    result = clear_artifacts(artifacts, target="failed")

    assert result["removed"] == 1
    assert not final.exists()

