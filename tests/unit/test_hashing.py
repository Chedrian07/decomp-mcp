from __future__ import annotations

from pathlib import Path

from decomp_mcp.hashing import artifact_id, canonical_json_hash, sha256_file


def test_sha256_file(tmp_path: Path) -> None:
    path = tmp_path / "value.bin"
    path.write_bytes(b"abc")

    assert sha256_file(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_canonical_json_hash_is_order_independent() -> None:
    left = canonical_json_hash({"b": 2, "a": 1})
    right = canonical_json_hash({"a": 1, "b": 2})

    assert left == right


def test_artifact_id_uses_safe_stem_and_hash_prefixes() -> None:
    result = artifact_id("bad name", "a" * 64, "b" * 64)

    assert result == "bad_name-aaaaaaaaaaaa-bbbbbbbb"

