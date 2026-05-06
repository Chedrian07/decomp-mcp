from __future__ import annotations

from pathlib import Path

import pytest

from decomp_mcp.paths import resolve_binary_path, sanitize_name


def test_resolve_binary_path_allows_file_under_input(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    binary = input_root / "hello"
    binary.write_bytes(b"hello")

    assert resolve_binary_path(str(binary), input_root) == binary.resolve()
    assert resolve_binary_path("hello", input_root) == binary.resolve()


def test_resolve_binary_path_blocks_symlink_escape(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    outside = tmp_path / "outside"
    input_root.mkdir()
    outside.write_bytes(b"outside")
    (input_root / "escape").symlink_to(outside)

    with pytest.raises(ValueError, match="under"):
        resolve_binary_path("escape", input_root)


def test_resolve_binary_path_rejects_directories(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "dir").mkdir()

    with pytest.raises(ValueError, match="regular file"):
        resolve_binary_path("dir", input_root)


def test_sanitize_name_keeps_safe_subset() -> None:
    assert sanitize_name("../bad name!!", default="x") == "bad_name"
    assert sanitize_name("...", default="x") == "x"
    assert sanitize_name("a" * 100, max_len=8) == "a" * 8
