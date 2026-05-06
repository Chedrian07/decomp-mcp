from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .paths import sanitize_name


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json_hash(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256_text(encoded)


def artifact_id(binary_stem: str, binary_sha256: str, options_hash: str) -> str:
    safe_stem = sanitize_name(binary_stem, default="binary", max_len=64)
    return f"{safe_stem}-{binary_sha256[:12]}-{options_hash[:8]}"

