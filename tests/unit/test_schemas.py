from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate


def test_metadata_schema_accepts_each_metadata_file_shape() -> None:
    schema = json.loads(Path("schemas/metadata.schema.json").read_text(encoding="utf-8"))
    for key in ("imports", "exports", "strings", "sections", "symbols"):
        validate({"schema_version": "1.0", "artifact_id": "sample", key: []}, schema)


def test_manifest_schema_accepts_current_stats_shape() -> None:
    schema = json.loads(Path("schemas/manifest.schema.json").read_text(encoding="utf-8"))
    validate(
        {
            "schema_version": "1.0",
            "artifact_id": "sample",
            "status": "ok",
            "created_at": "2026-05-05T00:00:00Z",
            "options_hash": "abc",
            "input": {"path": "/input/hello", "sha256": "abc", "size_bytes": 1},
            "environment": {},
            "options": {},
            "paths": {"index": "index.json", "sections": "sections.json"},
            "stats": {
                "functions_total": 1,
                "decompiled_ok": 1,
                "failed": 0,
                "skipped": 0,
                "imports_total": 0,
                "exports_total": 2,
                "strings_total": 0,
                "sections_total": 1,
                "symbols_total": 4,
                "duration_sec": 1.2,
            },
        },
        schema,
    )

