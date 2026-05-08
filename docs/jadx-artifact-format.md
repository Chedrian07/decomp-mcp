# Jadx Artifact Format

Jadx artifacts share the same lifecycle and output root as Ghidra artifacts (`<active-output-root>/artifacts/<artifact_id>/`) but the contents differ because jadx produces Java sources at the class level rather than Ghidra-style per-function pseudocode.

## Layout

```
<active-output-root>/artifacts/<artifact_id>/
├── manifest.json          # engine: "jadx"
├── index.json             # classes array
├── index.jsonl            # one class record per line
├── failures.json          # best-effort, parsed from logs/jadx.log
├── sources/<pkg>/<Class>.java
├── resources.json         # only when include_resources=true
├── strings.json           # only when include_resources=true
├── combined/all.java      # only when single_file=true
└── logs/
    ├── runner.log
    └── jadx.log
```

## `manifest.json`

```json
{
  "schema_version": "1.0",
  "artifact_id": "...",
  "engine": "jadx",
  "status": "ok | partial | failed",
  "options_hash": "...",
  "input": { "path": "...", "sha256": "...", "size_bytes": 0 },
  "environment": { "decomp_mcp_version": "...", "jadx_version": "...", "java_version": "..." },
  "options": { "profile": "...", "deobf": true, "show_bad_code": false, "include_resources": false, "classes_filter": null, "max_classes": null, "single_file": false, "total_timeout_sec": 1800 },
  "paths": { "index": "index.json", "sources_dir": "sources", "failures": "failures.json", "logs_dir": "logs" },
  "stats": { "classes_total": 0, "decompiled_ok": 0, "failed": 0, "sources_bytes": 0, "duration_sec": 0.0 },
  "warnings": []
}
```

## `index.json`

```json
{
  "schema_version": "1.0",
  "artifact_id": "...",
  "engine": "jadx",
  "classes": [
    {
      "name": "MainActivity",
      "package": "com.example",
      "file": "sources/com/example/MainActivity.java",
      "size_bytes": 1234,
      "status": "ok",
      "is_inner": false,
      "is_anonymous": false,
      "error_summary": null
    }
  ]
}
```

`status` values: `ok`, `partial` (class loaded, some methods failed), `failed` (class not loaded at all).

`is_inner` is true when the source filename contains `$`. `is_anonymous` is true when the inner suffix is purely numeric.

## `failures.json`

Failures are parsed best-effort from `logs/jadx.log` using these regexes:

- `^ERROR\s*-\s*Class\s+(\S+)\s+was not loaded(?:,\s*(.+))?$` → class-level failure
- `^ERROR\s*-\s*Method\s+(\S+)\s+failed to be decompiled` → method-level failure (recorded under owning class)

Each entry: `{"class": str, "method": str | null, "kind": "class" | "method", "message": str}`.

Other `ERROR -` lines are surfaced as artifact-level `warnings` (capped at 10) rather than per-class failures.

## Determinism inputs (`options_hash`)

- `engine = "jadx"` (only present in jadx options payloads)
- `jadx_version`
- `decomp_mcp_version`
- `java_version`
- `profile`
- `deobf`, `show_bad_code`, `include_resources`, `classes_filter`, `max_classes`, `single_file`

The CLI is invoked with `--deobf-cfg-file-mode ignore` so an external `.jobf` mapping cannot influence the output. `--no-res` is added when `include_resources=false`.
