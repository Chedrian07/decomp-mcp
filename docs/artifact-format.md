# Artifact Format

Artifacts are written under the active output root:

- docker-worker mode: `<DECOMP_MCP_HOST_OUTPUT_ROOT>/artifacts/<artifact_id>`
- container-server mode: `/output/artifacts/<artifact_id>`
- local Ghidra mode: `<DECOMP_MCP_OUTPUT_ROOT>/artifacts/<artifact_id>`

Required files:

- `manifest.json`: stable top-level metadata and stats
- `index.json`: function list and per-function file paths
- `index.jsonl`: newline-delimited function records for streaming-friendly readers
- `failures.json`: failed decompilations
- `functions/*.c`: one C-like pseudocode file per successful function
- `imports.json`: external/imported symbols inferred from Ghidra symbols
- `exports.json`: primary non-external function/label symbols
- `strings.json`: defined string data values
- `sections.json`: memory blocks with permissions and size
- `symbols.json`: Ghidra symbol table summary
- `logs/runner.log`: Python runner log
- `logs/ghidra.log`: Ghidra stdout/stderr

`combined/all.c` exists only when `single_file=true`.

Metadata files are intentionally shallow. They help triage a binary without turning this project into a broad Ghidra analysis API.
