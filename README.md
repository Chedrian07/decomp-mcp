# decomp-mcp

`decomp-mcp` is a file-first MCP server for headless decompilation. It supports two engines bundled in the same Docker image:

- **Ghidra** for native binaries (ELF, Mach-O, PE) — exposed via `decompile_binary`
- **jadx** for Android/Java inputs (APK, DEX, JAR, AAR, AAB, CLASS) — exposed via `decompile_apk`

Both tools accept a single input path, run the engine inside the worker, and write reproducible decompilation artifacts under an output directory.

The MCP response never includes decompiled source bodies. It returns artifact paths, cache state, stats, and warnings so a coding agent can read only the files it needs.

## Recommended Deployment

For Claude Code, OpenCode, Codex, and similar coding agents, run `decomp-mcp` as a local host MCP server and let it start a hardened Docker worker for each decompile job.

```text
Coding agent
  -> host decomp-mcp MCP server
    -> docker run decomp-mcp:0.1.0 worker
      -> Ghidra headless
      -> host artifact output directory
```

This keeps the product as one MCP server while still avoiding a host Ghidra/JDK install.

## Build Worker Image

```bash
docker build --platform linux/amd64 -t decomp-mcp:0.1.0 .
```

Build and run the image as `linux/amd64` because the pinned Ghidra release ships the headless decompiler native executable for Linux x86_64. The same image bundles jadx so both `decompile_binary` and `decompile_apk` work without a second image.

The `JADX_ZIP_SHA256` build arg is a placeholder by default. Compute it once for the pinned `JADX_VERSION` (`curl -L https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip | sha256sum`) and pass it via `--build-arg JADX_ZIP_SHA256=...` or replace the default in the Dockerfile.

## Client MCP Configuration

For Claude Code, OpenCode, Codex, and other coding-agent clients with native file reading, use only the `decomp` MCP server. The client reads returned `manifest_path`, `index_path`, and selected `functions/*.c` files with its own file tools.

The coding-agent example intentionally avoids `DECOMP_MCP_ALLOWED_INPUT_ROOTS` and `DECOMP_MCP_HOST_OUTPUT_ROOT`. With no explicit roots, `decomp-mcp` uses the MCP server's launch cwd as the allowed input root and writes artifacts to `./decompiled`. The `uv run --project` form keeps that cwd as the client workspace while still running this project.

```json
{
  "mcpServers": {
    "decomp": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "/Users/me/decomp-mcp",
        "decomp-mcp"
      ]
    }
  }
}
```

The same config is available as `.mcp.json.example`.

Codex can also read MCP servers from `~/.codex/config.toml`; see `.codex.config.toml.example`. That example sets a longer `tool_timeout_sec` because Ghidra decompilation can run longer than Codex's default MCP tool timeout.

For Claude Desktop and chat clients that cannot read returned local paths by themselves, use `.mcp.claude-desktop.json.example`. It starts both:

- `decomp`: runs Ghidra and returns artifact paths
- `filesystem`: lets the client read the returned artifact files under `DECOMP_MCP_HOST_OUTPUT_ROOT`

Then call:

```json
{
  "binary_path": "/Users/me/rev/chal"
}
```

The server validates that `binary_path` resolves under one of `DECOMP_MCP_ALLOWED_INPUT_ROOTS`, mounts that binary's parent directory read-only into the Docker worker as `/input`, mounts `DECOMP_MCP_HOST_OUTPUT_ROOT` as `/output`, and returns host-visible artifact paths.

If `DECOMP_MCP_ALLOWED_INPUT_ROOTS` is unset, the allowed root is the MCP server's cwd. If `DECOMP_MCP_HOST_OUTPUT_ROOT` is unset, output goes to `./decompiled`.

Useful docker-worker environment variables:

- `DECOMP_MCP_DOCKER_IMAGE`: worker image, default `decomp-mcp:0.1.0`
- `DECOMP_MCP_DOCKER_PLATFORM`: default `linux/amd64`
- `DECOMP_MCP_ALLOWED_INPUT_ROOTS`: comma-separated host input roots
- `DECOMP_MCP_HOST_OUTPUT_ROOT`: host artifact output root
- `DECOMP_MCP_DOCKER_MEMORY`: default `8g`
- `DECOMP_MCP_DOCKER_CPUS`: default `4`
- `DECOMP_MCP_DOCKER_PIDS_LIMIT`: default `512`

## Container Server Mode

You can still run the MCP server inside Docker directly. This is useful for clients that prefer pre-mounted `/input` and `/output` roots.

```bash
docker run -i --rm \
  --platform linux/amd64 \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 512 \
  --memory 8g \
  --cpus 4 \
  -e DECOMP_MCP_EXECUTION_MODE=direct \
  -v "$(pwd)/binaries:/input:ro" \
  -v "$(pwd)/decompiled:/output:rw" \
  decomp-mcp:0.1.0
```

In this mode, call `decompile_binary` with a container path such as `/input/hello`.

## Local Ghidra Mode

For development, you can run without Docker if Ghidra and JDK are installed locally.

Required packages:

- Python 3.11+
- `uv`
- JDK 21 64-bit
- Ghidra 12.x, currently pinned to 12.0.4 for artifact determinism

Example:

```bash
export DECOMP_MCP_EXECUTION_MODE=direct
export DECOMP_MCP_INPUT_ROOT="$HOME/rev"
export DECOMP_MCP_OUTPUT_ROOT="$HOME/decompiled"
export GHIDRA_HOME="$HOME/tools/ghidra_12.0.4_PUBLIC"
export GHIDRA_VERSION="12.0.4"
uv run decomp-mcp
```

## Artifact Output

Each artifact contains:

- `manifest.json`: stable metadata, options, paths, and stats
- `index.json`: function list without pseudocode bodies
- `index.jsonl`: one compact function record per line
- `failures.json`: failed function decompilations
- `functions/*.c`: per-function Ghidra pseudocode
- `imports.json`, `exports.json`, `strings.json`, `sections.json`, `symbols.json`: lightweight static metadata
- `logs/runner.log`, `logs/ghidra.log`: execution logs

## Tools

### `decompile_binary`

Runs Ghidra on a native binary (ELF/Mach-O/PE) and creates or reuses a decompilation artifact.

Important parameters:

- `binary_path`: host path in `docker-worker` mode, `/input/...` path in container-server mode
- `force`: regenerate an existing artifact
- `profile`: `fast`, `default`, or `deep`; supplies timeout defaults when explicit timeout values are omitted
- `single_file`: also write `combined/all.c`
- `total_timeout_sec`: overall Ghidra subprocess timeout; defaults by profile
- `function_timeout_sec`: per-function decompiler timeout; defaults by profile

### `decompile_apk`

Runs jadx on Android/Java inputs (APK/DEX/JAR/AAR/AAB/CLASS) and creates or reuses a decompilation artifact. Sources land under `sources/<pkg>/<Class>.java`.

Important parameters:

- `apk_path`: host path in `docker-worker` mode, `/input/...` path in container-server mode
- `force`: regenerate an existing artifact
- `profile`: `fast`, `default`, or `deep`; supplies the total timeout when `total_timeout_sec` is omitted (jadx defaults are larger than Ghidra's: 600/1800/5400)
- `deobf`: enable jadx `--deobf` (default true). The CLI is always run with `--deobf-cfg-file-mode ignore` so any external `.jobf` mapping is ignored, keeping the cache key stable
- `show_bad_code`: jadx `--show-bad-code`
- `include_resources`: when false (default), runs with `--no-res`. When true, also writes `resources.json` and `strings.json`
- `classes_filter`: regex applied to `package.ClassName`
- `max_classes`: cap the number of indexed classes
- `single_file`: also write `combined/all.java`

The response shape is identical to `decompile_binary` (`status`, `artifact_id`, `artifact_dir`, `manifest_path`, `index_path`, `binary_sha256`, `cache_hit`, `stats`, `warnings`). Class-level details live in `index.json`/`index.jsonl` under a `classes` array. See `docs/jadx-artifact-format.md`.

### `clear_cache`

Deletes failed artifacts or all artifacts under the active artifact output root. Engine-agnostic — Ghidra and jadx artifacts share the same artifact root and cache rules.

## No Filesystem Companion Required

The deployed product is a single MCP server. Coding agents already have file-reading capabilities, so they can read the returned `manifest_path`, `index_path`, and selected `functions/*.c` files directly.

A separate filesystem MCP server is only for chat clients such as Claude Desktop when they cannot read local files from returned paths. It is not part of the normal Claude Code/OpenCode/Codex deployment.

## LLM E2E Client

The LLM client uses OpenAI-compatible environment variables only:

```bash
export DECOMP_MCP_LLM_API_KEY="..."
export DECOMP_MCP_LLM_BASE_URL="https://example.invalid"
export DECOMP_MCP_LLM_MODEL="gpt-5.4-mini"
decomp-mcp-llm-e2e /path/to/artifact
```

Never commit API keys or place them in project files.

## Local Tests

Unit and Docker/Ghidra integration tests:

```bash
uv run pytest tests/unit tests/integration/test_docker_decompile.py
```

Full mandatory test suite, including live LLM E2E:

```bash
DECOMP_MCP_LLM_API_KEY="..." \
DECOMP_MCP_LLM_BASE_URL="https://example.invalid" \
DECOMP_MCP_LLM_MODEL="gpt-5.4-mini" \
uv run pytest
```

The Docker integration tests build the image and run both container-server and host docker-worker flows. The LLM E2E test intentionally fails if `DECOMP_MCP_LLM_API_KEY` or `DECOMP_MCP_LLM_BASE_URL` is missing.

Secrets are read from environment variables only and are not written to artifacts or logs.
