# Deployment Modes

## Recommended: Coding Agent With Native File Access

This is the default deployment for Claude Code, OpenCode, Codex, and other coding agents.

```text
MCP client
  -> decomp-mcp running on host
    -> docker worker container
      -> Ghidra headless
```

The MCP server accepts a host `binary_path`, validates it against `DECOMP_MCP_ALLOWED_INPUT_ROOTS`, mounts the binary's parent directory read-only as `/input`, mounts `DECOMP_MCP_HOST_OUTPUT_ROOT` as `/output`, and returns host artifact paths.

Use `.mcp.json.example` for this mode. It configures only the `decomp` MCP server because these clients can read returned artifact paths with their own file tools.

For Codex CLI or Codex Desktop, you can also add the TOML snippet from `.codex.config.toml.example` to `~/.codex/config.toml`. The TOML example keeps the workspace cwd behavior and sets a longer MCP `tool_timeout_sec` for Ghidra jobs.

The coding-agent config does not need `DECOMP_MCP_ALLOWED_INPUT_ROOTS` or `DECOMP_MCP_HOST_OUTPUT_ROOT`. When those variables are unset, `decomp-mcp` allows files under the MCP server launch cwd and writes artifacts to `./decompiled`. Use `uv run --project /path/to/decomp-mcp decomp-mcp`, not `uv --directory /path/to/decomp-mcp run decomp-mcp`, so the launch cwd remains the client workspace.

```bash
docker build --platform linux/amd64 -t decomp-mcp:0.1.0 .

cd /path/to/workspace
uv run --project /path/to/decomp-mcp decomp-mcp
```

## Claude Code Smoke Test

You can test without writing a persistent Claude Code MCP config by passing `--mcp-config` for one run.

```bash
claude -p \
  --model sonnet \
  --strict-mcp-config \
  --mcp-config '{"mcpServers":{"decomp":{"command":"uv","args":["run","--project","/path/to/decomp-mcp","decomp-mcp"]}}}' \
  --allowedTools 'mcp__decomp__decompile_binary,Read' \
  'Use the decomp MCP tool to decompile ./binaries/hello with force set to true. Then read the returned manifest_path and index_path. Reply with artifact_id, status, cache_hit, functions_total, and function names.'
```

Expected result: `cache_hit` is `false` on a forced run, `manifest.status` is `ok` or `partial`, and the returned artifact paths are host paths under `./decompiled`.

## Chat Client With Filesystem MCP

Use this for Claude Desktop and other chat clients that can call MCP tools but cannot read returned local paths directly.

Use `.mcp.claude-desktop.json.example` for this mode. It starts both:

- `decomp`: validates the host binary path, runs the Docker worker, and returns artifact paths.
- `filesystem`: grants the client access to the decompiled artifact output directory and selected input roots.

After `decompile_binary` returns, ask the client to read `manifest_path`, `index_path`, and any needed `functions/*.c` files through the filesystem MCP server.

## Container Server Mode

Use this only when the MCP client should connect directly to a Dockerized MCP server with pre-mounted `/input` and `/output` roots. This is a deployment option, not the primary split between coding-agent and chat-client usage.

```bash
docker run -i --rm \
  --platform linux/amd64 \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -e DECOMP_MCP_EXECUTION_MODE=direct \
  -v "$PWD/binaries:/input:ro" \
  -v "$PWD/decompiled:/output:rw" \
  decomp-mcp:0.1.0
```

Call `decompile_binary` with `/input/...` paths.

## Local Ghidra Mode

Use this only when Ghidra and JDK 21 are installed on the host.

```bash
export DECOMP_MCP_EXECUTION_MODE=direct
export GHIDRA_HOME="$HOME/tools/ghidra_12.0.4_PUBLIC"
export DECOMP_MCP_INPUT_ROOT="$HOME/rev"
export DECOMP_MCP_OUTPUT_ROOT="$HOME/decompiled"
uv run decomp-mcp
```

Call `decompile_binary` with paths under `DECOMP_MCP_INPUT_ROOT`.

## Upload/Chunk Mode

This project does not need a chunk upload protocol for the target clients. Coding agents can pass a host path to the host MCP server, and the server can mount that path into Docker without sending file bytes through MCP messages.
