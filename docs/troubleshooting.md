# Troubleshooting

## No artifact is created

Check `logs/runner.log` and `logs/ghidra.log` inside the artifact directory, or failed artifact directory.

In `docker-worker` mode, first check that:

- Docker is running.
- `DECOMP_MCP_DOCKER_IMAGE` exists locally.
- `binary_path` is under `DECOMP_MCP_ALLOWED_INPUT_ROOTS`.
- `DECOMP_MCP_HOST_OUTPUT_ROOT` is writable by Docker.

## Cache did not hit

Cache keys include the binary SHA256, Ghidra version, decomp-mcp version, script SHA256, and selected options.

## MCP client breaks

Make sure nothing writes diagnostic text to stdout. Runner and Ghidra logs are written to files or stderr.

## Docker build is slow on Apple Silicon

Build and run with `--platform linux/amd64`. The Ghidra release used by this project includes the native decompiler executable for Linux x86_64.

## Host path is rejected

In `docker-worker` mode, absolute host paths are accepted only if they resolve under one of the comma-separated `DECOMP_MCP_ALLOWED_INPUT_ROOTS`. Symlinks are resolved before this check.

## Client cannot read returned files

Claude Code, OpenCode, Codex, and similar coding agents should read returned host paths directly. General chat clients may need their own restricted filesystem bridge, but that bridge is not part of the standard `decomp-mcp` deployment.
