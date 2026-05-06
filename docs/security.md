# Security

`decomp-mcp` is deployed as one MCP server. The recommended coding-agent deployment runs that server on the host and starts a short-lived Docker worker for Ghidra.

## Docker Worker Mode

- `binary_path` must resolve under one of `DECOMP_MCP_ALLOWED_INPUT_ROOTS`.
- The Docker worker mounts the binary's parent directory as `/input:ro`.
- The Docker worker mounts `DECOMP_MCP_HOST_OUTPUT_ROOT` as `/output:rw`.
- The worker is started with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, pids, memory, and CPU limits.
- The server never executes the input binary.
- Returned paths are host-visible artifact paths so Claude Code/OpenCode can read them directly.

## Container Server Mode

- `binary_path` must resolve under `/input`.
- `/input` should be mounted read-only.
- Results are written only under `/output/artifacts`.
- The Docker examples disable networking and drop capabilities.

## Local Ghidra Mode

- Use only for trusted development environments.
- Set `DECOMP_MCP_INPUT_ROOT` and `DECOMP_MCP_OUTPUT_ROOT` explicitly.
- Ghidra analyzes the input file with the permissions of the local MCP server process.

## Secrets

- API keys for LLM smoke tests are read only from environment variables.
- Do not put secrets in MCP config examples, artifact directories, logs, or test fixtures.

## Filesystem MCP

A separate filesystem MCP server is not part of the normal deployment. If one is used for a chat client without native file access, restrict it to the host artifact output directory only.
