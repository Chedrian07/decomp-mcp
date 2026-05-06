from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def call_decompile(
    command: str,
    args: list[str],
    tool_args: dict[str, Any],
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    server_params = StdioServerParameters(command=command, args=args, env=env)
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("decompile_binary", tool_args)
            if result.isError:
                raise RuntimeError(str(result.content))
            if not result.content:
                raise RuntimeError("empty MCP tool result")
            first = result.content[0]
            text = getattr(first, "text", None)
            if text is None:
                raise RuntimeError(f"unexpected MCP result content: {result.content!r}")
            return json.loads(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Call decomp-mcp over stdio and print the tool result.")
    parser.add_argument("binary_path")
    parser.add_argument("--server-command", default="decomp-mcp")
    parser.add_argument("--server-arg", action="append", default=[])
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--profile", default="default", choices=["fast", "default", "deep"])
    parser.add_argument("--single-file", action="store_true")
    return parser


def main() -> None:
    parsed = build_parser().parse_args()
    tool_args = {
        "binary_path": parsed.binary_path,
        "force": parsed.force,
        "profile": parsed.profile,
        "single_file": parsed.single_file,
    }
    result = asyncio.run(call_decompile(parsed.server_command, parsed.server_arg, tool_args, env=dict(os.environ)))
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
