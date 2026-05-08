from __future__ import annotations

from typing import Literal

from mcp.server.fastmcp import FastMCP

from .ghidra_runner import clear_cache as clear_cache_impl
from .ghidra_runner import decompile_binary as decompile_binary_impl
from .jadx_runner import decompile_apk as decompile_apk_impl
from .logging_config import configure_logging


mcp = FastMCP("decomp-mcp")


@mcp.tool()
def decompile_binary(
    binary_path: str,
    output_name: str | None = None,
    force: bool = False,
    profile: Literal["fast", "default", "deep"] = "default",
    include_autonamed: bool = True,
    filter_regex: str | None = None,
    min_function_size: int = 0,
    max_functions: int | None = None,
    single_file: bool = False,
    total_timeout_sec: int | None = None,
    function_timeout_sec: int | None = None,
) -> dict:
    return decompile_binary_impl(
        binary_path=binary_path,
        output_name=output_name,
        force=force,
        profile=profile,
        include_autonamed=include_autonamed,
        filter_regex=filter_regex,
        min_function_size=min_function_size,
        max_functions=max_functions,
        single_file=single_file,
        total_timeout_sec=total_timeout_sec,
        function_timeout_sec=function_timeout_sec,
    )


@mcp.tool()
def decompile_apk(
    apk_path: str,
    output_name: str | None = None,
    force: bool = False,
    profile: Literal["fast", "default", "deep"] = "default",
    deobf: bool = True,
    show_bad_code: bool = False,
    include_resources: bool = False,
    classes_filter: str | None = None,
    max_classes: int | None = None,
    single_file: bool = False,
    total_timeout_sec: int | None = None,
) -> dict:
    return decompile_apk_impl(
        binary_path=apk_path,
        output_name=output_name,
        force=force,
        profile=profile,
        deobf=deobf,
        show_bad_code=show_bad_code,
        include_resources=include_resources,
        classes_filter=classes_filter,
        max_classes=max_classes,
        single_file=single_file,
        total_timeout_sec=total_timeout_sec,
    )


@mcp.tool()
def clear_cache(
    target: Literal["all", "failed"] = "failed",
    older_than_days: int | None = None,
) -> dict:
    return clear_cache_impl(target=target, older_than_days=older_than_days)


def main() -> None:
    configure_logging()
    mcp.run()
