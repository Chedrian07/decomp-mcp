from __future__ import annotations

from decomp_mcp.models import DecompileRequest


def test_decompile_request_uses_profile_timeout_defaults() -> None:
    request = DecompileRequest(binary_path="/input/hello", profile="deep")

    assert request.effective_total_timeout_sec() == 3600
    assert request.effective_function_timeout_sec() == 120


def test_decompile_request_explicit_timeouts_override_profile_defaults() -> None:
    request = DecompileRequest(
        binary_path="/input/hello",
        profile="fast",
        total_timeout_sec=90,
        function_timeout_sec=7,
    )

    assert request.effective_total_timeout_sec() == 90
    assert request.effective_function_timeout_sec() == 7
