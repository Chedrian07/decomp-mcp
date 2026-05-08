from __future__ import annotations

from dataclasses import asdict

from decomp_mcp.hashing import canonical_json_hash
from decomp_mcp.models import (
    JADX_PROFILE_TIMEOUTS,
    JadxArtifactOptions,
    JadxRequest,
)


def test_jadx_request_uses_profile_timeout_defaults() -> None:
    request = JadxRequest(binary_path="/input/hello.apk", profile="deep")

    assert request.effective_total_timeout_sec() == JADX_PROFILE_TIMEOUTS["deep"]


def test_jadx_request_explicit_timeout_overrides_profile_default() -> None:
    request = JadxRequest(binary_path="/input/hello.apk", profile="fast", total_timeout_sec=42)

    assert request.effective_total_timeout_sec() == 42


def test_jadx_options_hash_includes_engine_marker() -> None:
    options = JadxArtifactOptions(
        jadx_version="1.5.4",
        decomp_mcp_version="0.1.0",
        java_version="21",
        profile="default",
        deobf=True,
        show_bad_code=False,
        include_resources=False,
        classes_filter=None,
        max_classes=None,
        single_file=False,
    )
    payload = options.to_hash_payload()

    assert payload["engine"] == "jadx"
    assert payload["jadx_version"] == "1.5.4"
    assert payload["deobf"] is True
    assert "ghidra_version" not in payload
    assert "function_timeout_sec" not in payload


def test_jadx_options_hash_is_deterministic_and_sensitive_to_changes() -> None:
    base_kwargs = dict(
        jadx_version="1.5.4",
        decomp_mcp_version="0.1.0",
        java_version="21",
        profile="default",
        deobf=True,
        show_bad_code=False,
        include_resources=False,
        classes_filter=None,
        max_classes=None,
        single_file=False,
    )
    h1 = canonical_json_hash(JadxArtifactOptions(**base_kwargs).to_hash_payload())
    h2 = canonical_json_hash(JadxArtifactOptions(**base_kwargs).to_hash_payload())
    h3 = canonical_json_hash(JadxArtifactOptions(**{**base_kwargs, "deobf": False}).to_hash_payload())

    assert h1 == h2
    assert h1 != h3


def test_jadx_request_normalized_round_trips() -> None:
    request = JadxRequest(
        binary_path="/input/sample.apk",
        output_name="sample",
        deobf=False,
        include_resources=True,
        max_classes=10,
    )
    normalized = request.normalized()

    assert normalized["binary_path"] == "/input/sample.apk"
    assert normalized["deobf"] is False
    assert normalized["include_resources"] is True
    assert normalized["max_classes"] == 10
    assert normalized == asdict(request)
