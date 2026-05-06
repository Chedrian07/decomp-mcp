from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal


ArtifactStatus = Literal["ok", "partial", "failed", "cached"]
Profile = Literal["fast", "default", "deep"]


PROFILE_ANALYSIS_TIMEOUTS: dict[Profile, int] = {
    "fast": 300,
    "default": 1200,
    "deep": 3600,
}

PROFILE_FUNCTION_TIMEOUTS: dict[Profile, int] = {
    "fast": 20,
    "default": 60,
    "deep": 120,
}

MAX_TOTAL_TIMEOUT_SEC = 24 * 60 * 60
MAX_FUNCTION_TIMEOUT_SEC = 60 * 60


@dataclass(frozen=True)
class DecompileRequest:
    binary_path: str
    output_name: str | None = None
    force: bool = False
    profile: Profile = "default"
    include_autonamed: bool = True
    filter_regex: str | None = None
    min_function_size: int = 0
    max_functions: int | None = None
    single_file: bool = False
    total_timeout_sec: int | None = None
    function_timeout_sec: int | None = None

    def normalized(self) -> dict[str, object]:
        data = asdict(self)
        data["profile"] = self.profile
        return data

    def effective_total_timeout_sec(self) -> int:
        value = self.total_timeout_sec
        if value is None:
            value = PROFILE_ANALYSIS_TIMEOUTS[self.profile]
        return _bounded_timeout(value, MAX_TOTAL_TIMEOUT_SEC)

    def effective_function_timeout_sec(self) -> int:
        value = self.function_timeout_sec
        if value is None:
            value = PROFILE_FUNCTION_TIMEOUTS[self.profile]
        return _bounded_timeout(value, MAX_FUNCTION_TIMEOUT_SEC)


@dataclass(frozen=True)
class RuntimeInfo:
    decomp_mcp_version: str
    ghidra_version: str
    java_version: str
    script_sha256: str


@dataclass(frozen=True)
class ArtifactOptions:
    ghidra_version: str
    decomp_mcp_version: str
    script_sha256: str
    profile: Profile
    include_autonamed: bool
    filter_regex: str | None
    min_function_size: int
    max_functions: int | None
    single_file: bool
    function_timeout_sec: int

    def to_hash_payload(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ArtifactStats:
    functions_total: int = 0
    decompiled_ok: int = 0
    failed: int = 0
    skipped: int = 0
    imports_total: int = 0
    exports_total: int = 0
    strings_total: int = 0
    sections_total: int = 0
    symbols_total: int = 0
    duration_sec: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _bounded_timeout(value: int, maximum: int) -> int:
    return min(max(1, int(value)), maximum)
