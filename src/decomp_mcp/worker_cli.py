from __future__ import annotations

import json
import sys

from .ghidra_runner import GhidraRunner
from .models import DecompileRequest


def main() -> None:
    try:
        payload = json.load(sys.stdin)
        request = DecompileRequest(**payload)
        result = GhidraRunner().decompile(request)
        json.dump(result, sys.stdout)
        sys.stdout.write("\n")
    except Exception as exc:
        json.dump(
            {
                "status": "failed",
                "artifact_id": None,
                "artifact_dir": None,
                "manifest_path": None,
                "index_path": None,
                "binary_sha256": "",
                "cache_hit": False,
                "stats": {},
                "warnings": [str(exc)],
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
