from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
import urllib.error
import urllib.request
from urllib.parse import urlparse, urlunparse

from openai import OpenAI


REQUIRED_ENV = ("DECOMP_MCP_LLM_API_KEY", "DECOMP_MCP_LLM_BASE_URL")
MODEL_ENV = "DECOMP_MCP_LLM_MODEL"
DEFAULT_MODEL = "gpt-5.4-mini"


def require_env() -> tuple[str, str, str]:
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"missing required environment variables: {', '.join(missing)}")
    return (
        os.environ["DECOMP_MCP_LLM_API_KEY"],
        normalize_base_url(os.environ["DECOMP_MCP_LLM_BASE_URL"]),
        os.environ.get(MODEL_ENV, DEFAULT_MODEL),
    )


def normalize_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.path in {"", "/"}:
        parsed = parsed._replace(path="/v1")
    return urlunparse(parsed)


def build_prompt(artifact_dir: Path) -> str:
    manifest = json.loads((artifact_dir / "manifest.json").read_text(encoding="utf-8"))
    index = json.loads((artifact_dir / "index.json").read_text(encoding="utf-8"))
    function_snippets: list[str] = []
    for function in index.get("functions", []):
        if function.get("status") != "ok" or not function.get("file"):
            continue
        function_path = artifact_dir / function["file"]
        if function_path.exists():
            function_snippets.append(function_path.read_text(encoding="utf-8")[:2000])
        if len(function_snippets) >= 2:
            break

    return (
        "You are validating a decomp-mcp artifact. "
        "Reply with compact JSON containing keys artifact_id, status, functions_total, "
        "and whether pseudocode_files_are_readable.\n\n"
        f"manifest:\n{json.dumps(manifest, ensure_ascii=False)}\n\n"
        f"index functions sample:\n{json.dumps(index.get('functions', [])[:5], ensure_ascii=False)}\n\n"
        f"function snippets:\n{json.dumps(function_snippets, ensure_ascii=False)}"
    )


def run_llm_check(artifact_dir: Path) -> str:
    api_key, base_url, model = require_env()
    prompt = build_prompt(artifact_dir)
    messages = [
        {"role": "system", "content": "Return only compact JSON. Do not include secrets."},
        {"role": "user", "content": prompt},
    ]
    try:
        client = OpenAI(api_key=api_key, base_url=base_url)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            max_completion_tokens=300,
        )
        content = response.choices[0].message.content
    except Exception:
        content = raw_chat_completion(api_key=api_key, base_url=base_url, model=model, messages=messages)
    if not content:
        raise RuntimeError("LLM returned an empty response")
    return content


def raw_chat_completion(api_key: str, base_url: str, model: str, messages: list[dict[str, str]]) -> str:
    payload = json.dumps(
        {
            "model": model,
            "messages": messages,
            "max_completion_tokens": 300,
        }
    ).encode("utf-8")
    url = base_url.rstrip("/") + "/chat/completions"
    request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "curl/8.7.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"LLM HTTP error {exc.code}: {_redact(body)}") from exc
    parsed = json.loads(body)
    return parsed["choices"][0]["message"]["content"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run an OpenAI-compatible LLM check against an artifact directory.")
    parser.add_argument("artifact_dir", type=Path)
    return parser


def main() -> None:
    try:
        parsed = build_parser().parse_args()
        sys.stdout.write(run_llm_check(parsed.artifact_dir))
        sys.stdout.write("\n")
    except Exception as exc:
        sys.stderr.write(_redact(str(exc)) + "\n")
        raise SystemExit(1)


def _redact(text: str) -> str:
    api_key = os.environ.get("DECOMP_MCP_LLM_API_KEY")
    if api_key:
        text = text.replace(api_key, "[REDACTED_API_KEY]")
    return text


if __name__ == "__main__":
    main()
