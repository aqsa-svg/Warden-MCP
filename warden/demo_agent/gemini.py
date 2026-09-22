"""Gemini model adapter for the demo agent.

The agent's internal message shape (see agent.py) is Warden's own, not a provider's.
This module is the only place that knows about Gemini, so swapping brains does not
touch the graph or the provenance instrumentation.

Automatic function calling is disabled deliberately. Letting the SDK run the tool loop
would hide the message list, and the message list is exactly what the provenance
instrumentation has to see -- and what has to pass through the gateway proxy.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Final, cast

from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from warden.config import DEFAULT_MODEL as _DEFAULT_MODEL
from warden.errors import BudgetExceeded

DEFAULT_MODEL: Final = _DEFAULT_MODEL
MAX_RETRIES: Final = 5
DEFAULT_BACKOFF_S: Final = 60.0
MAX_BACKOFF_S: Final = 120.0
_RETRY_DELAY_RE: Final = re.compile(r"retryDelay['\"]?:\s*['\"]?(\d+(?:\.\d+)?)")
_PER_DAY_MARKER: Final = "PerDay"
"""Google names the violated quota in the 429 body. A per-minute violation is worth
sleeping through; a per-DAY one is not -- the window is 24 hours, so retrying burns
wall-clock and, worse, consumes the next window's allowance as it becomes available."""
SIG_KEY: Final = "_thought_signature"
"""Gemini 3.x returns an opaque thought_signature on functionCall parts and rejects
the next request if it is not echoed back. It rides along on the internal block so it
survives the LangGraph state round trip. Provider-internal: never logged, never taint."""
MAX_OUTPUT_TOKENS: Final = 8192


def tools_to_gemini(tools: list[dict[str, Any]]) -> list[types.Tool]:
    """MCP JSON Schema passes through via parameters_json_schema -- no lossy
    conversion into Gemini's restricted Schema type."""
    return [
        types.Tool(
            function_declarations=[
                types.FunctionDeclaration(
                    name=str(tool["name"]),
                    description=str(tool.get("description") or ""),
                    parameters_json_schema=tool.get("input_schema")
                    or {"type": "object", "properties": {}},
                )
                for tool in tools
            ]
        )
    ]


def _tool_names_by_id(messages: list[dict[str, Any]]) -> dict[str, str]:
    """Gemini's function_response requires the function name, but a tool_result block
    carries only the id it answers. Recover the mapping from prior assistant turns."""
    names: dict[str, str] = {}
    for message in messages:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                names[str(block.get("id"))] = str(block.get("name"))
    return names


def to_gemini(messages: list[dict[str, Any]]) -> list[types.Content]:
    names = _tool_names_by_id(messages)
    contents: list[types.Content] = []

    for message in messages:
        role = "model" if message.get("role") == "assistant" else "user"
        content = message.get("content")

        if isinstance(content, str):
            contents.append(
                types.Content(role=role, parts=[types.Part(text=content)])
            )
            continue
        if not isinstance(content, list):
            continue

        parts: list[types.Part] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                parts.append(types.Part(text=str(block.get("text") or "")))
            elif kind == "tool_use":
                parts.append(
                    types.Part(
                        function_call=types.FunctionCall(
                            id=str(block.get("id")),
                            name=str(block.get("name")),
                            args=dict(block.get("input") or {}),
                        ),
                        thought_signature=block.get(SIG_KEY),
                    )
                )
            elif kind == "tool_result":
                call_id = str(block.get("tool_use_id"))
                text = "".join(
                    part.get("text", "")
                    for part in block.get("content") or []
                    if isinstance(part, dict)
                )
                key = "error" if block.get("is_error") else "result"
                parts.append(
                    types.Part(
                        function_response=types.FunctionResponse(
                            id=call_id,
                            name=names.get(call_id, "unknown"),
                            response={key: text},
                        )
                    )
                )
        if parts:
            contents.append(types.Content(role=role, parts=parts))
    return contents


class ModelResponse:
    """Warden-shaped response. Mirrors what the graph and provenance code parse."""

    def __init__(self, content: list[dict[str, Any]]) -> None:
        self.content = content


def from_gemini(response: types.GenerateContentResponse) -> ModelResponse:
    blocks: list[dict[str, Any]] = []
    candidates = response.candidates or []
    if not candidates or candidates[0].content is None:
        return ModelResponse(blocks)

    for index, part in enumerate(candidates[0].content.parts or []):
        if part.thought:
            continue
        if part.function_call is not None:
            call = part.function_call
            block: dict[str, Any] = {
                "type": "tool_use",
                # Gemini omits the id for a single call; synthesise a stable one so
                # the tool_result can be matched back on the next turn.
                "id": call.id or f"call_{index}_{call.name}",
                "name": str(call.name),
                "input": dict(call.args or {}),
            }
            if part.thought_signature is not None:
                block[SIG_KEY] = part.thought_signature
            blocks.append(block)
        elif part.text:
            blocks.append({"type": "text", "text": part.text})
    return ModelResponse(blocks)


def is_daily_quota(message: str) -> bool:
    return _PER_DAY_MARKER in message


def _retry_after_seconds(message: str) -> float:
    """Honour the server's own RetryInfo rather than guessing a backoff.

    Free-tier quota is low enough that a multi-turn agent run will hit it mid-run.
    Failing the whole run there would record an attack as unsuccessful when the model
    never got to answer -- biasing ASR in the flattering direction, which is the
    direction to be paranoid about.
    """
    match = _RETRY_DELAY_RE.search(message)
    if match is None:
        return DEFAULT_BACKOFF_S
    return min(float(match.group(1)) + 1.0, MAX_BACKOFF_S)


def gemini_model(
    client: genai.Client,
    system: str,
    model: str = DEFAULT_MODEL,
    *,
    on_retry: Any = None,
) -> Any:
    declarations = None

    def call(
        messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ModelResponse:
        nonlocal declarations
        if declarations is None:
            declarations = tools_to_gemini(tools)
        config = types.GenerateContentConfig(
            system_instruction=system,
            tools=cast(Any, declarations),
            automatic_function_calling=types.AutomaticFunctionCallingConfig(
                disable=True
            ),
            max_output_tokens=MAX_OUTPUT_TOKENS,
        )
        contents = to_gemini(messages)
        last: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                return from_gemini(
                    client.models.generate_content(
                        model=model, contents=contents, config=config
                    )
                )
            except genai_errors.ClientError as exc:
                if exc.code != 429:
                    raise
                if is_daily_quota(str(exc)):
                    # Sleeping cannot clear a daily window. Surface it so the caller
                    # can checkpoint and resume tomorrow instead of spending the
                    # remaining wall-clock, and the next window's quota, on retries.
                    raise BudgetExceeded(
                        "daily model quota exhausted; stop and resume in the next "
                        "window rather than retrying"
                    ) from exc
                last = exc
                delay = _retry_after_seconds(str(exc))
                if on_retry is not None:
                    on_retry(attempt + 1, delay)
                time.sleep(delay)
        raise RuntimeError(f"rate limited after {MAX_RETRIES} attempts") from last

    return call
