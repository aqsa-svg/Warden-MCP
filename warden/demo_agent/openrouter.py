"""OpenRouter model adapter for the demo agent.

A sibling of gemini.py with the same contract: it turns Warden's internal message shape
(see agent.py) into a provider wire format and back, and nothing outside this module
knows the provider. OpenRouter speaks the OpenAI chat-completions API, so one adapter
reaches any model OpenRouter fronts (Grok, and others) by model id.

This is a *second* model line, not a replacement: results are keyed by model and by a
provider-scoped source hash (see source_hash.py), so an OpenRouter/Grok calibration never
counts toward Gemini's denominator and adding this file never moves Gemini's hash.

Unlike gemini.py there is no per-day free-tier wall, so there is no BudgetExceeded
fast-fail here: a paid key rate-limits per-minute, not per-day. The run-level request cap
(RequestBudget) remains the cost bound, and a 429/5xx is a transient pause to back off
through, never an exhausted window to abandon.

The default model is defined here rather than imported from config.py on purpose: config
is in the source-hash scope, this adapter is not part of Gemini's hash, so keeping the
OpenRouter default local keeps the two providers' hashes independent.
"""

from __future__ import annotations

import json
import time
from typing import Any, Final, cast

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    OpenAI,
    RateLimitError,
)

DEFAULT_MODEL: Final = "x-ai/grok-4-fast"
OPENROUTER_BASE_URL: Final = "https://openrouter.ai/api/v1"
MAX_RETRIES: Final = 5
BACKOFF_BASE_S: Final = 2.0
MAX_BACKOFF_S: Final = 120.0
MAX_OUTPUT_TOKENS: Final = 8192


def make_client(api_key: str) -> OpenAI:
    """OpenRouter is OpenAI-compatible; only the base URL differs."""
    return OpenAI(base_url=OPENROUTER_BASE_URL, api_key=api_key)


def tools_to_openai(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """MCP JSON Schema passes straight through as the function parameters -- no lossy
    conversion. OpenAI's tool schema uses the same JSON Schema dialect."""
    return [
        {
            "type": "function",
            "function": {
                "name": str(tool["name"]),
                "description": str(tool.get("description") or ""),
                "parameters": tool.get("input_schema")
                or {"type": "object", "properties": {}},
            },
        }
        for tool in tools
    ]


def _result_text(block: dict[str, Any]) -> str:
    return "".join(
        part.get("text", "")
        for part in block.get("content") or []
        if isinstance(part, dict)
    )


def to_openai(system: str, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Warden's internal messages -> OpenAI chat messages.

    Two shape differences the translation absorbs: the system prompt is its own leading
    message, not a request-level field; and a tool result is a `tool` role message keyed
    by tool_call_id, while tool calls ride on the assistant message.
    """
    out: list[dict[str, Any]] = [{"role": "system", "content": system}]

    for message in messages:
        role = "assistant" if message.get("role") == "assistant" else "user"
        content = message.get("content")

        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        if not isinstance(content, list):
            continue

        texts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        tool_messages: list[dict[str, Any]] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text":
                texts.append(str(block.get("text") or ""))
            elif kind == "tool_use":
                tool_calls.append(
                    {
                        "id": str(block.get("id")),
                        "type": "function",
                        "function": {
                            "name": str(block.get("name")),
                            "arguments": json.dumps(dict(block.get("input") or {})),
                        },
                    }
                )
            elif kind == "tool_result":
                tool_messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": str(block.get("tool_use_id")),
                        "content": _result_text(block),
                    }
                )

        if role == "assistant":
            assistant: dict[str, Any] = {"role": "assistant"}
            # OpenAI requires a content field even when the turn is only tool calls.
            assistant["content"] = "\n".join(t for t in texts if t) or None
            if tool_calls:
                assistant["tool_calls"] = tool_calls
            if assistant["content"] is not None or tool_calls:
                out.append(assistant)
        else:
            # Tool results first (they answer the prior assistant turn), then user text.
            out.extend(tool_messages)
            user_text = "\n".join(t for t in texts if t)
            if user_text:
                out.append({"role": "user", "content": user_text})

    return out


class ModelResponse:
    """Warden-shaped response. Mirrors what the graph and provenance code parse."""

    def __init__(self, content: list[dict[str, Any]]) -> None:
        self.content = content


def from_openai(response: Any) -> ModelResponse:
    blocks: list[dict[str, Any]] = []
    choices = getattr(response, "choices", None) or []
    if not choices:
        return ModelResponse(blocks)
    message = choices[0].message

    text = getattr(message, "content", None)
    if text:
        blocks.append({"type": "text", "text": str(text)})

    for call in getattr(message, "tool_calls", None) or []:
        try:
            arguments = json.loads(call.function.arguments or "{}")
        except (ValueError, TypeError):
            arguments = {}
        blocks.append(
            {
                "type": "tool_use",
                "id": str(call.id),
                "name": str(call.function.name),
                "input": arguments if isinstance(arguments, dict) else {},
            }
        )
    return ModelResponse(blocks)


def _backoff_seconds(attempt: int) -> float:
    return float(min(BACKOFF_BASE_S * (2**attempt), MAX_BACKOFF_S))


def openrouter_model(
    client: OpenAI,
    system: str,
    model: str = DEFAULT_MODEL,
    *,
    on_retry: Any = None,
) -> Any:
    declarations: list[dict[str, Any]] | None = None

    def call(
        messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> ModelResponse:
        nonlocal declarations
        if declarations is None:
            declarations = tools_to_openai(tools)
        wire = to_openai(system, messages)
        last: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                return from_openai(
                    client.chat.completions.create(
                        model=model,
                        messages=cast(Any, wire),
                        tools=cast(Any, declarations),
                        tool_choice="auto",
                        max_tokens=MAX_OUTPUT_TOKENS,
                    )
                )
            except (RateLimitError, APITimeoutError, APIConnectionError) as exc:
                last = exc
                delay = _backoff_seconds(attempt)
                if on_retry is not None:
                    on_retry(attempt + 1, delay)
                time.sleep(delay)
            except APIStatusError as exc:
                if exc.status_code < 500:
                    raise
                last = exc
                delay = _backoff_seconds(attempt)
                if on_retry is not None:
                    on_retry(attempt + 1, delay)
                time.sleep(delay)
        raise RuntimeError(f"gave up after {MAX_RETRIES} attempts") from last

    return call
