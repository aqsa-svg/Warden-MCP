"""Instrumentation for the component-3 input contract.

Records, for every tool call the model emits, exactly what was in the message list
that produced it. This is the empirical answer to "which retrieved documents and prior
tool results were in the prompt that generated these arguments" -- captured from the
real request rather than assumed.

Nothing here decides taint. It only measures what the agent can observe, so that
component 3's resolver interface is designed against a fact rather than a guess.
"""

from __future__ import annotations

import json
from typing import Any, NamedTuple


class ContextWitness(NamedTuple):
    """What was visible to the model when it produced one tool call."""

    turn: int
    tool_name: str
    tool_use_id: str
    arguments: dict[str, Any]
    prior_tool_results: tuple[str, ...]
    """tool_use_ids of every tool result already in the message list."""
    prior_tool_names: tuple[str, ...]
    """The tool that produced each of those results, same order."""
    user_text_blocks: int
    verbatim_argument_sources: tuple[str, ...]
    """tool_use_ids whose result text literally contains an argument value.

    A substring match, not a provenance proof: it detects copied spans and misses
    paraphrase. Its precision and recall against real traces is the number that tells
    us whether span-level taint is viable or whether component 3 must fall back to
    whole-turn granularity.
    """


def _result_text(block: dict[str, Any]) -> str:
    content = block.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            part.get("text", "")
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def witness(
    turn: int,
    messages: list[dict[str, Any]],
    tool_use_id: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> ContextWitness:
    """Walk the message list that produced this tool call and record what was in it."""
    result_ids: list[str] = []
    result_names: list[str] = []
    result_text: dict[str, str] = {}
    name_by_id: dict[str, str] = {}
    user_text = 0

    for message in messages:
        content = message.get("content")
        if isinstance(content, str):
            user_text += 1 if message.get("role") == "user" else 0
            continue
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "tool_use":
                name_by_id[str(block.get("id"))] = str(block.get("name"))
            elif kind == "tool_result":
                rid = str(block.get("tool_use_id"))
                result_ids.append(rid)
                result_names.append(name_by_id.get(rid, "?"))
                result_text[rid] = _result_text(block)
            elif kind == "text" and message.get("role") == "user":
                user_text += 1

    values = [v for v in arguments.values() if isinstance(v, str) and len(v) >= 8]
    sources = tuple(
        rid for rid, text in result_text.items() if any(v in text for v in values)
    )

    return ContextWitness(
        turn=turn,
        tool_name=tool_name,
        tool_use_id=tool_use_id,
        arguments=arguments,
        prior_tool_results=tuple(result_ids),
        prior_tool_names=tuple(result_names),
        user_text_blocks=user_text,
        verbatim_argument_sources=sources,
    )


def render(witnesses: list[ContextWitness]) -> str:
    lines: list[str] = []
    for w in witnesses:
        lines.append(
            f"turn {w.turn}  {w.tool_name}({json.dumps(w.arguments)[:70]})"
        )
        lines.append(
            f"    context held {len(w.prior_tool_results)} prior tool result(s): "
            f"{list(w.prior_tool_names) or '-'}"
        )
        lines.append(
            f"    verbatim argument source(s): "
            f"{[n for i, n in zip(w.prior_tool_results, w.prior_tool_names) if i in w.verbatim_argument_sources] or '-'}"
        )
    return "\n".join(lines)
