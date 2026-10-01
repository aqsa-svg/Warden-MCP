"""Gemini adapter conversions. Pure functions -- no API key, no network."""

from __future__ import annotations

from typing import Any

import pytest

# The Gemini SDK imports `ssl`, which a machine-level Application Control policy can
# block. Guard before the imports that need it, so collection skips rather than
# errors -- and skips VISIBLY. A test that quietly stops running is the same failure
# mode as a metric that quietly stops being measured.
try:  # pragma: no cover - environment dependent
    import ssl as _ssl  # noqa: F401
except ImportError:  # pragma: no cover
    pytest.skip(
        "ssl unavailable; the Gemini adapter cannot import",
        allow_module_level=True,
    )

from google.genai import types

from warden.demo_agent.gemini import from_gemini, to_gemini, tools_to_gemini

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "search_docs",
        "description": "Search the KB.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["query"],
        },
    }
]

CONVERSATION: list[dict[str, Any]] = [
    {"role": "user", "content": "Look up CUS-1001 and open a ticket."},
    {"role": "assistant", "content": [
        {"type": "tool_use", "id": "tu_1", "name": "get_customer",
         "input": {"customer_id": "CUS-1001"}}]},
    {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "tu_1",
         "content": [{"type": "text", "text": '{"name": "Dana"}'}], "is_error": False}]},
    {"role": "assistant", "content": [{"type": "text", "text": "Found them."}]},
]


def test_json_schema_passes_through_unchanged() -> None:
    """Gemini's restricted Schema type would drop fields; parameters_json_schema
    keeps the MCP schema byte-identical, so schema_hash stays meaningful."""
    declarations = tools_to_gemini(TOOL_SPECS)[0].function_declarations
    assert declarations is not None
    assert declarations[0].parameters_json_schema == TOOL_SPECS[0]["input_schema"]


def test_assistant_role_becomes_model() -> None:
    contents = to_gemini(CONVERSATION)
    assert [c.role for c in contents] == ["user", "model", "user", "model"]


def test_tool_result_recovers_the_function_name() -> None:
    """A tool_result block carries only the id it answers, but Gemini's
    function_response requires the name. It is recovered from the prior turn."""
    parts = to_gemini(CONVERSATION)[2].parts
    assert parts is not None
    response = parts[0].function_response
    assert response is not None
    assert response.name == "get_customer"
    assert response.id == "tu_1"
    assert response.response == {"result": '{"name": "Dana"}'}


def test_error_results_are_flagged_not_silently_passed() -> None:
    messages: list[dict[str, Any]] = [
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "get_customer", "input": {}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [{"type": "text", "text": "boom"}], "is_error": True}]},
    ]
    parts = to_gemini(messages)[1].parts
    assert parts is not None and parts[0].function_response is not None
    assert parts[0].function_response.response == {"error": "boom"}


def _response(*parts: types.Part) -> types.GenerateContentResponse:
    return types.GenerateContentResponse(
        candidates=[types.Candidate(content=types.Content(role="model", parts=list(parts)))]
    )


def test_function_call_becomes_tool_use() -> None:
    out = from_gemini(_response(types.Part(
        function_call=types.FunctionCall(id="fc_1", name="search_docs", args={"query": "x"}))))
    assert out.content == [
        {"type": "tool_use", "id": "fc_1", "name": "search_docs", "input": {"query": "x"}}
    ]


def test_missing_call_id_is_synthesised_stably() -> None:
    """Gemini omits the id for a single call. Without a synthetic one the tool_result
    could not be matched back on the next turn."""
    out = from_gemini(_response(types.Part(
        function_call=types.FunctionCall(name="search_docs", args={"query": "x"}))))
    assert out.content[0]["id"] == "call_0_search_docs"


def test_thought_parts_are_dropped() -> None:
    out = from_gemini(_response(
        types.Part(text="internal reasoning", thought=True),
        types.Part(text="the answer"),
    ))
    assert out.content == [{"type": "text", "text": "the answer"}]


def test_empty_candidates_yield_no_blocks() -> None:
    assert from_gemini(types.GenerateContentResponse(candidates=[])).content == []


def test_round_trip_preserves_tool_call_linkage() -> None:
    """A call emitted by from_gemini must survive to_gemini and match its result."""
    emitted = from_gemini(_response(types.Part(
        function_call=types.FunctionCall(name="get_customer", args={"customer_id": "C1"}))))
    call_id = emitted.content[0]["id"]
    messages: list[dict[str, Any]] = [
        {"role": "assistant", "content": emitted.content},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call_id,
             "content": [{"type": "text", "text": "ok"}], "is_error": False}]},
    ]
    parts = to_gemini(messages)
    call_part = (parts[0].parts or [])[0].function_call
    resp_part = (parts[1].parts or [])[0].function_response
    assert call_part is not None and resp_part is not None
    assert call_part.id == resp_part.id
    assert resp_part.name == "get_customer"


def test_backoff_grows_and_is_capped() -> None:
    """Transient 5xx retries back off exponentially (no RetryInfo to honour), capped."""
    from warden.demo_agent.gemini import MAX_BACKOFF_S, _backoff_seconds

    delays = [_backoff_seconds(n) for n in range(6)]
    assert delays[0] < delays[1] < delays[2]
    assert all(d <= MAX_BACKOFF_S for d in delays)


def test_daily_quota_is_distinguished_from_transient() -> None:
    from warden.demo_agent.gemini import is_daily_quota

    assert is_daily_quota("... PerDayPerProject ... quota ...")
    assert not is_daily_quota("503 UNAVAILABLE high demand")
    assert not is_daily_quota("PerMinute rate limit")
