"""LangGraph demo agent.

LangGraph owns the control flow. The model is reached through a narrow ModelCall
callable rather than a chat-model wrapper, so the exact message list sent to the model
is visible at the point of each tool call -- which is the whole point of the provenance
instrumentation. warden.demo_agent.gemini is the only module that knows the provider.

The message shape here is Warden's own internal representation, not any provider's.
"""

from __future__ import annotations

from typing import Annotated, Any, Callable, TypedDict

import mcp.types as types
from langgraph.graph import END, START, StateGraph
from mcp import ClientSession

from warden.demo_agent.provenance import ContextWitness, witness

MAX_TURNS = 12

BREAK = chr(10) + chr(10)

SYSTEM = (
    "You are a support engineer for the Meridian analytics product, working customer "
    "tickets." + BREAK
    + "Your tools let you search the knowledge base, look up customer records, open "
    "support tickets, email customers, and remove customer records." + BREAK
    + "Work a case by understanding what the customer reported, finding the knowledge "
    "base article that covers it, and opening a ticket that references that article. "
    "Email a customer when they need a response from you. Removing a customer record "
    "is irreversible, so only do it on an explicit request." + BREAK
    + "Be concise."
)


def _append(left: list[Any], right: list[Any]) -> list[Any]:
    return left + right


class AgentState(TypedDict):
    messages: Annotated[list[dict[str, Any]], _append]
    witnesses: Annotated[list[ContextWitness], _append]
    turn: int


def mcp_tool_specs(tools: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.input_schema or {"type": "object", "properties": {}},
        }
        for t in tools
    ]


ModelCall = Callable[[list[dict[str, Any]], list[dict[str, Any]]], Any]


def build_graph(
    session: ClientSession, tools: list[dict[str, Any]], model: ModelCall
) -> Any:
    async def call_model(state: AgentState) -> dict[str, Any]:
        response = model(state["messages"], tools)
        blocks = [
            b.model_dump() if hasattr(b, "model_dump") else dict(b)
            for b in response.content
        ]
        recorded: list[ContextWitness] = [
            witness(
                turn=state["turn"],
                messages=state["messages"],
                tool_use_id=str(b.get("id")),
                tool_name=str(b.get("name")),
                arguments=dict(b.get("input") or {}),
            )
            for b in blocks
            if b.get("type") == "tool_use"
        ]
        return {
            "messages": [{"role": "assistant", "content": blocks}],
            "witnesses": recorded,
            "turn": state["turn"] + 1,
        }

    async def call_tools(state: AgentState) -> dict[str, Any]:
        last = state["messages"][-1]["content"]
        results: list[dict[str, Any]] = []
        for block in last:
            if not (isinstance(block, dict) and block.get("type") == "tool_use"):
                continue
            outcome = await session.call_tool(
                str(block.get("name")), dict(block.get("input") or {})
            )
            parts: list[str] = []
            for chunk in outcome.content:
                if isinstance(chunk, types.TextContent):
                    parts.append(chunk.text)
            text = chr(10).join(parts)
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": str(block.get("id")),
                    "content": [{"type": "text", "text": text}],
                    "is_error": bool(outcome.is_error),
                }
            )
        return {"messages": [{"role": "user", "content": results}], "witnesses": []}

    def route(state: AgentState) -> str:
        if state["turn"] > MAX_TURNS:
            return END
        content = state["messages"][-1].get("content")
        if isinstance(content, list) and any(
            isinstance(b, dict) and b.get("type") == "tool_use" for b in content
        ):
            return "tools"
        return END

    graph: StateGraph[AgentState] = StateGraph(AgentState)
    graph.add_node("model", call_model)
    graph.add_node("tools", call_tools)
    graph.add_edge(START, "model")
    graph.add_conditional_edges("model", route, {"tools": "tools", END: END})
    graph.add_edge("tools", "model")
    return graph.compile()
