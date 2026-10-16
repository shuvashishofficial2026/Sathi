"""LLM backends: Claude for real runs, a scripted stand-in for offline tests."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "claude-opus-5-5"


class ClaudeLLM:
    """Claude through the official Anthropic SDK.

    - Effort is set explicitly (Claude Opus 5.5 defaults to medium; thinking is always on).
    - Server-side fallbacks are on: if a request is declined by a safety classifier, the API
      retries it on Anthropic's recommended fallback model in the same call.
    - The system prompt and tools are stable, so automatic prompt caching cuts repeat cost.
    """

    def __init__(self, model: str | None = None, effort: str | None = None, max_tokens: int = 16000,
                 fallbacks: bool = True, client=None):
        import anthropic

        self.client = client or anthropic.Anthropic()
        self.model = model or os.environ.get("SATHI_MODEL", DEFAULT_MODEL)
        self.effort = effort or os.environ.get("SATHI_EFFORT", "medium")
        self.max_tokens = max_tokens
        self.fallbacks = fallbacks

    def create(self, system: str, tools: list[dict], messages: list):
        kwargs = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            tools=tools,
            messages=messages,
            output_config={"effort": self.effort},
            cache_control={"type": "ephemeral"},
        )
        if self.fallbacks:
            return self.client.beta.messages.create(
                betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs
            )
        return self.client.beta.messages.create(**kwargs)


# ---------------------------------------------------------------- offline stand-in

@dataclass
class Block:
    type: str
    text: str = ""
    id: str = ""
    name: str = ""
    input: dict = field(default_factory=dict)


@dataclass
class Response:
    content: list
    stop_reason: str
    usage: object = None
    stop_details: object = None


class ScriptContext:
    """What a scripted step can look at: earlier tool results in the conversation."""

    def __init__(self, messages: list):
        self.names: dict[str, str] = {}
        self.results: list[tuple[str, dict]] = []
        for m in messages:
            content = m["content"] if isinstance(m["content"], list) else []
            for b in content:
                btype = b.get("type") if isinstance(b, dict) else getattr(b, "type", None)
                if btype == "tool_use":
                    self.names[getattr(b, "id", None) or b.get("id")] = getattr(b, "name", None) or b.get("name")
                elif btype == "tool_result":
                    name = self.names.get(b["tool_use_id"], "?")
                    try:
                        self.results.append((name, json.loads(b["content"])))
                    except (TypeError, ValueError):
                        self.results.append((name, {"raw": b["content"]}))

    def last(self, tool_name: str):
        for name, result in reversed(self.results):
            if name == tool_name:
                return result
        raise LookupError(f"no earlier result from {tool_name}")


class ScriptedLLM:
    """Plays back a fixed script instead of calling Claude.

    Each step is a list of ("text", "...") or ("tool", name, input) items. A text or an input can be a
    function of ScriptContext, to reuse ids and numbers from earlier tool results. Used to test the loop,
    to simulate a hijacked model in red-team tests, and for the app's offline demo, all without an API key.
    """

    def __init__(self, steps: list[list[tuple]], done_text: str = "(script finished)"):
        self.steps = list(steps)
        self.done_text = done_text
        self.calls = 0

    def create(self, system: str, tools: list[dict], messages: list):
        if not self.steps:
            return Response([Block("text", text=self.done_text)], "end_turn")
        step = self.steps.pop(0)
        ctx = ScriptContext(messages)
        blocks = []
        for item in step:
            if item[0] == "text":
                blocks.append(Block("text", text=item[1](ctx) if callable(item[1]) else item[1]))
            else:
                _, name, tool_input = item
                if callable(tool_input):
                    tool_input = tool_input(ctx)
                self.calls += 1
                blocks.append(Block("tool_use", id=f"toolu_{self.calls:03d}", name=name, input=tool_input))
        stop = "tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn"
        return Response(blocks, stop)
