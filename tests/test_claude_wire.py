"""Checks the real Anthropic SDK path end to end against a local fake API server (no key, no network).

This proves the request we send is well-formed (model, effort, fallbacks, caching, strict tools) and that
the loop handles the SDK's own response objects.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sathi.agent import AgentSession, ClaudeLLM

RESPONSES = [
    {"content": [{"type": "text", "text": "Checking."},
                 {"type": "tool_use", "id": "toolu_01", "name": "get_balances", "input": {}}],
     "stop_reason": "tool_use"},
    {"content": [{"type": "text", "text": "You have BDT 480,000.00."}], "stop_reason": "end_turn"},
]


@pytest.fixture
def fake_api(monkeypatch):
    seen = []
    queue = list(RESPONSES)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
            r = queue.pop(0)
            payload = {"id": f"msg_{len(seen)}", "type": "message", "role": "assistant", "model": body["model"],
                       "content": r["content"], "stop_reason": r["stop_reason"], "stop_sequence": None,
                       "usage": {"input_tokens": 1200, "output_tokens": 40, "cache_read_input_tokens": 900,
                                 "cache_creation_input_tokens": 0}}
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    yield f"http://127.0.0.1:{server.server_port}", seen
    server.shutdown()


def test_real_sdk_request_shape_and_loop(sb, fake_api):
    import anthropic

    base_url, seen = fake_api
    client = anthropic.Anthropic(api_key="test-key", base_url=base_url, max_retries=0)
    session = AgentSession(sb, "nusrat", ClaudeLLM(client=client, effort="medium"))
    turn = session.send("How much money do I have?")

    assert "BDT 480,000.00" in turn.text
    assert [c["name"] for c in turn.tool_calls] == ["get_balances"]
    assert session.usage["cache_read_input_tokens"] == 1800

    first = seen[0]
    assert first["path"].startswith("/v1/messages")
    assert "server-side-fallback-2026-07-01" in first["headers"].get("anthropic-beta", "")
    body = first["body"]
    assert body["model"] == "claude-opus-5-5"
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {"effort": "medium"}
    assert body["cache_control"] == {"type": "ephemeral"}
    assert "thinking" not in body  # always on for this model; sending "disabled" would be a 400
    assert all(t["strict"] is True and t["input_schema"]["additionalProperties"] is False for t in body["tools"])

    second = seen[1]["body"]["messages"]
    assert second[1]["role"] == "assistant" and second[1]["content"][1]["type"] == "tool_use"
    assert second[2]["content"][0]["type"] == "tool_result" and second[2]["content"][0]["tool_use_id"] == "toolu_01"
