"""Unit tests for the NDJSON MCP stdio client."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hippius_mem.mcp_client import McpError, McpStdioClient


class McpClientTests(unittest.TestCase):
    def test_handshake_then_skips_a_log_line_before_the_matching_reply(self) -> None:
        init_reply = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"serverInfo": {"name": "hippius-mem"}},
            }
        )
        stdout = io.StringIO("not json\n" + init_reply + "\n")
        stdin = io.StringIO()
        client = McpStdioClient(stdin, stdout)
        result = client.handshake()
        self.assertEqual(result["serverInfo"]["name"], "hippius-mem")
        written = stdin.getvalue().splitlines()
        self.assertEqual(json.loads(written[0])["method"], "initialize")
        self.assertEqual(json.loads(written[1])["method"], "notifications/initialized")

    def test_a_child_that_never_answers_fails_the_request(self) -> None:
        # The reply never comes: readline used to block the turn forever.
        read_end, write_end = os.pipe()
        stdout = os.fdopen(read_end, "r")
        try:
            client = McpStdioClient(io.StringIO(), stdout, timeout=0.2)
            with self.assertRaisesRegex(McpError, "no reply"):
                client.request("initialize", {})
        finally:
            os.close(write_end)
            stdout.close()

    def test_a_dead_childs_stdin_is_an_mcp_error(self) -> None:
        # A BrokenPipeError used to reach the Hermes turn, which catches only
        # McpError.
        class Broken(io.StringIO):
            def write(self, _text: str) -> int:
                raise BrokenPipeError(32, "Broken pipe")

        client = McpStdioClient(Broken(), io.StringIO(""))
        with self.assertRaisesRegex(McpError, "stdin is closed"):
            client.call_tool("recall", {"text": "x"})

    def test_call_tool_forwards_arguments_and_returns_text(self) -> None:
        replies = [
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"serverInfo": {"name": "t"}},
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [{"type": "text", "text": '{"id":"mem_01"}'}],
                        "isError": False,
                    },
                }
            ),
        ]
        stdout = io.StringIO("\n".join(replies) + "\n")
        stdin = io.StringIO()
        client = McpStdioClient(stdin, stdout)
        client.handshake()
        text = client.call_tool(
            "remember",
            {"note_type": "gotcha", "summary": "s", "body": "b"},
        )
        self.assertEqual(text, '{"id":"mem_01"}')
        call = json.loads(stdin.getvalue().splitlines()[-1])
        self.assertEqual(call["method"], "tools/call")
        self.assertEqual(call["params"]["name"], "remember")
        self.assertEqual(call["params"]["arguments"]["note_type"], "gotcha")

    def test_call_tool_raises_on_is_error(self) -> None:
        replies = [
            json.dumps(
                {"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "t"}}}
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "result": {
                        "content": [{"type": "text", "text": "boom"}],
                        "isError": True,
                    },
                }
            ),
        ]
        client = McpStdioClient(io.StringIO(), io.StringIO("\n".join(replies) + "\n"))
        client.handshake()
        with self.assertRaisesRegex(McpError, "boom"):
            client.call_tool("recall", {"text": "q"})


if __name__ == "__main__":
    unittest.main()
