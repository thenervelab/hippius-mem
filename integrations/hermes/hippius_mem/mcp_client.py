"""Minimal MCP stdio client for the hippius-mem binary.

The binary's stdio transport is newline-delimited JSON-RPC (the same
framing `hippius-mem/tests/mcp_stdio.rs` speaks), not LSP Content-Length.
This module is stdlib-only so the Hermes directory plugin has no extra
deps.
"""

from __future__ import annotations

import json
import threading
from typing import Any, TextIO


class McpError(RuntimeError):
    """JSON-RPC or MCP tool error from the hippius-mem subprocess."""


class McpStdioClient:
    """One JSON-RPC session over a pair of text streams.

    `request` is serialized: prefetch and a background `refresh` can overlap
    at the provider, so the lock keeps request ids and replies paired.
    """

    def __init__(self, stdin: TextIO, stdout: TextIO) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._next_id = 1
        self._lock = threading.Lock()

    def handshake(self, client_name: str = "hippius-mem-hermes") -> dict[str, Any]:
        """MCP `initialize` + `notifications/initialized`."""
        result = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "0.1.0"},
            },
        )
        self.notify("notifications/initialized")
        return result

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        """`tools/call`. Returns concatenated `content[].text`.

        Raises [`McpError`] if the reply is a JSON-RPC error or `isError`.
        """
        result = self.request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )
        if result.get("isError"):
            raise McpError(_content_text(result) or f"{name} returned isError")
        return _content_text(result)

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            msg_id = self._next_id
            self._next_id += 1
            payload: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params
            self._send(payload)
            reply = self._recv_matching(msg_id)
        if "error" in reply:
            raise McpError(str(reply["error"]))
        result = reply.get("result")
        if not isinstance(result, dict):
            raise McpError(f"{method} reply missing result object: {reply!r}")
        return result

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        with self._lock:
            self._send(payload)

    def _send(self, payload: dict[str, Any]) -> None:
        line = json.dumps(payload, separators=(",", ":"))
        self._stdin.write(line + "\n")
        self._stdin.flush()

    def _recv_matching(self, msg_id: int) -> dict[str, Any]:
        # Skip notifications (no id) and any other-id replies so a server
        # log line that slipped onto stdout does not desynchronize us —
        # those fail json.loads and are skipped too, up to a bound.
        for _ in range(32):
            raw = self._stdout.readline()
            if raw == "":
                raise McpError("MCP subprocess closed stdout")
            try:
                reply = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(reply, dict):
                continue
            if reply.get("id") == msg_id:
                return reply
        raise McpError(f"no JSON-RPC reply with id {msg_id}")


def _content_text(result: dict[str, Any]) -> str:
    blocks = result.get("content") or []
    parts: list[str] = []
    if isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
    return "\n".join(parts)
