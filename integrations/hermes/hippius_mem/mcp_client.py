"""Minimal MCP stdio client for the hippius-mem binary.

The binary's stdio transport is newline-delimited JSON-RPC (the same
framing `hippius-mem/tests/mcp_stdio.rs` speaks), not LSP Content-Length.
This module is stdlib-only so the Hermes directory plugin has no extra
deps.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from typing import Any, TextIO

# Seconds one request may wait for its reply before it fails. A cold
# hippius-mem answers its first recall only after the startup sync, which takes
# tens of seconds on a large team, so this is generous; it exists so a hung
# child fails the Hermes turn instead of blocking it forever.
REQUEST_TIMEOUT = 120.0


class McpError(RuntimeError):
    """JSON-RPC or MCP tool error from the hippius-mem subprocess."""


class McpStdioClient:
    """One JSON-RPC session over a pair of text streams.

    `request` is serialized: prefetch and a background `refresh` can overlap
    at the provider, so the lock keeps request ids and replies paired. A
    reader thread owns `stdout`, so a request waits on a queue with a timeout
    rather than in `readline`, and a broken pipe or a closed stdout becomes
    an `McpError` the provider already handles.
    """

    def __init__(
        self, stdin: TextIO, stdout: TextIO, timeout: float = REQUEST_TIMEOUT
    ) -> None:
        self._stdin = stdin
        self._timeout = timeout
        self._next_id = 1
        self._lock = threading.Lock()
        # Lines from stdout; `None` once it reached EOF (and it stays there).
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(
            target=_read_lines,
            args=(stdout, self._lines),
            name="hippius-mem-stdout",
            daemon=True,
        )
        self._reader.start()

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
        try:
            self._stdin.write(line + "\n")
            self._stdin.flush()
        except (OSError, ValueError) as err:
            # A dead child (BrokenPipeError) or a pipe closed by shutdown.
            raise McpError(f"MCP subprocess stdin is closed: {err}") from err

    def join_reader(self, timeout: float) -> None:
        """Wait up to `timeout` seconds for the stdout reader to reach EOF."""
        self._reader.join(timeout=timeout)

    def _recv_matching(self, msg_id: int) -> dict[str, Any]:
        # Skip notifications (no id) and any other-id replies so a server
        # log line that slipped onto stdout does not desynchronize us —
        # those fail json.loads and are skipped too, up to a bound. The
        # timeout covers the whole wait, not each line, so a child that keeps
        # printing other lines still fails the request in time.
        deadline = time.monotonic() + self._timeout
        for _ in range(32):
            try:
                raw = self._lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise McpError(
                    f"no reply from the MCP subprocess within {self._timeout:g}s"
                ) from None
            if raw is None:
                self._lines.put(None)
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


def _read_lines(stream: TextIO, lines: queue.Queue[str | None]) -> None:
    try:
        for raw in iter(stream.readline, ""):
            lines.put(raw)
    except (OSError, ValueError):
        pass
    lines.put(None)


def _content_text(result: dict[str, Any]) -> str:
    blocks = result.get("content") or []
    parts: list[str] = []
    if isinstance(blocks, list):
        for block in blocks:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
    return "\n".join(parts)
