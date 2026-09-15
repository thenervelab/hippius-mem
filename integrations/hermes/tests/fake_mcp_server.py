"""NDJSON MCP stub used by the Hermes provider tests.

Speaks the same newline-delimited JSON-RPC the hippius-mem binary uses.
When `HIPPIUS_MEM_FAKE_LAST_CALL` is set, each `tools/call` is appended as
one JSON line so tests can assert parameter names.
"""

from __future__ import annotations

import json
import os
import sys


RECALL_PAYLOAD = {
    "pointers": [
        {
            "id": "mem_01FAKE",
            "summary": "Hippius copy_object is a CID reference, not a byte copy",
            "score": 0.91,
            "repo": "global",
        }
    ],
    "returned": 1,
    "total_matched": 1,
    "semantic": True,
}

BRIEF_PAYLOAD = {
    "brief": "# Team memory brief\n\n- honour HERMES_HOME when wiring the adapter\n"
}

REMEMBER_PAYLOAD = {"id": "mem_01NEW"}
GET_PAYLOAD = {
    "id": "mem_01FAKE",
    "summary": "Hippius copy_object is a CID reference, not a byte copy",
    "body": "the body",
    "version": "abc",
}
REFRESH_PAYLOAD = {"indexed": 1}


def _ok(msg_id: object, payload: object) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "isError": False,
        },
    }


def main() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            reply = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-hippius-mem", "version": "0"},
                },
            }
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
            continue
        if method == "notifications/initialized":
            continue
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            last_path = os.environ.get("HIPPIUS_MEM_FAKE_LAST_CALL")
            if last_path:
                with open(last_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"name": name, "arguments": arguments}) + "\n")
            if name == "recall":
                reply = _ok(msg_id, RECALL_PAYLOAD)
            elif name == "brief":
                reply = _ok(msg_id, BRIEF_PAYLOAD)
            elif name == "remember":
                reply = _ok(msg_id, REMEMBER_PAYLOAD)
            elif name == "get":
                reply = _ok(msg_id, GET_PAYLOAD)
            elif name == "refresh":
                reply = _ok(msg_id, REFRESH_PAYLOAD)
            else:
                reply = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"unknown tool {name}"},
                }
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
