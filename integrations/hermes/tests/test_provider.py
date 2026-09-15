"""Provider tests against a fake NDJSON MCP child (no live hippius-mem binary)."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hippius_mem import (  # noqa: E402
    BRIEF_TOKEN_BUDGET,
    HippiusMemProvider,
    PREFETCH_K,
    PREFETCH_TOKEN_BUDGET,
)

FAKE_SERVER = Path(__file__).resolve().parent / "fake_mcp_server.py"


class ProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.last_call = self.tmp_path / "last_call.jsonl"
        os.environ["HIPPIUS_MEM_FAKE_LAST_CALL"] = str(self.last_call)

    def tearDown(self) -> None:
        os.environ.pop("HIPPIUS_MEM_FAKE_LAST_CALL", None)
        self.tmp.cleanup()

    def _provider(self) -> HippiusMemProvider:
        launcher = self.tmp_path / "fake-hippius-mem"
        launcher.write_text(
            f"#!{sys.executable}\n"
            "import runpy\n"
            f"runpy.run_path({str(FAKE_SERVER)!r}, run_name='__main__')\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        sidecar = self.tmp_path / "hippius-mem.json"
        sidecar.write_text(
            json.dumps(
                {
                    "binary": str(launcher),
                    "config_path": str(self.tmp_path / "hippius-mem.toml"),
                }
            ),
            encoding="utf-8",
        )
        provider = HippiusMemProvider()
        provider.initialize("sess-1", hermes_home=str(self.tmp_path))
        return provider

    def _last_calls(self) -> list[dict]:
        if not self.last_call.is_file():
            return []
        return [
            json.loads(line)
            for line in self.last_call.read_text(encoding="utf-8").splitlines()
            if line
        ]

    def test_initialize_requires_hermes_home(self) -> None:
        provider = HippiusMemProvider()
        with self.assertRaisesRegex(RuntimeError, "hermes_home"):
            provider.initialize("sess-1")

    def test_initialize_uses_hermes_home_not_home_dot_hermes(self) -> None:
        home = self.tmp_path / "home"
        (home / ".hermes").mkdir(parents=True)
        previous = os.environ.get("HOME")
        os.environ["HOME"] = str(home)
        try:
            provider = self._provider()
            try:
                self.assertEqual(provider._hermes_home, self.tmp_path)
            finally:
                provider.shutdown()
        finally:
            if previous is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = previous

    def test_is_available_is_false_when_binary_missing(self) -> None:
        provider = HippiusMemProvider()
        original = shutil.which

        def _none(_name: str) -> None:
            return None

        shutil.which = _none  # type: ignore[assignment]
        try:
            self.assertFalse(provider.is_available())
        finally:
            shutil.which = original  # type: ignore[assignment]

    def test_prefetch_returns_formatted_recall(self) -> None:
        provider = self._provider()
        try:
            text = provider.prefetch("gateway copy_object")
        finally:
            provider.shutdown()
        self.assertIn("mem_01FAKE", text)
        self.assertIn("CID reference", text)
        call = self._last_calls()[-1]
        self.assertEqual(call["name"], "recall")
        self.assertEqual(call["arguments"]["text"], "gateway copy_object")
        self.assertEqual(call["arguments"]["k"], PREFETCH_K)
        self.assertEqual(call["arguments"]["token_budget"], PREFETCH_TOKEN_BUDGET)

    def test_prefetch_skips_slash_commands(self) -> None:
        provider = self._provider()
        try:
            self.assertEqual(provider.prefetch("/help"), "")
            self.assertEqual(provider.prefetch("   "), "")
        finally:
            provider.shutdown()
        self.assertEqual(self._last_calls(), [])

    def test_system_prompt_block_calls_brief_with_hermes_budget(self) -> None:
        provider = self._provider()
        try:
            block = provider.system_prompt_block()
        finally:
            provider.shutdown()
        self.assertIn("untrusted reference data", block)
        self.assertIn("HERMES_HOME", block)
        call = self._last_calls()[-1]
        self.assertEqual(call["name"], "brief")
        self.assertEqual(call["arguments"]["token_budget"], BRIEF_TOKEN_BUDGET)

    def test_remember_forwards_schema_field_names(self) -> None:
        provider = self._provider()
        try:
            result = provider.handle_tool_call(
                "remember",
                {
                    "note_type": "gotcha",
                    "summary": "copy_object is a CID reference",
                    "body": "not a byte copy",
                },
            )
        finally:
            provider.shutdown()
        parsed = json.loads(result)
        self.assertEqual(parsed["id"], "mem_01NEW")
        call = self._last_calls()[-1]
        self.assertEqual(call["name"], "remember")
        self.assertEqual(call["arguments"]["note_type"], "gotcha")
        self.assertNotIn("query", call["arguments"])
        self.assertNotIn("kind", call["arguments"])

    def test_get_tool_schemas_use_text_and_note_type(self) -> None:
        schemas = {item["name"]: item for item in HippiusMemProvider().get_tool_schemas()}
        self.assertIn("text", schemas["recall"]["parameters"]["properties"])
        self.assertNotIn("query", schemas["recall"]["parameters"]["properties"])
        self.assertIn("note_type", schemas["remember"]["parameters"]["properties"])
        self.assertNotIn("kind", schemas["remember"]["parameters"]["properties"])

    def test_prefetch_budget_constants(self) -> None:
        self.assertEqual(PREFETCH_K, 6)
        self.assertEqual(PREFETCH_TOKEN_BUDGET, 400)
        self.assertEqual(BRIEF_TOKEN_BUDGET, 350)


if __name__ == "__main__":
    unittest.main()
