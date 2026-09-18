# Agent support matrix

hippius-mem's recall/remember loop is delivered through three layers: instruction
text (the mandates block), Claude Code hooks, and the MCP tool surface itself.
Which layers an agent gets depends on what it reads and how it connects. This page
is the truth table.

`hippius-mem init` writes a marker-delimited mandates block into two files at the
repo root:

- `CLAUDE.md` — read natively by Claude Code (and by Grok Build, which also
  loads `AGENTS.md`).
- `AGENTS.md` — read by convention by other agents (Cursor, Codex CLI, opencode,
  Hermes, OpenClaw, and most AGENTS.md-aware tools). This variant adds a
  hook-scope preamble: the hooks run under Claude Code — and under Grok, via
  the committed shim described below — while for any other client the mandates
  are honor-system.

Both blocks are idempotent (re-running `init` is byte-identical), preserve any
user content outside the `<!-- hippius-mem:start/end -->` markers, refuse to
silently rewrite a git-tracked, clean file (`--allow-overwrite-tracked` opts in),
are refreshed best-effort on server boot (`AGENTS.md` for any client;
`CLAUDE.md` only when Claude Code is the active agent), and are removed by
`init --uninstall`. Boot does more than refresh the blocks: it repairs broken
hook pairs additively, skips a `$HOME` repo root outright, nudges when the launch
repo is un-provisioned, and — under `auto_init = true` — provisions it, behind
conservative guards. The full boot behavior is in
[Reference § Install details](REFERENCE.md#install-details).

## Installing the MCP server per agent

`hippius-mem install` requires `--agent` or `--all-detected`. A bare
`install` prompts on a TTY and refuses otherwise — it will not silently
rewrite every local client's config. `--all-detected` is Claude plus every
local client whose product directory already exists.

```sh
hippius-mem install --all-detected        # Claude + any of ~/.grok ~/.codex
                                          # ~/.gemini ~/.hermes ~/.openclaw
                                          # that already exist
hippius-mem install --agent grok,codex    # those two only
hippius-mem install --agent claude        # Claude Code only
hippius-mem install --agent hermes        # Hermes memory provider (not MCP)
```

Detection is **directory presence**, never PATH: a machine that has never run
Codex does not get a `~/.codex` invented for it.

On an embeddings+`http-mcp` build (the shipped binary), Claude / Grok / Codex
are pointed at a **loopback streamable-HTTP** daemon (`hippius-mem serve`,
`http://127.0.0.1:17432/mcp`) so N sessions share one process and one ONNX
load — but only when that is sound. The daemon is one process for every HTTP
client and cannot route per repo, so `install` starts it only for a **single
catch-all S3 profile**. A second `[[teams]]` entry, an org-routed sole
profile, or a `storage = "local"` trial vault (whose exclusive write role a
never-exiting service would hold for good) keeps those clients on stdio.
`install` starts the user service and waits for `/health` before rewriting
configs; a start failure leaves stdio entries. Uninstalling one HTTP client
leaves the daemon running for the others. Client configs that embed the
bearer token are written `0600`. Gemini and OpenClaw stay on stdio (one child
per session). Hermes is a memory-provider plugin, not MCP. Bare
`hippius-mem` is still the stdio server.

A lean / no-`http-mcp` build keeps the previous payload for every adapter:
the absolute binary path, no args, and `HIPPIUS_MEM_CONFIG` pinned to the
absolute config path. That pin is required — on macOS the binary does not find
`~/.config/hippius-mem/hippius-mem.toml` from an arbitrary cwd.

| Client | Config file written | Notes |
|---|---|---|
| Claude Code | `~/.claude.json` `mcpServers` | HTTP `url` on http-mcp builds; also writes `~/.claude/CLAUDE.md` |
| Grok Build | `~/.grok/config.toml` `[mcp_servers.hippius-mem]` | HTTP `url` on http-mcp builds. Also loads `~/.claude.json` via Claude compat |
| Codex CLI | `~/.codex/config.toml` `[mcp_servers.hippius-mem]` | HTTP `url` on http-mcp builds |
| Gemini CLI | `~/.gemini/settings.json` `mcpServers` | Confirm this machine still uses Gemini CLI, not Antigravity, before relying on this path |
| Hermes | `$HERMES_HOME/plugins/hippius-mem/` + `memory.provider` | Memory-provider plugin, not MCP. Honours `HERMES_HOME` and `--hermes-profile`. Block-style YAML only; a flow `{ ... }` mapping is refused. Do not put mandates in `SOUL.md` |
| OpenClaw | `~/.openclaw/openclaw.json` `mcp.servers` | Messaging gateway; honor-system + MCP, no edit-gate |
| Grok Bot | none | Cloud VM; local stdio cannot run there. See [Grok Bot](#grok-bot) |

There is deliberately no user-global `AGENTS.md`: no cross-agent convention for
one exists (Codex uses `~/.codex/AGENTS.md`, other tools use their own private
directories, and the agents.md spec has only an open proposal for
`~/.config/agents/AGENTS.md`), so `install` never writes those files.

## Truth table

| Capability | Claude Code | Grok Build | Codex / Gemini | Hermes | OpenClaw | Bare MCP / Grok Bot |
|---|---|---|---|---|---|---|
| Mandates text in context | yes (`CLAUDE.md`) | yes (`AGENTS.md` + `CLAUDE.md`) | yes (`AGENTS.md`, honor-system preamble) | no (cwd is often `$HOME`; plugin injects the brief) | yes if the workspace has `AGENTS.md` | no |
| Recall edit-gate | yes | yes (committed `.claude/.claude/hooks` shim + dual matcher) | no | n/a (prefetch before every model call) | no | no |
| Recall token writer | yes (`mcp__hippius-mem__recall`) | yes (`hippius-mem__recall` **or** the Claude name) | no | `prefetch` → `recall` | no | no |
| Remember nudge / seed / brief | yes | yes, via the same hook scripts | no | `system_prompt_block` → `brief`; `remember` tool | no | no |
| MCP tools | yes | yes | yes, once `install --agent` (or `--all-detected`) has seen their config dir | no (memory provider; slim `remember`/`recall`/`get` tools) | yes, once registered | only if the operator pasted a config |
| Enforcement model | mechanical + text | mechanical when hooks load; text otherwise | text only | mechanical (provider prefetch) | text only | tool descriptions only |

> [!NOTE]
> **Why Grok is different.** Grok reads `AGENTS.md` *and* shares
> `.claude/settings.json`, resolving each hook command relative to that file —
> which the committed `.claude/.claude/hooks → ../hooks` shim (a Unix symlink
> `init` plants) makes land on the real scripts. The hook scripts accept both
> Claude's snake_case envelope (`tool_name`) and Grok's camelCase (`toolName`),
> and the PostToolUse matcher lists both `mcp__hippius-mem__recall` and
> `hippius-mem__recall`. Without the second name, a repo provisioned only for
> Claude can **block Grok edits forever** (the gate fires via the Edit alias,
> the token writer never does). Caveats: boot's hook-pair repair (including
> re-planting a drifted shim) runs only in Claude Code sessions, so a Grok-only
> repo restores a lost shim by re-running `hippius-mem init`; and on Windows no
> shim exists (it is a symlink).

## What the degraded modes mean in practice

**AGENTS.md-reading agents (Cursor, Codex CLI, generic AGENTS.md-aware
tools — Grok and Hermes excepted).** The mandates text is the entire
floor. Nothing blocks the agent's first edit if it skipped `recall`, nothing
prompts it to `remember` at session end, nothing points it at seedable
pre-existing knowledge, and no ambient brief of team memory is injected at
session start — the agent starts cold and must pull-recall. An agent that
follows instructions well will still run the loop, because the block tells it
to; an agent that ignores instructions loses the loop silently. Expect lower
recall discipline from these sessions and review their output accordingly.

**Hermes.** After `install --agent hermes`, the loop is mechanical: `prefetch`
runs `recall` before every model call, `system_prompt_block` injects the
session brief, and the agent writes with the `remember` tool. No `AGENTS.md`
and no hooks. Conversation turns are not auto-remembered. Restart Hermes after
install — the plugin loads on the next process. `doctor --offline` fails if
Hermes is present but unwired.

**Bare MCP clients (read neither `CLAUDE.md` nor `AGENTS.md`).** The only
steering is the MCP tool descriptions themselves, which say to recall before
acting and to remember durable facts. There is no repo-level mandate in context
at all, so whether the loop happens depends entirely on the client's own
prompting. Team memory still works as a queryable store; it just is not
self-enforcing.

## Concurrent writers

On an `http-mcp` build, Claude / Grok / Codex share one `hippius-mem serve`
process, so they no longer fork the op chain against each other. Gemini,
OpenClaw, Hermes, a lean (no-`http-mcp`) build, and any client still on stdio
still spawn **one process per session**. Two of those under **one identity**
on `storage = "s3"` are unserialized: the local-vault advisory lock covers
`storage = "local"` only. Concurrent head PUTs can fork the op chain and
permanently drop the losing branch, which later shows up as a `reconcile`
`head_regressions` entry against the operator's own key. Two machines remain
unserialized either way. One identity, one writer at a time — or accept
possible branch loss.

## Wiring the server into a generic MCP client

The server speaks MCP over stdio **or** loopback streamable HTTP. Prefer HTTP
when the client supports it and `hippius-mem serve` is running, so sessions
share one process:

Grok (`~/.grok/config.toml`):

```toml
[mcp_servers.hippius-mem]
url = "http://127.0.0.1:17432/mcp"

[mcp_servers.hippius-mem.headers]
Authorization = "Bearer <contents of ~/.config/hippius-mem/mcp-token>"
```

Codex (`~/.codex/config.toml`) uses `http_headers`, not `headers` — the latter is ignored and the daemon 401s:

```toml
[mcp_servers.hippius-mem]
url = "http://127.0.0.1:17432/mcp"

[mcp_servers.hippius-mem.http_headers]
Authorization = "Bearer <contents of ~/.config/hippius-mem/mcp-token>"
```

Any client that can only launch a stdio server can still use the bare binary —
configure the command as the absolute path with no arguments, and pin the
config path in the environment (a stdio server has no predictable cwd to
resolve the default relative `hippius-mem.toml` against):

```json
{
  "mcpServers": {
    "hippius-mem": {
      "command": "/absolute/path/to/hippius-mem",
      "args": [],
      "env": {
        "HIPPIUS_MEM_CONFIG": "/absolute/path/to/hippius-mem.toml"
      }
    }
  }
}
```

This is the same entry `hippius-mem install` writes into `~/.claude.json` for
Claude Code. Grok and Codex take the TOML equivalent:

```toml
[mcp_servers.hippius-mem]
command = "/absolute/path/to/hippius-mem"
args = []

[mcp_servers.hippius-mem.env]
HIPPIUS_MEM_CONFIG = "/absolute/path/to/hippius-mem.toml"
```

For semantic (paraphrase-matching) recall, point the entry at a binary built
with `--features embeddings`; a lean build ranks lexically.

## Grok Bot

Grok Bot is a persistent **cloud computer**, not a local CLI. `~/.claude.json`
and a stdio `hippius-mem` do not exist on that VM. There is no adapter for it.
If the Bot UI later accepts a custom remote MCP URL, that is a different
threat model from the loopback `hippius-mem serve` daemon (which binds
127.0.0.1 only). Until then, Grok Bot is document-only.

A coding agent installing hippius-mem for a user should follow
[FOR-AGENTS.md](../FOR-AGENTS.md), not this page. This page is the truth table
of what each client gets *after* install.

This page is linked from the [README docs index](../README.md#documentation) and
from [Reference § What init and install write](REFERENCE.md#install-details).
