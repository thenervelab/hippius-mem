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

`hippius-mem install` autodetects: Claude plus every local client whose product
directory already exists. Name a subset with `--agent`. `--all-detected` is
that default spelled out.

```sh
hippius-mem install                       # Claude + any of ~/.grok ~/.codex
                                          # ~/.gemini ~/.hermes ~/.openclaw
                                          # that already exist
hippius-mem install --agent grok,codex    # those two only
hippius-mem install --agent claude        # Claude Code only
```

Detection is **directory presence**, never PATH: a machine that has never run
Codex does not get a `~/.codex` invented for it.

Every adapter writes the same payload, format-translated: the absolute binary
path, no args, and `HIPPIUS_MEM_CONFIG` pinned to the absolute config path. That
pin is required — on macOS the binary does not find
`~/.config/hippius-mem/hippius-mem.toml` from an arbitrary cwd.

| Client | Config file written | Notes |
|---|---|---|
| Claude Code | `~/.claude.json` `mcpServers` | Also writes `~/.claude/CLAUDE.md` |
| Grok Build | `~/.grok/config.toml` `[mcp_servers.hippius-mem]` | Also loads `~/.claude.json` via Claude compat; native write still pins the path |
| Codex CLI | `~/.codex/config.toml` `[mcp_servers.hippius-mem]` | |
| Gemini CLI | `~/.gemini/settings.json` `mcpServers` | Confirm this machine still uses Gemini CLI, not Antigravity, before relying on this path |
| Hermes | `~/.hermes/config.yaml` `mcp_servers` | Block-style YAML only; a flow `{ ... }` mapping is refused. Do not put mandates in `SOUL.md` |
| OpenClaw | `~/.openclaw/openclaw.json` `mcp.servers` | Messaging gateway; honor-system + MCP, no edit-gate |
| Grok Bot | none | Cloud VM; local stdio cannot run there. See [Grok Bot](#grok-bot) |

There is deliberately no user-global `AGENTS.md`: no cross-agent convention for
one exists (Codex uses `~/.codex/AGENTS.md`, other tools use their own private
directories, and the agents.md spec has only an open proposal for
`~/.config/agents/AGENTS.md`), so `install` never writes those files.

## Truth table

| Capability | Claude Code | Grok Build | Codex / Gemini / Hermes | OpenClaw | Bare MCP / Grok Bot |
|---|---|---|---|---|---|
| Mandates text in context | yes (`CLAUDE.md`) | yes (`AGENTS.md` + `CLAUDE.md`) | yes (`AGENTS.md`, honor-system preamble) | yes if the workspace has `AGENTS.md` | no |
| Recall edit-gate | yes | yes (committed `.claude/.claude/hooks` shim + dual matcher) | no | no | no |
| Recall token writer | yes (`mcp__hippius-mem__recall`) | yes (`hippius-mem__recall` **or** the Claude name) | no | no | no |
| Remember nudge / seed / brief | yes | yes, via the same hook scripts | no | no | no |
| MCP tools | yes | yes | yes, once `install` has seen their config dir (or `--agent`) | yes, once registered | only if the operator pasted a config |
| Enforcement model | mechanical + text | mechanical when hooks load; text otherwise | text only | text only | tool descriptions only |

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

**AGENTS.md-reading agents (Cursor, Codex CLI, Hermes, generic AGENTS.md-aware
tools — Grok excepted, see the note above).** The mandates text is the entire
floor. Nothing blocks the agent's first edit if it skipped `recall`, nothing
prompts it to `remember` at session end, nothing points it at seedable
pre-existing knowledge, and no ambient brief of team memory is injected at
session start — the agent starts cold and must pull-recall. An agent that
follows instructions well will still run the loop, because the block tells it
to; an agent that ignores instructions loses the loop silently. Expect lower
recall discipline from these sessions and review their output accordingly.

**Bare MCP clients (read neither `CLAUDE.md` nor `AGENTS.md`).** The only
steering is the MCP tool descriptions themselves, which say to recall before
acting and to remember durable facts. There is no repo-level mandate in context
at all, so whether the loop happens depends entirely on the client's own
prompting. Team memory still works as a queryable store; it just is not
self-enforcing.

## Concurrent writers

User-global MCP registration means two agent sessions (Claude and Grok, two
Codex windows, …) routinely spawn two `hippius-mem` processes under **one
identity**. On `storage = "s3"` those writers are unserialized: the local-vault
advisory lock covers `storage = "local"` only. Concurrent head PUTs can fork the
op chain and permanently drop the losing branch, which later shows up as a
`reconcile` `head_regressions` entry against the operator's own key. One
identity, one writer at a time — or accept possible branch loss.

## Wiring the server into a generic MCP client

The server speaks MCP over stdio. Any client that can launch a stdio server can
use it — configure the command as the absolute path to the binary with no
arguments, and pin the config path in the environment (a stdio server has no
predictable cwd to resolve the default relative `hippius-mem.toml` against):

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
If the Bot UI later accepts a custom remote MCP URL, run a separately designed
HTTP front (this binary is stdio-only today) and treat that as its own threat
model. Until then, Grok Bot is document-only.

This page is linked from the [README docs index](../README.md#documentation) and
from [Reference § What init and install write](REFERENCE.md#install-details).
