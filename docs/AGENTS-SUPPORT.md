# Agent support matrix

hippius-mem's recall/remember loop is delivered through three layers: instruction
text (the mandates block), Claude Code hooks, and the MCP tool surface itself.
Which layers an agent gets depends on what it reads and how it connects. This page
is the truth table.

`hippius-mem init` writes a marker-delimited mandates block into two files at the
repo root:

- `CLAUDE.md` — read natively by Claude Code.
- `AGENTS.md` — read by convention by other agents (Cursor, Codex CLI, opencode,
  and most AGENTS.md-aware tools). This variant adds a hook-scope preamble: the
  hooks run under Claude Code — and under Grok, via the committed shim described
  below — while for any other client the mandates are honor-system.

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

## Truth table

| Capability | Claude Code | AGENTS.md-reading agent via MCP | Bare MCP client |
|---|---|---|---|
| Mandates text in context | yes (`CLAUDE.md`) | yes (`AGENTS.md`, with honor-system preamble) | no |
| Recall edit-gate (PreToolUse blocks first edit until a recall token exists) | yes | no | no |
| Recall token writer (PostToolUse on `recall`) | yes | no | no |
| Remember nudge (Stop hook, once per session) | yes | no | no |
| Seed nudge (SessionStart, points at pre-existing `CLAUDE.md`/`AGENTS.md`/`MEMORY.md` knowledge) | yes | no | no |
| Session brief (SessionStart injects a digest of live team memory) | yes | no | no |
| MCP tools (`recall`, `remember`, `get`, ...) | yes | yes | yes |
| Enforcement model | mechanical (hooks) + text | text only (honor system) | tool descriptions only |

> [!NOTE]
> **Grok is the exception in the middle column.** Grok reads `AGENTS.md` *and*
> shares `.claude/settings.json`, resolving each hook command relative to that
> file — which the committed `.claude/.claude/hooks → ../hooks` shim (a Unix
> symlink `init` plants and boot re-plants when it drifts) makes land on the real
> scripts. A Grok session in a provisioned repo therefore gets the same hook
> wiring as Claude Code, not the honor-system floor.

## What the degraded modes mean in practice

**AGENTS.md-reading agents (Cursor, Codex CLI, generic AGENTS.md-aware tools).**
The mandates text is the entire floor. Nothing blocks the agent's first edit if it
skipped `recall`, nothing prompts it to `remember` at session end, nothing points
it at seedable pre-existing knowledge, and no ambient brief of team memory is
injected at session start — the agent starts cold and must pull-recall. An agent
that follows instructions well will still run the loop, because the block tells it
to; an agent that ignores instructions loses the loop silently. Expect
lower recall discipline from these sessions and review their output accordingly.

**Bare MCP clients (read neither `CLAUDE.md` nor `AGENTS.md`).** The only steering
is the MCP tool descriptions themselves, which say to recall before acting and to
remember durable facts. There is no repo-level mandate in context at all, so
whether the loop happens depends entirely on the client's own prompting. Team
memory still works as a queryable store; it just is not self-enforcing.

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
Claude Code. For semantic (paraphrase-matching) recall, point the entry at a
binary built with `--features embeddings`; a lean build ranks lexically.

There is deliberately no user-global `AGENTS.md`: no cross-agent convention for
one exists (Codex uses `~/.codex/AGENTS.md`, other tools use their own private
directories, and the agents.md spec has only an open proposal for
`~/.config/agents/AGENTS.md`), so `install` provisions `~/.claude/CLAUDE.md` only
and AGENTS.md support stays repo-level.

This page is linked from the [README docs index](../README.md#documentation) and
from [Reference § What init and install write](REFERENCE.md#install-details).
