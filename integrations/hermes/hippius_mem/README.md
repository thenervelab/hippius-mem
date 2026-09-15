# hippius-mem Hermes memory provider

Encrypted, team-owned memory on Hippius, wired as a Hermes **memory provider**
(not an MCP server). Prefetch before every model call is `recall`. The session
brief is the team's live conventions and gotchas. The agent writes with the
`remember` tool — conversation turns are not auto-extracted.

## Setup

```sh
hippius-mem install --agent hermes
```

That copies this plugin into `$HERMES_HOME/plugins/hippius-mem/`, writes
`$HERMES_HOME/hippius-mem.json` (absolute binary + `HIPPIUS_MEM_CONFIG`), and
sets `memory.provider: hippius-mem` in `$HERMES_HOME/config.yaml`.

Honours `HERMES_HOME`. Multi-agent hosts:

```sh
hippius-mem install --agent hermes --hermes-profile ops
hippius-mem install --agent hermes --hermes-all-profiles
```

If another memory provider is already active, install refuses rather than
clobbering it. Switch explicitly:

```sh
hermes config set memory.provider hippius-mem
```

## What it does not do

- It does **not** register `mcp_servers.hippius-mem`. Hermes already budgets
  built-in memory tightly; the 10-tool MCP schema would blow that.
- It does **not** auto-`remember` each turn. Durable team facts only.
- It does **not** share one `author_seed_hex` across a fleet. Each host
  `join --bundle`s its own invite (or `invite --count N` from the founder).

## Runtime cost

One `hippius-mem` subprocess per Hermes session, ~205 MB RSS with the
embeddings build (the ONNX model). Cron jobs and subagents each pay that
again; there is no shared daemon in this version.

## Tools

| Tool | Parameters |
|---|---|
| `remember` | `note_type`, `summary`, `body` (optional `repo`, `tags`, `force`) |
| `recall` | `text` (optional `k`, `repo`) |
| `get` | `id` |
