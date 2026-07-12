<div align="center">

# 🧠 Hippius Memory

### Long-term memory for your team's AI coding agents.

**Every agent, on every machine, shares one encrypted memory — so a lesson learned once is never learned twice.**

[![Rust](https://img.shields.io/badge/Rust-1.95-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Protocol](https://img.shields.io/badge/MCP-stdio_server-6E56CF)](https://modelcontextprotocol.io/)
[![Encryption](https://img.shields.io/badge/encryption-XChaCha20--Poly1305-2EA043)](docs/REFERENCE.md#configuration)
[![Audit](https://img.shields.io/badge/audit-signed_op--log_%2B_Merkle-blue)](docs/SECURITY.md#phase-2--shared-op-log-convergence-and-verifiable-history)
[![Status](https://img.shields.io/badge/phase_4-done_(except_ANN)-success)](docs/REFERENCE.md#scope-by-phase)

```sh
git clone https://github.com/thenervelab/hippius-mem
cd hippius-mem && sh scripts/install.sh
```

</div>

---

AI coding agents start every session from zero. They forget the decision you made last
week, the gotcha that cost you an afternoon, the convention the team agreed on — and
each teammate's agent rediscovers all of it independently.

**Hippius Memory fixes that.** It is an [MCP](https://modelcontextprotocol.io/) server
that gives your agents one shared, long-term memory: notes are encrypted **on your
machine**, stored in a bucket **your team owns**, and synced across everyone. An agent
recalls what is relevant *before* it acts and remembers what is worth keeping *after* it
learns — automatically, because installing it wires in the hooks that enforce the loop.

<details>
<summary><b>📖 Table of contents</b></summary>

**Getting started**
- [Install](#install)
- [How it works](#how-it-works)
- [Features](#features)
- [Working as a team](docs/TEAMS.md)
- [Configuration](docs/REFERENCE.md#configuration)

**Reference & internals**
- [Operating model](docs/REFERENCE.md#operating-model)
- [MCP tools](docs/REFERENCE.md#mcp-tools)
- [Dashboard](docs/REFERENCE.md#dashboard)
- [Architecture](docs/REFERENCE.md#architecture)
- [How history is stored and received](docs/SECURITY.md#how-history-is-stored-and-received)
- [Retrieval honesty](docs/SECURITY.md#retrieval-honesty)
- [Phase 2 — op-log, convergence, verifiable history](docs/SECURITY.md#phase-2--shared-op-log-convergence-and-verifiable-history)
- [Phase 3 — identity, teams, key distribution](docs/SECURITY.md#phase-3--identity-teams-and-key-distribution)
- [Threat model — honest limits](docs/SECURITY.md#threat-model--honest-limits)
- [Scope by phase](docs/REFERENCE.md#scope-by-phase)
- [Design and plan](docs/REFERENCE.md#design-and-plan)

</details>

## Install

**hippius-mem is a private repo, so install over authenticated git, not a public `curl`**
(a raw `curl | sh` against `raw.githubusercontent.com` 404s without credentials). Clone
it — you already have access — and run the installer from the checkout; it installs Rust
if missing, builds hippius-mem with semantic recall, prompts for your team's config, and
wires it into Claude Code:

```sh
git clone https://github.com/thenervelab/hippius-mem
cd hippius-mem && sh scripts/install.sh
```

The script is idempotent and, in order: installs Rust via rustup if `cargo` is missing →
`cargo install --path hippius-mem --features embeddings,dashboard` (semantic recall plus
the browse UI; the ~90 MB model downloads on first run) → prompts for the five team values (`team`, `bucket`,
`access_key_id`, `secret`, `team_key_hex`) and auto-generates this machine's unique
`author_seed_hex` → writes a `0600` `~/.config/hippius-mem/hippius-mem.toml` → runs
`hippius-mem install` (user-global) and,
when run inside a project, `hippius-mem init` (that repo) → `hippius-mem doctor`. Pass
`--no-init-here` to skip provisioning the current repo, or `--no-hooks` to install
without the recall/remember hooks.

**Updating after a code change:** re-run from the clone with `--update`:

```sh
sh scripts/install.sh --update
```

It rebuilds the binary from your working tree, **keeps your existing config** (secrets
in `~/.config/hippius-mem/hippius-mem.toml` are never re-prompted), and **re-runs the
same idempotent `install`/`init` so the setup — the global `~/.claude.json` registration,
CLAUDE.md sections, and hooks — tracks the freshly built binary** (the rebuild and the
re-wire happen together), then runs `doctor` — skipping the Rust bootstrap and the config
prompts. It requires a local clone (the rebuild is of your working tree, not a fresh
fetch). In an open Claude session run `/mcp` afterward so the running server picks up the
new binary.

**Adding a team later:** the fresh install only writes a config when none exists, so to
add an org-routed profile to an *existing* config, use `--add-team`:

```sh
sh scripts/install.sh --add-team
```

It prompts for one `[[teams]]` profile (name, `orgs`, bucket, sub-token, key — the
signing seed is auto-generated), appends it `0600`-safe to your config
(`$HIPPIUS_MEM_CONFIG` if set, else `~/.config/hippius-mem/hippius-mem.toml`),
validates with `doctor`, and exits — no rebuild, no re-wire. See
[Routing memory to multiple teams](docs/REFERENCE.md#routing-memory-to-multiple-teams).

> [!NOTE]
> **Prefer a one-liner?** With the GitHub CLI authenticated (`gh auth login`, which also
> wires git auth for the build step) and repo access, pull and run the script without a
> full clone:
> ```sh
> gh api repos/thenervelab/hippius-mem/contents/scripts/install.sh \
>   -H 'Accept: application/vnd.github.raw' | sh
> ```
> The script reads secrets from `/dev/tty`, not the pipe, so it still prompts safely.
> Either way you need a team bucket, an S3 sub-token, and a team key first — see
> [Configuration](docs/REFERENCE.md#configuration) and [Working as a team](docs/TEAMS.md).

<details>
<summary><b>What <code>init</code> and <code>install</code> write</b></summary>

Both wire Claude Code so an agent obeys the team-memory rules automatically. Both are
idempotent and preserve anything else already in the files.

| Command | Scope | Writes |
|---------|-------|--------|
| `hippius-mem init` | current repo | a marker-delimited mandates block in `CLAUDE.md`; the five hooks (recall gate + token, remember nudge, seed nudge, session brief) in `.claude/hooks/` merged into `.claude/settings.json`; `.hippius-mem/` and `.fastembed_cache/` in `.gitignore`. It does **not** write a `.mcp.json` server entry — it *removes* any stale one (a project entry only shadows the global registration), leaving the repo free to commit `.mcp.json` for other servers. Flags: `--no-hooks`, `--allow-overwrite-tracked`, `--uninstall`. |
| `hippius-mem install` | user-global | the mandates block in `~/.claude/CLAUDE.md` and the server in `~/.claude.json` (an **absolute** path, since a user-scope server has no fixed cwd). This is the *only* place the MCP server is registered — registration is global-only. |

On every server boot, if Claude Code is the active agent (`CLAUDECODE`) and the cwd is a
git repo, the server also refreshes the committed `CLAUDE.md` block so the mandates track
the running binary — best-effort, never installing hooks and never aborting the server.
A committed, clean `CLAUDE.md` is never silently downgraded.

</details>

<details>
<summary><b>Manual install (no curl-pipe)</b></summary>

```bash
# 1. Build (pick the retrieval mode) and put it on PATH. `dashboard` adds the browse UI,
#    matching what scripts/install.sh builds; drop it for a smaller binary without `dashboard`.
cargo install --path hippius-mem --features embeddings,dashboard   # semantic recall + UI (~90 MB on first run)
# or `cargo build --release` for a lexical-only build — see Retrieval honesty.

# 2. Provision + register (from your project directory).
hippius-mem init      # CLAUDE.md block + hooks + .gitignore (removes any stale .mcp.json entry)
hippius-mem install   # user-global ~/.claude/CLAUDE.md + ~/.claude.json (registers the MCP server)
# (or register by hand: claude mcp add hippius-mem -- "$(command -v hippius-mem)")

# 3. Point it at a config (see Configuration) and validate the bundle.
hippius-mem doctor            # live seal→put→get→open probe
hippius-mem doctor --offline  # field/key validation without the network
```

> [!NOTE]
> The server speaks the MCP stdio protocol on **stdout**; diagnostics go to **stderr**
> via `tracing` (control verbosity with `RUST_LOG`, e.g. `RUST_LOG=info`), so stdout
> stays a clean protocol channel.

</details>

## How it works

Two habits make shared memory actually work — and hippius-mem makes them automatic:

1. **Recall before acting.** Before your agent edits code, it searches team memory for
   anything relevant — a past decision, a known gotcha — so it does not repeat a mistake
   or contradict a decision someone already made.
2. **Remember after learning.** When a session turns up something durable, the agent
   saves it as a one-line-summarized note the whole team can find later.

```text
recall "S3 sub-token bucket scope"  → a teammate already hit this: the bucket must
                                       match the sub-token's scope, or every request 403s
… agent avoids the 403, does the work, finds a new wrinkle …
remember (gotcha) "hippius-mem.toml bucket must equal the sub-token's scoped bucket"
```

`hippius-mem init` installs Claude Code hooks that **enforce** the loop: the first file
edit of a session is blocked until the agent has recalled, and a prompt at the end nudges
it to remember anything worth keeping. There is nothing for a human to remember to do.

Under the hood, notes live in one bucket your team owns, encrypted before they leave the
machine; `recall` returns short **pointers** so an agent pulls only what it needs into
its context window; and every change is a signed, independently verifiable event. The
[Architecture](docs/REFERENCE.md#architecture) and [Phase 2](docs/SECURITY.md#phase-2--shared-op-log-convergence-and-verifiable-history)
sections have the cryptographic detail.

## Features

| | |
|---|---|
| 🌐 **One shared brain** | One bucket, one op-log, one namespace — every member's agent, on every machine, reads the same memory. |
| 🔒 **Encrypted client-side** | Notes are sealed with XChaCha20-Poly1305 **before** they leave the process; the gateway only ever sees ciphertext. |
| 🧾 **Verifiable history** | Every change is a signed, hash-chained op with a Merkle inclusion proof anyone can check — no need to trust the server. |
| 🎯 **Context-efficient** | `recall` returns pointers + summaries; `get` hydrates a body only when the agent actually needs it. |
| 🧠 **Semantic recall, local and private** | The recommended install builds a local dense model (`bge-small-en-v1.5`, embedded in-process — no text leaves the machine) so paraphrases match; a lean `cargo build` without `--features embeddings` falls back to a zero-dependency lexical index. |
| 🪪 **Cryptographic identity** | One mnemonic per developer → SS58 signing key + x25519 encryption key; authorship is bound to the key. |

## Working as a team

Moved to **[docs/TEAMS.md](docs/TEAMS.md)** — day-to-day usage plus the found / add / remove runbooks.

## Configuration

Moved to **[docs/REFERENCE.md § Configuration](docs/REFERENCE.md#configuration)**.

## Operating model

Moved to **[docs/REFERENCE.md § Operating model](docs/REFERENCE.md#operating-model)**.

## MCP tools

Moved to **[docs/REFERENCE.md § MCP tools](docs/REFERENCE.md#mcp-tools)**.

## Dashboard

Moved to **[docs/REFERENCE.md § Dashboard](docs/REFERENCE.md#dashboard)**.

## Architecture

Moved to **[docs/REFERENCE.md § Architecture](docs/REFERENCE.md#architecture)**.

## How history is stored and received

Moved to **[docs/SECURITY.md § How history is stored and received](docs/SECURITY.md#how-history-is-stored-and-received)**.

## Retrieval honesty

Moved to **[docs/SECURITY.md § Retrieval honesty](docs/SECURITY.md#retrieval-honesty)**.

## Phase 2 — shared op-log, convergence, and verifiable history

Moved to **[docs/SECURITY.md § Phase 2](docs/SECURITY.md#phase-2--shared-op-log-convergence-and-verifiable-history)**.

## Phase 3 — identity, teams, and key distribution

Moved to **[docs/SECURITY.md § Phase 3](docs/SECURITY.md#phase-3--identity-teams-and-key-distribution)**; the Cargo features table is in **[docs/REFERENCE.md § Cargo features](docs/REFERENCE.md#cargo-features)**.

## Threat model — honest limits

Moved to **[docs/SECURITY.md § Threat model](docs/SECURITY.md#threat-model--honest-limits)**.

## Scope by phase

Moved to **[docs/REFERENCE.md § Scope by phase](docs/REFERENCE.md#scope-by-phase)**.

## Design and plan

Moved to **[docs/REFERENCE.md § Design and plan](docs/REFERENCE.md#design-and-plan)**.
