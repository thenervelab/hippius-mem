<div align="center">

# 🧠 Hippius Memory

### Team memory for coding agents that your security team will actually approve.

**Encrypted on your machine, stored in your Hippius bucket, every change
cryptographically provable — so a lesson learned once is never learned twice.**

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
that gives your agents one shared, long-term memory — built so that adopting it is a
security *non-event*:

- 🔒 **Encrypted on your machine.** Notes are sealed with XChaCha20-Poly1305 in-process,
  **before** they leave it; the storage gateway only ever sees ciphertext.
- 🪣 **Stored in your bucket.** One team-owned bucket on the
  [Hippius](https://hippius.com) S3 gateway — decentralized storage, no vendor database,
  no third-party memory service holding your notes.
- 🧾 **Every change provable.** Each mutation is a signed, hash-chained op with a Merkle
  inclusion proof anyone can verify — no need to trust the server, or us.

An agent recalls what is relevant *before* it acts and remembers what is worth keeping
*after* it learns — automatically, because installing it wires in the hooks that enforce
the loop.

## Install

**hippius-mem is a private repo, so install over authenticated git, not a public
`curl`** (a raw `curl | sh` against `raw.githubusercontent.com` 404s without
credentials). Clone it — you already have access — and run the installer from the
checkout:

```sh
git clone https://github.com/thenervelab/hippius-mem
cd hippius-mem && sh scripts/install.sh
```

The script is idempotent: it installs Rust via rustup if `cargo` is missing, builds
hippius-mem with semantic recall and the browse UI (`cargo install --path hippius-mem
--features embeddings,dashboard`; the ~90 MB model downloads on first run), prompts for
the five team values (`team`, `bucket`, `access_key_id`, `secret`, `team_key_hex`) and
auto-generates this machine's unique `author_seed_hex`, writes a `0600`
`~/.config/hippius-mem/hippius-mem.toml`, wires Claude Code (`hippius-mem install`
user-globally, plus `hippius-mem init` when run inside a project), and validates the
bundle with `hippius-mem doctor` — a live seal→put→get→open probe that proves the
encryption boundary before your first tool call.

You need a Hippius team bucket, an S3 sub-token scoped to it, and the shared team key
first — the founder mints and hands those out. See the runbooks in
[docs/TEAMS.md](docs/TEAMS.md) and the field-by-field
[Configuration](docs/REFERENCE.md#configuration).

- **Update after a code change:** `sh scripts/install.sh --update` rebuilds from your
  working tree, keeps your existing config (secrets are never re-prompted), re-runs the
  same idempotent wiring so the setup tracks the fresh binary, then runs `doctor`. In an
  open Claude session run `/mcp` afterward so the server picks up the new binary.
- **Add a team later:** `sh scripts/install.sh --add-team` appends one org-routed
  `[[teams]]` profile to your existing config (validated with `doctor`; no rebuild) —
  see [Routing memory to multiple teams](docs/REFERENCE.md#routing-memory-to-multiple-teams).
- **Install flags:** `--no-init-here` skips provisioning the current repo; `--no-hooks`
  installs without the recall/remember hooks.

> [!NOTE]
> **Prefer a one-liner?** With the GitHub CLI authenticated (`gh auth login`, which also
> wires git auth for the build step) and repo access, pull and run the script without a
> full clone:
> ```sh
> gh api repos/thenervelab/hippius-mem/contents/scripts/install.sh \
>   -H 'Accept: application/vnd.github.raw' | sh
> ```
> The script reads secrets from `/dev/tty`, not the pipe, so it still prompts safely.

Manual install (no curl-pipe) and exactly what `init` / `install` write are in
[docs/REFERENCE.md § Install details](docs/REFERENCE.md#install-details).

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

Under the hood, notes live in one bucket your team owns on the Hippius S3 gateway,
encrypted before they leave the machine; `recall` returns short **pointers** so an agent
pulls only what it needs into its context window; and every change is a signed,
independently verifiable event. The [Architecture](docs/REFERENCE.md#architecture) and
[Security](docs/SECURITY.md) docs have the cryptographic detail.

## Features

| | |
|---|---|
| 🌐 **One shared brain** | One bucket, one op-log, one namespace — every member's agent, on every machine, reads the same memory. |
| 🔒 **Encrypted client-side** | Notes are sealed with XChaCha20-Poly1305 **before** they leave the process; the gateway only ever sees ciphertext. |
| 🧾 **Verifiable history** | Every change is a signed, hash-chained op with a Merkle inclusion proof anyone can check — no need to trust the server. |
| 🎯 **Context-efficient** | `recall` returns pointers + summaries; `get` hydrates a body only when the agent actually needs it. |
| 🧠 **Semantic recall, local and private** | The recommended install builds a local dense model (`bge-small-en-v1.5`, embedded in-process — no text leaves the machine) so paraphrases match; a lean `cargo build` without `--features embeddings` falls back to a zero-dependency lexical index. |
| 🪪 **Cryptographic identity** | One mnemonic per developer → SS58 signing key + x25519 encryption key; authorship is bound to the key. |

## Documentation

| Doc | What's inside |
|-----|---------------|
| **[docs/TEAMS.md](docs/TEAMS.md)** | Working as a team: the day-to-day recall/remember discipline, what belongs in team memory, and the found / add / remove runbooks. |
| **[docs/REFERENCE.md](docs/REFERENCE.md)** | Install details, the configuration table + example TOML, multi-team routing, the MCP tools table, operating model, dashboard, architecture, Cargo features, and scope by phase. |
| **[docs/SECURITY.md](docs/SECURITY.md)** | The threat model and its honest limits, the encryption boundary, how history is stored and verified (signed op-log, Merkle anchoring, key distribution), and retrieval honesty. |
| [Design](docs/plans/2026-06-26-hippius-memory-design.md) · [Implementation plan](docs/plans/2026-06-26-hippius-memory-implementation-plan.md) | The original design document and the phased implementation plan. |
