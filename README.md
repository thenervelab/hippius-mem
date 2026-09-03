<div align="center">

# 🧠 Hippius Memory

### Team memory for coding agents that your security team will actually approve.

**Encrypted on your machine, stored in your Hippius bucket, every change
cryptographically provable — so a lesson learned once is never learned twice.**

[![Rust](https://img.shields.io/badge/Rust-1.97.1-000000?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Protocol](https://img.shields.io/badge/MCP-stdio_server-6E56CF)](https://modelcontextprotocol.io/)
[![Encryption](https://img.shields.io/badge/encryption-XChaCha20--Poly1305-2EA043)](docs/REFERENCE.md#configuration)
[![Audit](https://img.shields.io/badge/audit-signed_op--log_%2B_Merkle-blue)](docs/SECURITY.md#phase-2--shared-op-log-convergence-and-verifiable-history)
[![Status](https://img.shields.io/badge/status-active-success)](docs/REFERENCE.md#scope-by-phase)

```sh
git clone https://github.com/thenervelab/hippius-mem
cd hippius-mem && sh scripts/install.sh
```

*(needs the four team values from your founder — or an invite bundle; see [Install](#install))*

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

**Pricing.** The `hippius-mem` binary itself is free — no license and no per-seat fee:
build it from source and run it. (Public prebuilt releases are not published yet, so
today you build from a checkout you have access to.) What you pay for is what you already
pay for: your team's Hippius storage subscription, since the bucket your memory lives in
is a Hippius bucket — hippius-mem adds no seat, account, or subscription of its own.
There is **no free tier**; to try it without a bucket, use the local trial vault
(`--solo`, [below](#install)).

## Install

You need **four** team values before you run the installer: the **team namespace**, the
**bucket**, the shared **team key** (`team_key_hex`), and your **S3 sub-token**
(`access_key_id` + `secret`) — the founder mints and hands those out. The namespace is
the note-key prefix and must **byte-match your teammates' exactly** (same case, no stray
spaces), or your notes silently land in a separate partition. Joining an existing team?
Skip the typing entirely: have your founder send a one-paste invite bundle
(`hippius-mem invite`) and run `sh scripts/install.sh --bundle <file>` — the bundle
carries the exact namespace. See the runbooks in [docs/TEAMS.md](docs/TEAMS.md) and the
field-by-field [Configuration](docs/REFERENCE.md#configuration).

The source repo is private, so clone over authenticated git (a raw `curl | sh` against
`raw.githubusercontent.com` 404s without credentials):

```sh
git clone https://github.com/thenervelab/hippius-mem
cd hippius-mem && sh scripts/install.sh
```

The script is idempotent. In order it:

1. **Obtains the binary.** Tries a prebuilt from the public
   [`thenervelab/hippius-mem-releases`](https://github.com/thenervelab/hippius-mem-releases)
   GitHub Release for your OS/arch, verifies the sha256, and installs it to
   `~/.local/bin` (or `$HIPPIUS_MEM_BIN_DIR`) — though none are published yet, so
   today this always falls through to the source build. It builds from this checkout
   whenever no artifact exists, curl or a sha256 tool is missing, or you pass
   `--from-source` (`cargo install --path hippius-mem --features
   embeddings,dashboard --locked`; rustup is bootstrapped only when `cargo` is
   missing). The ~130 MB embedding model downloads on first serve. Intel macOS
   prebuilts, once published, are lexical-only — see
   [Retrieval honesty](#retrieval-honesty).
2. **Writes config** (first run only) at
   `${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/hippius-mem.toml` (mode `0600`),
   prompting for `team`, `bucket`, `access_key_id`, `secret`, `team_key_hex` and
   minting this machine's unique `author_seed_hex`.
3. **Wires agents:** `hippius-mem install --all-detected` (Claude Code plus
   every local MCP client whose config directory already exists) and, when you
   run it inside a project repo, `hippius-mem init`.
4. **Validates** with `hippius-mem doctor --offline`.

**Then enable the hooks in each project you work in.** The installer provisions only
the repo it was run in (and skips this vendor clone), so the recall/remember hooks — the
headline enforcement — are absent everywhere else until you turn them on. In every other
project, once:

```sh
cd <your project> && hippius-mem init
```

The installer's final "Done" block prints this reminder too, along with a PATH line
if the binary directory isn't on your `PATH` yet — and the server itself nudges at
session start when it boots in an un-provisioned repo (setting `auto_init = true`
makes boot provision it automatically). Joining instead of founding?
`sh scripts/install.sh --bundle <file>` installs, joins from the founder's invite
bundle, wires Claude Code, and validates with `doctor --offline` in one flow — run a
full `hippius-mem doctor` once afterwards to live-probe the minted credentials.
Updating, adding a second team, the full flag list, and the `auto_init` fine print
are in [docs/REFERENCE.md § Install details](docs/REFERENCE.md#install-details);
config-file resolution — the usual source of a first-run `bucket is required but
empty` error — is under
[docs/REFERENCE.md § Configuration](docs/REFERENCE.md#configuration).

**Solo trial (no team bucket yet).** No bucket? `sh scripts/install.sh --solo` installs
the binary, wires Claude Code, and hands off to `hippius-mem quickstart` — a local-only
trial vault, with **no team prompts**. When you have a Hippius bucket,
`hippius-mem upgrade --bucket <name> --access-key-id <id>` copies it up (the S3 secret is
prompted, never passed on argv). (Already have the binary on PATH? `hippius-mem
quickstart` alone does the same thing.)

### Wire other agents

`scripts/install.sh` already runs `hippius-mem install --all-detected`: Claude Code
plus every local client whose config directory already exists on this machine.
A bare `hippius-mem install` (no flags) still wires **Claude only**.

To add a client later, or to name them explicitly:

```sh
hippius-mem install --all-detected          # Claude + whatever is already installed
hippius-mem install --agent grok            # Grok Build only
hippius-mem install --agent grok,codex,gemini,hermes,openclaw
```

| Client | Wired when | Config the installer writes |
|--------|------------|-----------------------------|
| Claude Code | always (default and `--all-detected`) | `~/.claude.json` + `~/.claude/CLAUDE.md` |
| Grok Build | `--agent grok` or `~/.grok` exists | `~/.grok/config.toml` |
| Codex CLI | `--agent codex` or `~/.codex` exists | `~/.codex/config.toml` |
| Gemini CLI | `--agent gemini` or `~/.gemini` exists | `~/.gemini/settings.json` |
| Hermes | `--agent hermes` or `~/.hermes` exists | `~/.hermes/config.yaml` |
| OpenClaw | `--agent openclaw` or `~/.openclaw` exists | `~/.openclaw/openclaw.json` |
| Grok Bot | not supported | cloud VM — no local stdio; see [docs/AGENTS-SUPPORT.md](docs/AGENTS-SUPPORT.md) |

Detection is directory presence, never PATH: `install --all-detected` will not
create `~/.codex` on a machine that has never run Codex. After wiring, reopen
the agent (Grok: `/mcps` then refresh) so it picks up the new server.

The full capability matrix (hooks vs honor-system, matchers, Grok Bot) is in
[docs/AGENTS-SUPPORT.md](docs/AGENTS-SUPPORT.md).

> [!NOTE]
> **Prefer a one-liner?** With the GitHub CLI authenticated (`gh auth login`, which also
> wires git auth for a source-build fallback) and repo access, pull and run the script
> without a full clone:
> ```sh
> gh api repos/thenervelab/hippius-mem/contents/scripts/install.sh \
>   -H 'Accept: application/vnd.github.raw' | sh
> ```
> The script reads secrets from `/dev/tty`, not the pipe, so it still prompts safely.
> A source-build fallback from this path installs from git (needs the same auth);
> `--update` requires a local clone.

Manual install (no installer) and exactly what `init` / `install` write are in
[docs/REFERENCE.md § Install details](docs/REFERENCE.md#install-details).

## How it works

Two habits make shared memory actually work — and hippius-mem makes them automatic:

1. **Recall before acting.** Before your agent edits code, it searches team memory for
   anything relevant — a past decision, a known gotcha — so it does not repeat a mistake
   or contradict a decision someone already made.
2. **Remember after learning.** When a session turns up something durable, the agent
   saves it as a one-line-summarized note the whole team can find later.

A worked example of the loop — `recall` surfacing a teammate's gotcha, the agent
avoiding it, and the new wrinkle being `remember`ed — is in
[docs/TEAMS.md § Using it day to day](docs/TEAMS.md#using-it-day-to-day).

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
| 🧠 **Semantic recall, local and private** | The recommended install builds a local dense model (`bge-small-en-v1.5`, embedded in-process — no text leaves the machine) so paraphrases match; a lean `cargo build` without `--features embeddings` falls back to a zero-dependency lexical index. See [Retrieval honesty](#retrieval-honesty). |
| 🪪 **Cryptographic identity** | A per-machine signing seed stamps every note with its true author (authorship is bound to the key); a per-developer mnemonic (SS58 + x25519) drives membership and key distribution. |

## Retrieval honesty

Whether recall matches a **paraphrase** depends on the binary you installed, not on a
config flag: a `--features embeddings` build (what `scripts/install.sh` and the
recommended `cargo install` produce) compiles in a local `bge-small-en-v1.5` model, so
paraphrases match and no note text leaves the machine — while a lean build, such as the
planned Intel macOS prebuilt (`hippius-mem-lean`, for which ONNX Runtime ships no
library), ranks by keyword overlap only, so a reworded situation can miss its note
(pass `--from-source` there for semantic recall). The measured gap, the ranking rules, and the per-target table
are the canonical reference in
[docs/SECURITY.md § Retrieval honesty](docs/SECURITY.md#retrieval-honesty).

## Documentation

| Doc | What's inside |
|-----|---------------|
| **[docs/TEAMS.md](docs/TEAMS.md)** | Working as a team: the day-to-day recall/remember discipline, what belongs in team memory, and the found / add / remove runbooks. |
| **[docs/REFERENCE.md](docs/REFERENCE.md)** | Install details, the configuration table + example TOML, multi-team routing, the MCP tools table, operating model, dashboard, architecture, Cargo features, and scope by phase. |
| **[docs/SECURITY.md](docs/SECURITY.md)** | The threat model and its honest limits, the encryption boundary, how history is stored and verified (signed op-log, Merkle anchoring, key distribution), and retrieval honesty. |
| **[docs/AGENTS-SUPPORT.md](docs/AGENTS-SUPPORT.md)** | Which agents get hooks vs honor-system, how `install --agent` / `--all-detected` wires MCP, and why Grok Bot is document-only. |
| **[docs/INVARIANTS.md](docs/INVARIANTS.md)** | Core product promises → the test that pins each one → the CI job that runs it, plus the promotion loop for mutants and extra stress seeds. |
| [Design](docs/plans/2026-06-26-hippius-memory-design.md) · [Implementation plan](docs/plans/2026-06-26-hippius-memory-implementation-plan.md) | The original design document and the phased implementation plan. |
