# Agent setup for hippius-mem

You are a coding agent. The human wants **hippius-mem** installed and working
in their environment. Follow this playbook end to end. Do not skip steps. Do
not invent credentials. Do not print, log, commit, or paste secrets into the
repo, the shell history on argv, or chat.

This file is the installer for agents. Humans can follow
[README.md](README.md) instead.

## Goal

When you finish, all of the following are true:

1. The `hippius-mem` binary is on `PATH` (or at a path you recorded).
2. A config file exists at
   `${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/hippius-mem.toml` with mode
   `0600`. It is **never** written into a git checkout.
3. The MCP server is registered for the agent the human is using.
4. The **human's project repo** (not this source checkout) is provisioned with
   `hippius-mem init`.
5. `hippius-mem doctor --offline` succeeds.

## Hard rules

- **Secrets stay off the tree.** Never write `hippius-mem.toml`, invite
  bundles, mnemonics, `team_key_hex`, S3 `secret`, or `author_seed_hex` into
  the project. Those paths are gitignored for a reason.
- **Do not echo secrets.** Prompt via `/dev/tty` or the installer's own
  prompts. If you must pass a secret, use the installer / CLI, not `echo` on
  argv.
- **Do not init this vendor clone.** `install.sh` skips `init` when cwd is
  this checkout *only if* it can see the script inside the clone
  (`SOURCE_ROOT`). `curl | sh` has no `SOURCE_ROOT` and **will init cwd**.
  `--no-init-here` skips `init` for default / `--bundle` / `--update`. It has
  **no effect** with `--solo`: that runs `quickstart`, which always inits the
  cwd git repo. Never run `--solo`, `quickstart`, or unadorned `curl | sh`
  from this checkout.
- **Do not create a Hippius account for them.** If they have no team bucket,
  use the local trial (`--solo`).
- **Prefer the installer.** Do not hand-roll `cargo install` unless the
  installer cannot run.

## 0. Detect state

Run these checks and branch on the results:

```sh
command -v hippius-mem
hippius-mem --version || true
test -f "${HIPPIUS_MEM_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/hippius-mem.toml}" \
  && echo "config exists" || echo "no config"
```

- Binary **and** config already present → [Wire MCP](#3-wire-mcp), then
  [Provision the project](#4-provision-the-humans-project), then
  [Verify](#5-verify).
- Binary present, no config → [Configure](#2-configure), then steps 3–5.
  `join --bundle` and `quickstart --no-wire` do **not** register MCP; you
  still owe step 3.
- Neither → [Install the binary](#1-install-the-binary). `--solo` from
  their project already wires and inits; still run step 5. Other modes
  continue with 3–5 (and 2 if the installer did not write config).

Also detect the **project repo** you should provision: the human's working
directory if it is a git repo that is **not** this hippius-mem source tree.
If you are running inside a clone of `thenervelab/hippius-mem`, that clone is
the vendor tree; the project to provision is wherever they actually work.

## 1. Install the binary

Need git, a network, and a POSIX shell (plus curl if Rust has to be
bootstrapped). Rust/cargo is **not** required when a prebuilt exists for this
OS/arch; otherwise the installer builds from source and bootstraps rustup if
`cargo` is missing. As of 2026-09-03 no prebuilts are published, so expect a
source build: a Rust toolchain download if needed, then `cargo install` with
`--features embeddings,dashboard`. Trust the installer's own report over this
sentence: `sh scripts/install.sh --dry-run` prints the prebuilt URL it would
try, and a real run says `no release artifact at ... yet ... building from
source instead` when it falls back.

The ~130 MB embedding model is downloaded the first time an embedder is
built. On the four-values path, and on `--bundle` without
`HIPPIUS_MEM_MNEMONIC`, that is the first `serve`. On `--solo` /
`quickstart` (and on `--bundle` with the mnemonic set) it happens **during
install**, because the probe builds the store. A sandbox that reaches
crates.io but not the Hugging Face CDN therefore fails inside `quickstart`
with an `Embedding(...)` error, after the trial config was already written
(see the blocked table).

**From a clone of this repo** (preferred — the human can read the script):

```sh
if git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && [ -f "$(git rev-parse --show-toplevel)/hippius-mem/Cargo.toml" ]; then
  CLONE=$(git rev-parse --show-toplevel)
else
  git clone https://github.com/thenervelab/hippius-mem
  CLONE=$PWD/hippius-mem
fi
```

Pick **one** onboarding mode. `--no-init-here` is for commands run *inside*
the clone. `--solo` must run from the **human's project** — `quickstart`
always inits the cwd git repo, and `--no-init-here` does not stop it.

| Situation | Command |
|---|---|
| Human has no team / no Hippius bucket yet | `cd <their-project> && sh "$CLONE/scripts/install.sh" --solo` |
| Human has a founder invite bundle file | `cd "$CLONE" && sh scripts/install.sh --bundle <file> --no-init-here` |
| Human has the four team values (namespace, bucket, team key, S3 sub-token) | `cd "$CLONE" && sh scripts/install.sh --no-init-here` (prompts on `/dev/tty`) |
| Updating an existing install from this checkout | `cd "$CLONE" && sh scripts/install.sh --update --no-init-here` |

You will `init` the human's project in step 4 (except `--solo`, which already
did).

**Without a clone:** never `curl | sh`. A pipe has no script path, so
`SOURCE_ROOT` is empty and `init` runs in **cwd** — including this vendor
clone. Download the file, then pass flags:

```sh
curl -fsSL https://raw.githubusercontent.com/thenervelab/hippius-mem/main/scripts/install.sh -o /tmp/hippius-mem-install.sh
cd <their-project> && sh /tmp/hippius-mem-install.sh --solo
```

For `--bundle` / four-values without a clone:

```sh
sh /tmp/hippius-mem-install.sh --bundle <file> --no-init-here
# or: sh /tmp/hippius-mem-install.sh --no-init-here   # prompts on /dev/tty
```

then `init` their project in step 4. The script reads secrets from
`/dev/tty`, not stdin.

If `~/.local/bin` or `~/.cargo/bin` is not on `PATH`, add it for this session
and tell the human to add it permanently. The installer prints that reminder.

Intel macOS prebuilts, when published, are lexical-only (`hippius-mem-lean`).
If the human is on Intel macOS and needs paraphrase-matching recall, pass
`--from-source`. See README "Retrieval honesty".

## 2. Configure

Skip this section if `--solo` or `--bundle` already wrote the config.

**Solo trial (no bucket):** from the **human's project**, not this clone:

```sh
cd <their-project> && hippius-mem quickstart
```

`quickstart` writes the trial config, then — unless `--no-wire` — runs
`install` (autodetect) and `init` in the cwd git repo. If you are stuck in
this vendor clone, `hippius-mem quickstart --no-wire` writes config only;
you still run steps 3 and 4 in their project. Local-only vault, no team
prompts.
Upgrade later with `hippius-mem upgrade --bucket <name> --access-key-id <id>`
(the S3 secret is prompted, never passed on argv).

**Join a team:** the founder sends an invite bundle. One paste, exact
namespace, no typing:

```sh
hippius-mem join --bundle <file>
```

`join --bundle <file>` needs no TTY. It skips publishing a member key unless
`HIPPIUS_MEM_MNEMONIC` is set; that is only needed for wrapped-key
distribution ([docs/TEAMS.md](docs/TEAMS.md)), so do not ask for or invent a
mnemonic to get the install working.

**Found / type the four values:** only if the human already has them. There is
no `hippius-mem configure`. Re-run the installer and let it prompt on
`/dev/tty` — do not hand-write the toml:

```sh
cd "$CLONE" && sh scripts/install.sh --no-init-here
```

(or the downloaded `/tmp/hippius-mem-install.sh --no-init-here`). The
namespace (`team`) must **byte-match** teammates (same case, no stray spaces)
or notes silently land in a separate partition. Do not guess.

Config lives at
`${XDG_CONFIG_HOME:-$HOME/.config}/hippius-mem/hippius-mem.toml`
(mode `0600`). Confirm it is not inside a git repo.

Field-by-field meaning: [docs/REFERENCE.md](docs/REFERENCE.md#configuration).
Found / add / remove runbooks: [docs/TEAMS.md](docs/TEAMS.md).

Then continue with steps 3–5. Do not stop here.

## 3. Wire MCP

The server speaks MCP over **stdio**. Pin `HIPPIUS_MEM_CONFIG` to the
user-global config — a stdio server has no predictable cwd.

`scripts/install.sh` already ran `hippius-mem install`, which autodetects:
Claude Code plus every local client whose config directory already exists
(`~/.grok`, `~/.codex`, `~/.gemini`, `~/.hermes`, `~/.openclaw`). Confirm, and
pick up any client that appeared after install:

```sh
hippius-mem install
```

Bare `install` autodetects by directory presence and will not create
`~/.codex` on a machine that has never run Codex. To name a subset:
`hippius-mem install --agent grok,codex` (that **will** create those clients'
config files). Claude-only is `--agent claude`.

**Grok.** Native entry is `~/.grok/config.toml`. It also shares
`.claude/settings.json`; `hippius-mem init` in the project (step 4) plants the
hook shim. Re-run `hippius-mem init` if the shim is missing.

**Cursor, Copilot, or any other stdio MCP client without an adapter.** Register
this entry, substituting the real absolute paths (`command -v hippius-mem` and
the config path from step 2):

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

Where that JSON lives is client-specific (Cursor user MCP settings, Copilot
MCP config, and so on). Write it in the client's **user** config, not as a
committed project file, unless the human asks for a repo-local MCP entry.
Do not paste this JSON into Codex, Grok, Gemini, Hermes, or OpenClaw —
those have adapters; use `hippius-mem install --agent …`.

For semantic (paraphrase-matching) recall the binary must be the
`--features embeddings` build, which is what `scripts/install.sh` produces.
A lean build ranks by keyword overlap only.

Client matrix (hooks vs honor-system): [docs/AGENTS-SUPPORT.md](docs/AGENTS-SUPPORT.md).

## 4. Provision the human's project

In **their** project directory, once:

```sh
cd <their-project> && hippius-mem init
```

This writes the mandates block into `CLAUDE.md` and `AGENTS.md`, installs the
recall/remember hooks for Claude Code (and Grok via the shim), and gitignores
local state. As a side effect it also ensures Claude's entry in
`~/.claude.json`. Autodetect of Grok/Codex/Gemini/Hermes/OpenClaw is
**only** `hippius-mem install` — run that in step 3, do not rely on `init`
for those clients.

Do this for every project they want the loop in. Setting `auto_init = true`
in the user-global config makes the server provision on boot; leave that off
unless they ask.

`--no-hooks` is only for environments that must not run Claude Code hooks.

The hooks need `jq` at runtime. Check `command -v jq`; if it is missing,
install it (`brew install jq` / `apt-get install -y jq`). Without it the
recall gate passes every edit through and only reports itself inactive, and
`doctor` does not check for it.

## 5. Verify

```sh
hippius-mem doctor --offline
```

That is the installer's validation. After a team join or a live bucket,
also run `hippius-mem doctor` (no flag) to probe the gateway with the minted
credentials.

If doctor fails, read the error; the usual first-run miss is an empty
`bucket` because the config file the server loaded is not the one you wrote.
See [docs/REFERENCE.md § Configuration](docs/REFERENCE.md#configuration).

## 6. After setup — how the agent must behave

hippius-mem only works if you use it. In the provisioned project:

1. **Recall before you act.** Before the first edit, and again when the task
   shifts, call `recall` (tool name may be `mcp__hippius-mem__recall` or
   plain `recall`) with a query for the feature, bug, or subsystem. Read the
   summaries; `get` any that look relevant.
2. **Remember after you learn.** Store a durable `decision`, `gotcha`,
   `convention`, or `reference` — one self-contained fact per note, with a
   keyword-rich summary. Do not store session trivia or anything already
   obvious from the code or git.
3. **Subagents.** When you spawn a subagent, tell it to recall before
   changes and remember durable findings.

Claude Code / Grok: hooks enforce (1) and nudge (2). Other clients: honor
system — you still do it.

## If something is blocked

| Problem | What to do |
|---|---|
| No Hippius bucket | `--solo` / `quickstart` from **their** project, not this clone. Do not block on an account. |
| Human does not have the four team values | Ask for an invite bundle from their founder. Do not invent a namespace. |
| Intel macOS and they need semantic recall | Add `--from-source` to the same command you would already run (`--solo` from their project, or `--no-init-here` from the clone). |
| `bucket is required but empty` | Wrong config path. Pin `HIPPIUS_MEM_CONFIG`. |
| MCP tools missing in this session | Restart the client after `hippius-mem install`. Adapters write native files (Grok/Codex TOML, etc.), not the generic JSON snippet. |
| Installer says `no TTY available; skipping the config prompt` | No terminal, so the four-values prompt cannot run. The installer still wires MCP, skips `doctor`, and exits 0 with a `config: ... NOT WRITTEN` line, so do not read its `Done.` as success. In order of preference: have the human run the same `install.sh` command in their own terminal; get an invite bundle **file** and use `--bundle <file>` / `join --bundle <file>` (reads the file, no prompt); or `--solo` / `quickstart` for a trial, which need no TTY. Hand-writing the toml is the last resort the installer itself describes, and only with values the human supplied verbatim: a namespace that differs by one byte partitions their notes silently. |
| `a config already exists at …` from `quickstart` / `--solo` | Look at the file before deciding. If it holds a `bucket` and `secret`, it is the human's real config: keep it, run `hippius-mem doctor`, and continue from [Wire MCP](#3-wire-mcp). If it is a `storage = "local"` trial config and an earlier `--solo` / `quickstart` run failed before printing its next steps, it is half-provisioned: quickstart writes the config **before** its probe and leaves it behind on failure, and `doctor` never builds the embedder, so it cannot see that failure. Confirm with the human that the trial was never used (the file holds the key to the local trial vault), fix the cause (usually the model download), delete that trial file, and re-run. |
| You are in the hippius-mem source repo | Install from here; `init` the human's other project, not this one. |
