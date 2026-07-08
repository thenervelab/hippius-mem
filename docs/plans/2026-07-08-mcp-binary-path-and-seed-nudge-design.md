# Stable MCP binary path + agent-curated seed nudge

Date: 2026-07-08

Two changes to `hippius-mem/src/setup/`, shipped together because they touch the
same module and the same `init` flow. They are independent in behavior and will
land as two logical commits.

---

## Part 1 — Stable per-machine MCP binary path (never committed)

### Problem

`hippius-mem` reconnect failed with `ENOENT`. The git-tracked `.mcp.json` pinned
the server `command` to an absolute build path from the repo's *previous*
location:

```
/Users/georgiosdelkos/Documents/GitHub/Bitensor/hippius-mem/target/release/hippius-mem
```

That path no longer exists. Project-scope `.mcp.json` overrides user-scope
`~/.claude.json`, so the correct global registration
(`~/.cargo/bin/hippius-mem`) was shadowed by the stale one. The absolute path was
written by an older setup that used `current_exe()` for the repo entry and was
committed. The `illu` entry in the same file is machine-specific too (absolute
`--repo`), so this file was never portable.

Recorded team memory `mem_01KWHW4ZKA1R9Z74VSKQQST6D8` states the *current*
behavior ("init writes the BARE binary name in committed .mcp.json; only
per-machine ~/.claude.json uses the absolute current_exe() path") — this change
supersedes that note, which will be updated after the fix lands.

### Decision

Per-user install location (`~/.cargo/bin`, where `cargo install` already puts it
— no `sudo`). The repo `.mcp.json` carries the absolute installed path but is
**gitignored**, so each machine self-provisions via `init`/the installer and no
absolute path is ever committed. (Rejected: `/usr/local/bin` + committing that
constant — avoids the per-machine problem but adds a `sudo` install step.)

### Design

No new types. The unit of change is the JSON written into `.mcp.json` /
`~/.claude.json` by `setup::mcp`. Functions take `&Path` borrows and own a
transient `serde_json::Value`.

1. **`mcp::register_mcp_repo`** — write the absolute installed path plus an
   absolute `HIPPIUS_MEM_CONFIG` env, mirroring `register_mcp_global`, instead of
   the bare `SERVER_BINARY` name.
   - New signature: `register_mcp_repo(repo: &Path, command: &str, config_path: &Path)`.
   - Entry: `{ "command": command, "args": [], "env": { "HIPPIUS_MEM_CONFIG": config_path } }`.
   - Remove the now-unused `SERVER_BINARY` const.
   - Rewrite the doc comment (per-machine + gitignored, not portable).

2. **Shared config-path helper** — extract the
   `home/.config/hippius-mem/hippius-mem.toml` computation (inline in
   `register_mcp_global`) into `fn global_config_path(home: &Path) -> PathBuf`, so
   global and repo registrations cannot drift.

3. **`mod::configure_repo`** — resolve `home_dir()`, compute
   `global_config_path(&home)`, pass `resolved_binary_path()` as the command to
   `register_mcp_repo`, and add `ensure_gitignore_entry(repo, MCP_JSON_IGNORE)`
   (new `const MCP_JSON_IGNORE: &str = ".mcp.json"`). If `HOME` is unset,
   `register_mcp_repo` still writes the command; the config env falls back to the
   relative default (documented).

4. **`mod::self_heal_on_serve`** — on every `serve` boot in a provisioned repo,
   best-effort re-register `.mcp.json` with the current `current_exe()` path
   (same helper). Idempotent upsert; errors swallowed exactly like the existing
   `CLAUDE.md` refresh. Safety net: a reinstalled/moved binary self-corrects on
   the next session instead of `ENOENT`-ing. Gated the same way as the CLAUDE.md
   refresh (Claude Code active + inside a repo).

### Error strategy

Unchanged: `anyhow::Result<()>` with `.with_context(...)`; `self_heal_on_serve`
stays best-effort (`let _ =` / logged), never blocking the server boot.

### Tests (`setup/mcp.rs`)

- `writes_bare_command_and_no_secret` → `writes_absolute_command_and_config_env`:
  assert `command` == passed path, `env.HIPPIUS_MEM_CONFIG` == passed config path.
- Update `preserves_other_servers`, `register_is_idempotent` for the 3-arg call.
- Extend the gitignore test to assert `.mcp.json` is appended.

### One-time repo delivery (not code)

`init` only edits `.gitignore`/`.mcp.json`, and the installer *skips* `init`
inside the source clone. So for this repo, one-time:

1. `git rm --cached .mcp.json` — untrack (working copy + `illu` entry preserved).
2. Append `.mcp.json` to this repo's `.gitignore`.
3. Regenerate `.mcp.json` with the correct absolute path — run `hippius-mem init`
   here after rebuilding (the documented maintainer dogfood path).

---

## Part 2 — Agent-curated seed nudge for repos with existing memory

### Goal

When hippius-mem is provisioned on a repo that already holds knowledge — a repo
`CLAUDE.md` with real content, or a personal Claude Code memory store — nudge the
agent, once, to lift the genuinely team-durable facts into hippius-mem. The
semantic judgment of "team-relevant vs personal/noise" is the agent's (an LLM);
the Rust binary only *detects and reminds*. No mechanical parsing, no type
mapping, no bulk import.

This is the automation of the existing `TEAM_MEMORY_MANDATES` "Seeding" clause,
delivered as a fourth hook alongside recall-gate / recall-token / remember-nudge.

### Why a nudge, not an importer

The binary has no LLM, so it cannot decide what is team-relevant. A mechanical
importer would either dump noise into the shared vault (violating the four-tier
routing: personal → native memory, only team-durable → hippius-mem) or push that
judgment onto a human per-item. The agent already makes exactly this judgment
during a normal `remember`. So: detect + remind + let the agent curate.

### Data / ownership

- `SeedSources` — a small owned value listing the detected source paths
  (`Vec<PathBuf>` / serialized to JSON). Built at `init`, consumed by the hook.
- The pending marker `.hippius-mem/cache/seed-pending.json` (gitignored under the
  already-ignored `.hippius-mem/`) records those paths.
- The done marker `.hippius-mem/cache/seeded` (empty file) suppresses the nudge
  permanently once the agent finishes.

### Detection (Rust, at `init`)

New `mod::detect_seed_sources(repo: &Path) -> Vec<PathBuf>`, called from
`configure_repo` (skipped on `uninstall`). A source is added when:

1. **Personal memory**: `~/.claude/projects/<slug>/memory/MEMORY.md` exists, where
   `<slug>` is the repo's absolute path with every `/` replaced by `-` (Claude
   Code's per-project directory convention; e.g.
   `/Volumes/Source/.../hippius-mem` → `-Volumes-Source-...-hippius-mem`). Uses
   `home_dir()`; a no-`HOME` box simply skips this source.
2. **Repo CLAUDE.md**: `CLAUDE.md` has non-whitespace content *outside* the
   generated blocks — both the hippius-mem block (`SECTION_START`/`SECTION_END`)
   and the illu block. Both are machine-generated rules, not seedable knowledge,
   so both are stripped before the emptiness check; otherwise every
   illu-provisioned repo would false-trigger. The illu marker constants are
   verified against illu's actual output at implementation time; if the illu
   block is absent only the hippius block is stripped. Detection runs on the file
   **before** `write_md_section` splices our block in, so a re-run does not
   self-trigger. Rust string slicing (not bash) does this cleanly and testably.

If the resulting list is non-empty, write `seed-pending.json`. If empty, ensure
no stale `seed-pending.json` remains (best-effort remove). Never overwrite an
existing `seeded` marker.

### The hook (`hippius-mem-seed-nudge.sh`, SessionStart)

Added as a 4th `HookSpec` in the `HOOKS` array → auto-installed by
`install_hook_scripts` and auto-registered by `register_hooks_in_settings`.
`HookEvent` gains a `SessionStart` variant (settings.json key `"SessionStart"`),
`matcher: None` (fires on all sources; self-suppresses once seeded).

Script logic (mirrors the existing hooks: `set -u`, `jq` guard, fail-open trap,
`HIPPIUS_MEM_HOOKS_BYPASS`):

- stdin JSON: `{ session_id, source, cwd, hook_event_name, ... }` (verified
  contract). We read nothing critical from it beyond bypass hygiene.
- `repo_root` = script's `../..` (same as the other hooks).
- If `.hippius-mem/cache/seeded` exists → pass through (already curated).
- If `.hippius-mem/cache/seed-pending.json` absent → pass through (nothing to do).
- Else emit context via
  `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"<directive>"}}`.
  The directive names the source paths (read from the pending file) and instructs:
  read them, `recall` to dedupe, `remember` only genuinely team-durable facts,
  skip personal/noise, and when finished `touch .hippius-mem/cache/seeded` to
  dismiss (or do so immediately if there is nothing worth lifting).
- Pass-through output shape is `{"continue":true}` (SessionStart cannot block, so
  there is no `decision:block` path — this is context injection only).

### Delivery interaction with Part 1

`configure_repo` already gains `home_dir()`; both parts share it. The
`seed-pending.json` / `seeded` markers live under `.hippius-mem/`, already
gitignored — no new gitignore entry needed for them.

### Tests

- `setup/mod.rs`: `detect_seed_sources` — a repo with a plain `CLAUDE.md` →
  detected; a repo whose `CLAUDE.md` holds only our marker block → not detected;
  personal `MEMORY.md` present (via a `HOME` temp override) → detected; empty repo
  → none. This is a non-trivial pure-ish function (string parsing of the marker
  block) → add a `proptest!` asserting the marker-stripping invariant (content
  consisting only of our block, for arbitrary inner text, never counts as a
  source).
- `setup/hooks.rs`: assert the 4th hook installs, is executable, and registers
  under `SessionStart` in `settings.json`; assert `bash -n` parses the script
  body (the existing hook tests' pattern).

### Out of scope (YAGNI)

- Transcript (`*.jsonl`) mining — highest noise, highest privacy risk.
- A `hippius-mem seed` importer subcommand (the mechanical path we rejected).
- Re-arming the nudge when sources change after seeding (mtime tracking).

## Post-review revisions (PR #33)

A high-effort code review surfaced real issues; the implementation was revised:

- **Self-heal `.mcp.json` refresh removed.** It ran inside the server boot, so it
  could not repair a stale-path ENOENT (the server never boots to run it) and was
  a no-op when the server *did* boot (`current_exe()` == the spawn path). The
  durable recovery is the user-global `~/.claude.json` entry (refreshed by
  `install`) plus `init` writing an absolute path into a gitignored, untracked
  `.mcp.json`. `write_json`'s compare-and-skip (added only for the removed
  self-heal churn) was reverted too.
- **`global_config_path` now honors `XDG_CONFIG_HOME`**, mirroring
  `scripts/install.sh` and `dashboard::global_config_path`. Hardcoding `~/.config`
  made `HIPPIUS_MEM_CONFIG` point at the wrong file when `XDG_CONFIG_HOME` was set.
- **`init` untracks an already-committed `.mcp.json`** (`git rm --cached`,
  best-effort). Adding a path to `.gitignore` does not untrack it, so a repo that
  historically committed `.mcp.json` would otherwise keep tracking a machine path.
- **Repo `.mcp.json` config env prefers a repo-local `hippius-mem.toml`** when one
  exists (the documented cwd-relative `DEFAULT_CONFIG_PATH` pattern), else the
  global config — so a team scoping a repo to its own config is not silently
  overridden.
- **`claude_md_has_user_content` ignores Markdown heading lines**, so the
  `# CLAUDE.md` title `write_md_section` emits on a fresh file is not a
  false-positive seed source; the test fixture was corrected to carry the heading.
- **The secret-leak test's `!contains("secret")` assertion was restored** (it had
  been narrowed just as the entry gained an `env` block).

Consciously kept as-is: the seed hook's fail-open-without-`jq` (consistent with
all three existing hooks; it cannot emit the directive without `jq`), the loss of
the committed `illu` project registration for fresh clones (its `--repo` was an
absolute machine path — never portable), and the best-effort slug (a mismatch only
omits the personal-`MEMORY.md` source; `CLAUDE.md` still triggers).

## Follow-up: global-only MCP registration

Field failure after PR #33 landed: a teammate hit `-32000` on `/mcp` in a *different*
repo whose **committed, stale `.mcp.json`** (from an old hippius-mem — bare command,
no config env) shadowed the good user-global entry, so the server launched with no
resolvable config (`bucket required`). `--update`, run from the hippius-mem clone,
refreshed the binary and the global entry but never touched that other repo.

Root insight: once `.mcp.json` is gitignored (PR #33), the project-scope entry has
**no cross-teammate value** — it is per-machine — yet it still *overrides* the good
user-global entry and can go stale. So it is strictly a liability. Fix:

- `init` no longer writes a project-scope hippius-mem `.mcp.json` entry. Instead
  `mcp::deregister_mcp_repo` **removes** any entry a prior version left (preserving
  other servers, never creating the file, no rewrite when our entry is absent).
- hippius-mem stops managing `.mcp.json`'s git state entirely: the `.mcp.json`
  gitignore entry and the `git rm --cached` untrack are gone (a repo may legitimately
  commit `.mcp.json` for other servers). Removed `register_mcp_repo`,
  `repo_config_path`, `untrack_from_git`, `MCP_JSON_IGNORE`.
- The sole registration is the user-global `~/.claude.json` entry (XDG-aware, absolute
  path, refreshed by `install`), which serves every repo and routes to the right team
  by the launch repo's git remote. This drops per-repo `hippius-mem.toml` config —
  superseded by `[[teams]]` in the global config.
