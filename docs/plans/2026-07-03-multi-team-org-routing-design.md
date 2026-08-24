# Multi-team org routing: one machine, many memories, no cross-contamination

**Date:** 2026-07-03
**Status:** Implemented — historical record. Multi-team `[[teams]]` routing shipped;
the current behavior is documented in
[Reference § Routing memory to multiple teams](../REFERENCE.md#routing-memory-to-multiple-teams).
**Scope:** `hippius-mem` (config + resolver, the real feature), `scripts/install.sh`, `README.md`

## Problem

Today one running `hippius-mem` server serves exactly **one** team: `Config`
holds a single `team` / `bucket` / `team_key_hex` / `access_key_id`
(`hippius-mem/src/config.rs`). Which config a repo uses is decided only by cwd +
Claude Code scope precedence, and a note's `repo` field is an **agent-supplied
string** the server never verifies (`RememberParams.repo: Option<String>`,
`RepoScope::{Global, Repo(name)}`).

The consequences a user hits:

- The user-global install (`register_mcp_global`) pins `HIPPIUS_MEM_CONFIG` to an
  absolute path, so **every repo opened on the machine writes to the one team
  bucket** — a catch-all. Open a personal side project, let the agent
  `remember`, and it lands in the team's shared memory.
- There is **no concept of an organization or git remote** anywhere in the code,
  so nothing routes "this repo belongs to team X" or refuses "this repo belongs
  to nobody I share with."

Goal: a person on several teams (plus personal projects) opens any repo and the
server automatically binds the **right** team's memory — or none — with no manual
per-repo wiring and no risk of leaking one context into another.

## Decisions (and why)

Settled in the 2026-07-03 brainstorm.

1. **Central multi-profile map.** The user-level config becomes a list of
   `[[team]]` profiles, each fully self-contained (its own bucket, sub-token, key,
   seed). Separate bucket + key per profile is what makes teams **cryptographically
   isolated** — a `clientX` sub-token cannot read `ourovoros-memory`, and its notes
   cannot be decrypted without that team's `team_key_hex`.

2. **Org-based routing off the real git remote.** Each profile declares
   `orgs = ["github.com/<org>", ...]`. At startup the server reads the launch
   repo's `origin` remote, normalizes it, and routes to the first profile whose
   `orgs` matches. Routing is derived from ground truth (the remote), not from an
   agent's guess.

3. **Unmatched → optional personal catch-all.** A profile may set
   `catch_all = true` (your own private bucket + key). A repo matching no `orgs`
   — including a repo with **no remote at all** (a local-only project is de facto
   personal) — routes there. If no catch-all is defined, memory is **disabled**
   for that repo: `remember` refuses with a clear message and `recall` returns
   nothing. Nothing ever leaks into a team by default.

4. **One process = one profile, resolved once at startup.** Resolution reads the
   server's launch cwd (the repo you opened) and binds exactly one profile's store
   for the process lifetime. This preserves today's single-store architecture — no
   per-call multi-store juggling, no holding several team keys in memory at once.
   It is sound because the server is relaunched every time a repo is opened.

5. **Backward compatible.** A flat single-team config (today's format) is read as
   a **one-profile map** with `catch_all = true` and no `orgs` — i.e. it matches
   every repo, exactly like today. Existing installs keep working untouched; users
   opt into routing by adding `orgs` and more profiles. (Chosen over a hard cut so
   rollout needs no forced migration.)

6. **Derived repo scope.** With the remote known, a note's `RepoScope::Repo(name)`
   is set from the resolved `org/repo` rather than an agent string, closing the
   soft-label gap. The agent may still choose `Global`, but cannot misattribute a
   note to the wrong repo.

## Config schema

```toml
# ~/.config/hippius-mem/hippius-mem.toml

[[team]]
name = "ourovoros"
orgs = ["github.com/thenervelab"]
bucket = "ourovoros-memory"
access_key_id = "hip_AK..."
secret = "..."
team_key_hex = "..."
author_seed_hex = "..."      # auto-generated per machine by the installer

[[team]]
name = "clientX"
orgs = ["github.com/clientX"]
bucket = "clientx-memory"
access_key_id = "hip_AK..."
secret = "..."
team_key_hex = "..."
author_seed_hex = "..."

[[team]]
name = "personal"
catch_all = true             # unmatched repos (and no-remote repos) land here
bucket = "alice-personal-mem"
access_key_id = "hip_AK..."
secret = "..."
team_key_hex = "..."
author_seed_hex = "..."
```

Validation rules (fail fast at startup):
- At most one profile may set `catch_all = true`.
- Every profile validates as today (key/seed decode to 32 bytes, required fields).
- A flat top-level config (no `[[team]]`) is accepted and wrapped as one
  `catch_all` profile named from its `team` field.
- Profile names are unique.

## Resolution algorithm

At startup, after loading the map:

1. **Find the repo root** of the launch cwd (`git rev-parse --show-toplevel`
   equivalent). No repo → treat as no-remote.
2. **Read `origin`** (`git remote get-url origin`). Missing → no-remote.
3. **Normalize** the URL to `host/org/repo` (a pure function — see below).
4. **Match** the normalized `host/org` (and optionally full `host/org/repo`)
   against each profile's `orgs` patterns, first match wins.
5. **Fallback:** no match → the `catch_all` profile if present, else **disabled**.
6. **Bind** the chosen profile's `MemoryStore`; log which profile (by name) bound,
   or that memory is disabled and why.

**Remote normalization** must handle all three URL shapes to one canonical form:
- `git@github.com:org/repo.git` → `github.com/org/repo`
- `https://github.com/org/repo.git` → `github.com/org/repo`
- `ssh://git@github.com/org/repo` → `github.com/org/repo`
Strip a trailing `.git`, lowercase the host, keep org/repo case. This is a pure
string transform and the natural home for a `proptest!` block (idempotence:
`normalize(normalize(x)) == normalize(x)`; and agreement across the three input
shapes for the same repo).

`orgs` pattern semantics (v1, minimal): an entry is `host/org` (profile owns a
whole org) or `host/org/repo` (a single repo). Match = exact equality on that
prefix. Globs are deferred unless a real need appears.

## Rust core changes

- **`Config` split** — introduce `TeamProfile` (the per-team fields) and make the
  loaded config a `Vec<TeamProfile>` plus the shared non-team settings
  (embeddings, anchor threshold, chain). serde accepts either `[[team]]` or the
  legacy flat shape (wrap-as-one on the flat path).
- **New `resolver` module** — `resolve_profile(repo_root, map) -> Resolution`
  where `Resolution = Bound(TeamProfile) | Disabled(reason)`. Remote reading is
  isolated behind a small trait so it is testable without a real repo (inject the
  remote string). Reuse the `#[async_trait]` seam pattern noted in team memory for
  live-dependency isolation.
- **`build_store` per profile** — unchanged internally; called on the resolved
  profile. When `Disabled`, the server still starts (so `/mcp` connects) but the
  memory tools return a clear "no team maps this repo" error rather than 500ing.
- **Errors** follow the existing typed-enum `ConfigError` shape (a new
  `ConfigError::MultipleCatchAll` / `::NoProfiles`, etc.), not a stringly `Other`.

## Installer changes (`scripts/install.sh`)

- Prompt **per profile** in a loop: name, `orgs` (comma-separated, blank =
  catch-all), bucket, access_key_id, secret, team_key_hex. Auto-generate each
  profile's `author_seed_hex` via the existing `gen_seed` (CSPRNG) — never
  prompted.
- On re-run with an existing config, offer to **add another profile** rather than
  only keeping the file as-is.
- Write the `[[team]]` array at `0600`. `doctor` then validates each profile.
- Ctrl-C abort (already merged) stays.

## README changes

- Rewrite **Configuration** around the map: the `[[team]]` schema, `orgs`,
  `catch_all`, and the resolution/disable behavior.
- Rewrite **Working as a team** so "add a teammate" and "personal projects" are
  expressed as profiles; state that separate bucket + key per profile is the
  isolation boundary.
- Document that routing is derived from the repo's `origin` remote, and what
  happens with no remote / no match / no catch-all.

## Non-goals (v1)

- No glob/regex in `orgs` beyond `host/org` and `host/org/repo` exact prefixes.
- No per-call profile switching (one process = one profile).
- No central server-side org registry — the map is local, user-owned.
- No change to the op-log / encryption / anchoring layers.
- No auto-discovery of which org a repo "should" belong to — unmatched is
  catch-all or disabled, never a guess.

## Testing

- **Resolver** — unit tests over injected remote strings: match, no-match →
  catch-all, no-match + no catch-all → disabled, no remote → catch-all.
- **Normalization** — `proptest!` for idempotence and cross-shape agreement.
- **Config** — legacy flat config wraps to one catch-all profile; duplicate
  catch-all rejected; per-profile validation through the public load path (not a
  hand-built struct), per team-memory test-rigor guidance.
- **Server** — a `Disabled` resolution starts the server but the tools return the
  clear error; a `Bound` resolution round-trips remember/recall.

## Build order (must not become a phantom feature)

1. Rust core (config + resolver + server wiring) — where routing is *enforced*.
2. Installer (multi-profile prompting + per-profile seed generation).
3. README (schema + routing + personal catch-all).

Docs/installer land only after the core, so we never document behavior the binary
cannot perform.

## Open questions / risks

- **Reading the remote:** shell out to `git` (simplest, git is always present in
  dev) vs a Rust lib (`gix`). v1 leans to shelling out behind the testable seam;
  revisit if the subprocess proves flaky.
- **MCP launch cwd assumption:** the whole model rests on the server being
  launched with the repo as cwd on each repo-open. Confirmed by the user's
  observation ("it starts every time we open a new repository"); verify against
  Claude Code's project-vs-user server launch cwd during implementation.
