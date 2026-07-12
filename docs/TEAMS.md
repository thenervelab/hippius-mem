# Teams

A team is one shared bucket, one shared encryption key, and one `team` namespace.
Everyone writes to the same op-log under their own signing identity, and any member's
agent on any machine reads the same memory. This page covers both **how the team
uses memory day to day** and the three lifecycle flows — **found** the team, **add** a
teammate, **remove** one.

Part of [hippius-mem](../README.md) · Teams · [Reference](REFERENCE.md) · [Security](SECURITY.md)

## Using it day to day

The whole point is that a mistake, decision, or gotcha one teammate's agent hits is
**not rediscovered** by the next. Two habits make that real, and `hippius-mem init`
installs hooks that enforce both — so they hold even when nobody remembers to.

**1 · Recall before you act.** Before an agent edits code — a feature, a bug, a
subsystem — it calls `recall` with a description of what it is about to do, reads the
returned summaries, and `get`s any that look relevant. That is how it avoids repeating
a documented gotcha or contradicting a recorded decision.

**2 · Remember after you learn.** When a session turns up something durable and
team-relevant, the agent calls `remember` — **one self-contained fact per note**, with
a keyword-rich `summary` so `recall` can find it later.

```text
# A typical loop
recall "S3 sub-token bucket scope"   → surfaces a gotcha: the bucket must match the
                                        sub-token's scope or every request 403s
… agent avoids the 403, does the work, discovers a new wrinkle …
remember (gotcha) "hippius-mem.toml bucket must equal the sub-token's scoped bucket"
```

> [!IMPORTANT]
> **The hooks make the discipline non-optional.** `init` writes five hooks into
> `.claude/hooks/`; three of them enforce the recall/remember loop: a **PreToolUse** gate
> that BLOCKS the first file edit of a session
> until a `recall` has happened (one recall opens a window,
> `HIPPIUS_MEM_RECALL_WINDOW_SECS`, default 1800 s), a **PostToolUse** hook that records
> the recall, and a **Stop** hook that nudges once per session to `remember` anything
> durable. Escape hatch for emergencies: `HIPPIUS_MEM_HOOKS_BYPASS=1`. The hooks do
> **not** fire for Task-tool subagents, so the mandates block `init` adds to `CLAUDE.md`
> is the enforcement floor there — spawned subagents are told to recall/remember in
> their prompt.

**What belongs in team memory — and what does not.** Keep `recall` signal-rich; noise
poisons it.

| Store as a team memory (`remember`) | Do **not** store |
|-------------------------------------|------------------|
| A decision and its rationale ("we anchor per-batch, not per-op, because…") | Restatements of what the code already says |
| A gotcha that cost someone time ("the gateway 403s unless the bucket matches the sub-token scope") | Anything derivable from `git log` / the diff |
| A convention the team agreed ("error types follow the typed-enum shape") | Per-session trivia ("ran the tests, they passed") |
| A reference (a dashboard, a ticket, an external doc) | Secrets, tokens, or keys |

> [!TIP]
> **Route each fact to the right tier so it is not duplicated.** Team-durable,
> cross-machine facts → hippius-mem (`remember`). Repo-invariant rules that must ship
> with the code → `CLAUDE.md` (committed). Personal or machine-specific notes → your own
> `~/.claude` memory. hippius-mem is the *cross-machine, encrypted, team* tier.

**Seeing teammates' notes.** `recall` and `get` auto-refresh: before they answer, they
cheaply probe the shared op-log and replay it (applying teammates' additions **and**
tombstones) only if it has grown since the last check, and at most once per short
window — so a long session stays current without repeated full syncs. `refresh` is
still there to force a replay on demand (and `history`/`reconcile` always read the
op-log directly, so they never go stale).

**Fixing and removing notes.** `edit` updates a note in place (optionally with a
compare-and-swap that refuses if it changed since you read it). `forget` tombstones a
note so it stops surfacing in `recall` while its signed op stays in the audit trail.
`redact` **permanently** scrubs a note's content (leaked secret, PII, deletion request)
yet keeps the signed op provable in `history`. See [MCP tools](REFERENCE.md#mcp-tools).

> [!WARNING]
> **Recall quality depends on the build.** Semantic (paraphrase-matching) recall — the
> thing that catches a past mistake even when phrased differently — needs the server
> built `--features embeddings`. A lean build silently ranks **lexically** (keyword
> overlap only), so a reworded situation may miss its stored note. The
> [installer](../README.md#install) (`scripts/install.sh`) builds with embeddings; if you install by hand, use
> `cargo install --path hippius-mem --features embeddings`. See
> [Retrieval honesty](SECURITY.md#retrieval-honesty).

## Found the team (the first member)

1. **Get a bucket and a sub-token.** Create (or reuse) a team-owned bucket — your
   (the founder's) account **owns** it, which is exactly what lets you mint sub-tokens
   against it, both for yourself now and for each teammate later. Mint your own
   sub-token: build with `--features console` and run `hippius-mem mint-token`, or take
   the `{ access_key_id, secret }` from the hippius-console flow (see
   [Getting an S3 sub-token](REFERENCE.md#configuration)).
2. **Generate the shared team key.** It is 32 random bytes as 64 hex characters —
   `openssl rand -hex 32`. That string is `team_key_hex`: every member encrypts and
   decrypts under it, so guard it like a password and share it only out of band (or use
   wrapped-key distribution — see [The team key](REFERENCE.md#configuration) and
   [Phase 3](SECURITY.md#phase-3--identity-teams-and-key-distribution)).
3. **Write the config.** Put the S3 coordinates, a chosen `team` namespace,
   `team_key_hex`, and *your own* `author_seed_hex` in `hippius-mem.toml`.
4. **Validate.** Run `hippius-mem doctor` to check the bundle and prove the encryption
   boundary (a live seal→put→get→open probe).
5. **Start the server.** The team is **open** — every signature-verified op converges —
   until you close it. That is deliberate: a team can dogfood before it is formalized.

## Add a teammate (runbook)

Onboarding is **two-sided**: the **founder** (who owns the bucket) mints the credential,
and the **joiner** consumes it. The split is not optional — a sub-token can only be
minted by the account that **owns the bucket**, so a joiner signed in as themselves
cannot mint one against the shared team bucket. The whole flow is **two commands**:

**The founder runs — once per teammate:**

```sh
HIPPIUS_MEM_MNEMONIC="<founder mnemonic>" hippius-mem invite --name alice
```

Built `--features console`, run from the founder's own valid config. It mints a fresh
per-teammate sub-token against the team bucket (individually revocable later) and
prints **one paste-ready TOML bundle** holding everything the joiner needs: `bucket`,
`team`, `team_key_hex`, the new `{ access_key_id, secret }`, plus — when applicable —
`s3_endpoint`, `max_epoch` (rotated team), and the pinned `founder_ss58`. The secret is
shown **once**; share the bundle with that one teammate over a secure out-of-band
channel (never git or a chat log), then delete it.

**The joiner runs — on their own machine:**

```sh
hippius-mem join --bundle invite.toml     # or:  pbpaste | hippius-mem join --bundle -
```

That one command reads the bundle (a file, or `-` for stdin), generates this machine's
own `author_seed_hex` from the OS CSPRNG (never prompted for, never taken from the
bundle — it is the joiner's unique op-log identity), and writes the config **0600**:

- **Fresh machine** (no config yet): the bundle becomes the primary profile at
  `$HIPPIUS_MEM_CONFIG` (or `${XDG_CONFIG_HOME:-~/.config}/hippius-mem/hippius-mem.toml`).
- **Existing config**: the bundle is appended as an org-routed `[[teams]]` profile —
  pass `--orgs github.com/acme` so repos route to it. A conflicting profile name, a
  different `s3_endpoint`, or a too-low top-level `max_epoch` is **refused with
  guidance**, never silently overwritten.

When `HIPPIUS_MEM_MNEMONIC` is set it also publishes the member key (the same thing
the bare `hippius-mem join` does) so the founder can `provision` wrapped epoch keys.
Then verify and start:

```sh
hippius-mem doctor        # validates the bundle + live encryption-boundary probe
```

On boot the server bootstraps the epoch key-ring (when `HIPPIUS_MEM_MNEMONIC` is set)
and syncs the index from the shared op-log, so the machine comes up already aware of
teammates' notes.

### Fallback: manual onboarding (no `invite` bundle)

If the founder cannot run `invite` (no console-feature build), the same flow by hand:

1. **Founder mints a sub-token** in hippius-console (S3 → Sub Tokens → Create Sub
   Token, `read`+`write`, scoped to the team bucket) or via `hippius-mem mint-token
   --bucket <team-bucket>`. One sub-token per teammate; the secret is shown once.
2. **Founder hands the joiner four values out of band**: the `bucket` name, the `team`
   namespace, the shared `team_key_hex`, and that teammate's `{ access_key_id, secret }`.
3. **Joiner gets their own signing seed.** The installer mints a fresh
   `author_seed_hex` automatically; by hand, `openssl rand -hex 32`. Unique per
   machine, never shared.
4. **Joiner writes the config.** The four handed values plus their own
   `author_seed_hex` into `hippius-mem.toml` (or `HIPPIUS_MEM_*`); optionally the chain
   anchor (`chain_ws_url`, `chain` feature). (A founder using wrapped-key distribution
   can set `HIPPIUS_MEM_MNEMONIC` instead of pasting `team_key_hex`.)
5. **Joiner verifies with `hippius-mem doctor`** — bundle validation plus the live
   seal→put→get→open probe (use `--offline` to skip the network probe) — and starts
   the server.

**Optionally close the team.** Once the roster is fixed, the founder runs `hippius-mem
publish-membership --members <ss58,...>` (each teammate's SS58 is printed by their
`doctor`) so only listed members' ops converge.

> [!IMPORTANT]
> **Two keys, two jobs — do not conflate them.** The **sub-token** (`access_key_id` +
> `secret`) is *write permission* on the bucket; it is bound to the bucket **owner's**
> account, so the founder mints every one. The **`author_seed_hex`** is the teammate's
> *op-log identity*, generated on their own machine and never shared — it owns nothing on
> the backend. That decoupling is what lets everyone write to one founder-owned bucket
> while each note still carries its true author, and it is why hippius-s3 needs no
> per-teammate accounts.

## Remove a member

> [!CAUTION]
> **Membership filtering alone does *not* revoke access** — a removed member keeps their
> sub-token and the current team key. To fully cut someone off, do **all three**:

1. **Revoke their sub-token** at the gateway/console so they lose direct bucket access.
2. **Rotate the team key** (`rotate_team_key`, a library call today — see
   [Operating model](REFERENCE.md#operating-model)) to mint a new epoch wrapped to the *remaining*
   members only. Older epochs stay wrapped, so previously shared notes remain readable;
   writes sealed under the new epoch are unreadable to the removed member.
3. **Re-publish membership** without them (`hippius-mem publish-membership --members
   <ss58,...>`) so their future ops stop converging.

Until the sub-token is revoked **and** the key is rotated, a removed member can still
read and write the bucket directly — stated in full under
[Threat model](SECURITY.md#threat-model--honest-limits).

> [!NOTE]
> **Where this is headed.** The paste-ready-bundle onboarding exists today as the CLI
> pair `hippius-mem invite` → `hippius-mem join --bundle` (the runbook above); the
> remaining step is a hippius-console "Memory key" wizard that mints the same bundle
> from the browser — see
> [`docs/plans/2026-06-28-memory-subkey-console-design.md`](plans/2026-06-28-memory-subkey-console-design.md)
> for the design. Note-content encryption stays entirely inside this server regardless:
> no plaintext note content leaves it for the gateway. (The signed op-log envelope
> carries cleartext metadata — team/repo names, author SS58, timestamps — by design;
> see [Encryption boundary](SECURITY.md#encryption-boundary).)
>
> Onboarding a member onto **wrapped-key distribution** (so they fetch the team key
> cryptographically rather than receiving `team_key_hex` out of band) is driveable from
> the binary: the member runs `hippius-mem join` (requires `HIPPIUS_MEM_MNEMONIC`), then
> the founder runs `hippius-mem provision`. See [Operating model](REFERENCE.md#operating-model).

