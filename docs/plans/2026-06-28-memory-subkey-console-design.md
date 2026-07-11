# Memory subkey: one console key to use the service

**Date:** 2026-06-28
**Status:** Design accepted, not yet implemented
**Scope:** `hippius-console` (most of the work), `hippius-mem` (small), `hippius-s3` (none)

## Problem

`hippius-mem` (the team-memory MCP server — internally "the MPC") today needs a
developer to assemble four secrets by hand in `hippius-mem.toml`: the S3
sub-token (`access_key_id` + `secret`), a `team` namespace, a `team_key_hex`
encryption key, and an `author_seed_hex` signing seed. Onboarding is a chain of
manual steps (mint a token, hand-copy a team key out of band). The goal is: a
user creates **one subkey on the console**, pastes **one bundle**, and the
memory service runs.

## Decisions (and why)

These were settled during the 2026-06-28 brainstorm. They are deliberately the
*smallest* shapes that deliver the outcome.

1. **The subkey is off-chain only (v1).** The chain (`thebrain`) does support
   `pallet_proxy` (`ProxyType::{Any,NonTransfer,Governance,Staking}`, zero
   deposit) and `pallet_identity` sub-accounts — but every *user-callable* write
   path is gated: Marketplace usage updates require the single
   `SubscriptionCanceller` account, Arion merkle-anchoring
   (`submit_attestation_commitment`) requires the hardcoded `ArionAdminMembers`
   origin, and Arion file-size updates require a registered Validator. A normal
   user's memory subkey has **no on-chain action it can perform**, so an on-chain
   proxy registration buys nothing in v1. Deferred, not designed out.

2. **Bundled author key, zero backend change.** The S3 backend (`hippius-s3`)
   already binds a sub-token to an SS58 `account_id`, and requires the buckets it
   scopes to be owned by that same SS58. Rather than fight that, the **main
   account** (already signed in on the console) owns the bucket and owns the
   sub-token — exactly as the existing `mint-token` flow does. The **subkey** is a
   *freshly generated* sr25519 keypair whose only role is to **sign the op-log**
   (`author_seed_hex` → author SS58 on every note). It owns nothing on the
   backend, so the backend never has to learn about it. This is why `hippius-s3`
   needs no change.

3. **Founder-instant, joiner-paste for the team key.** `team_key_hex` is the only
   secret the console *cannot* produce — client-side encryption means the backend
   never sees it. The founder's wizard generates a fresh one; a joiner must
   receive it from the team. See [Team key](#team-key).

## Encryption boundary (invariant)

**All note *content* is encrypted inside `hippius-mem` (the MPC) before anything
is stored — no plaintext note content ever leaves the process.** This is a hard
invariant the subkey work must not weaken, and it is already true in the code
(verified 2026-06-28):

- `crypto::seal(key, plaintext, aad)` (`hippius-mem-core/src/crypto.rs:101`)
  encrypts with **XChaCha20-Poly1305** (24-byte nonce from the OS CSPRNG) before
  anything is stored. `MemoryStore::remember`/`edit` seal the note JSON
  (summary, body, tags) *before* calling `blob.put`, and bind the ciphertext to
  its object key as AEAD associated data.
- `BlobStore` (`hippius-mem-core/src/store/blob.rs:38`) documents its contract:
  "values are already-sealed ciphertext — this layer neither encrypts nor
  interprets them." For note blobs, `S3BlobStore` only ever sees
  `nonce ‖ ciphertext+tag`.
- HCFS is **not in the data path.** Memory blobs go straight to the S3 gateway
  with the sub-token; no HCFS server mediates and no note content is delegated.

**What is NOT encrypted — and why.** The Phase-2 op-log objects are stored as
*signed cleartext JSON* (`OpLogStore::append`, `hippius-mem-core/src/oplog/store.rs:85`):
each op carries metadata — the author SS58, the object key (which embeds the
`team` and `repo` names), the Lamport clock, the key epoch, BLAKE3 content
hashes, and the signature — but **never** the note summary/body/tags. This is by
design: the op-log is the team's independently verifiable, convergent audit
trail, so its envelope must be readable to replay, converge, and Merkle-anchor
it. The consequence is that the S3 gateway operator can see team/repo names,
author identities, and activity volume/timing for the op-log — they cannot see
note content. If hiding that metadata from the gateway is required, it is a
separate piece of work (e.g. sealing or tokenising the op-log envelope), not part
of this plan. The accurate one-line invariant is therefore "**no plaintext note
content leaves the MPC**," not "only ciphertext leaves."

The plan pins the note-content invariant with a regression guard (a spy
`BlobStore` asserting every `put` payload is non-plaintext and decrypts), and
`hippius-mem doctor` proves it
live by sealing before the probe `put` and asserting the stored object is
ciphertext.

## The bundle

The unit the console produces is `hippius-mem`'s existing config schema — so
consuming it requires no parser change:

```toml
# hippius-mem.toml  — produced by the console "Memory key" wizard
bucket          = "ourovoros-memory"   # owned by the main account
team            = "ourovoros"          # shared namespace string
access_key_id   = "hip_AKID..."        # main-account-owned sub-token
secret          = "..."                # shown once
author_seed_hex = "…32 bytes hex…"     # dedicated fresh author identity
team_key_hex    = "…32 bytes hex…"     # encryption key (founder: fresh; joiner: pasted)
```

## Data flow

```
console (main account signed in)
  ├─ ensure bucket   POST /api/objectstore/buckets/        [existing]
  ├─ mint sub-token  POST /api/objectstore/sub-tokens/     [existing]
  │     scope_type=single_bucket, bucket_names=[bucket],
  │     actions=[read,write], account_id = main SS58
  ├─ generate subkey seed   @polkadot/keyring (fresh)      [new, client-side]
  ├─ team key               fresh 32 bytes | pasted        [new]
  └─ render bundle + copy + download hippius-mem.toml      [new]
        ↓  user pastes
hippius-mem  →  signs ops with subkey, reads/writes blobs with sub-token
```

Every secret-bearing call stays on a path that already exists. The new code is a
client-side keypair generator and a bundle renderer.

## Console work (the bulk)

Lives alongside the existing sub-token UI, which already hosts a shared
dialog-state pattern in `src/components/s3/sub-tokens/index.tsx`.

New files:

```
src/components/s3/service-keys/
  CreateMemoryKeyDialog.tsx     # the wizard
  MemoryKeyResultDialog.tsx     # bundle render, copy + download, "secret shown once"
src/lib/hooks/useMemoryKey.ts   # orchestration
```

Wizard steps, reusing existing hooks end-to-end:

1. **Bucket** — reuse `useApiBuckets`; pick existing or create (`CreateBucketDialog`
   mutation). Suggest `"<team>-memory"`.
2. **Team name** — free text; defaults from the bucket.
3. **Subkey** — `new Keyring({type:"sr25519"}).addFromMnemonic(mnemonicGenerate())`,
   **fresh**, client-side, never the user's main mnemonic. Export its seed hex as
   `author_seed_hex`. Adds only `mnemonicGenerate` from `@polkadot/util-crypto`;
   `@polkadot/keyring` is already imported in `WalletAuthContext.tsx`.
4. **Sub-token** — reuse `useApiTokens` create: `single_bucket`, `[bucket]`,
   `["read","write"]`, owned by the main account (today's behavior).
5. **Team key** — new vs join (below).
6. **Result** — render the full `hippius-mem.toml` and the `.mcp.json` env block;
   copy + download; the S3 `secret`, `author_seed_hex`, and `team_key_hex` are
   **shown once**, mirroring `TokenDetailsDialog`'s existing "will not be displayed
   again" warning.

**Honesty constraint:** the wizard generates secrets the backend never stores
(subkey seed, team key). The download-once UX is load-bearing — if the user loses
the bundle, the sub-token can be *rotated* but the author identity and team key
are *gone*. The result dialog must say this in plain words.

## Team key

- **Create new memory (founder):** wizard generates a fresh random `team_key_hex`
  into the bundle. Fully instant.
- **Join existing memory:** the console cannot hand out the team key (it never
  sees it). Wizard "Join" mode has a paste field; the joiner drops in the
  `team_key_hex` a teammate gave them, and the wizard assembles the rest of the
  bundle around it. The console still mints their sub-token + author subkey
  instantly.
- **Deferred v2 (seam, not scope):** the repo already has cryptographic key
  distribution — `provision_team_key` / `rotate_team_key` wrap the key to each
  member's x25519 key, and startup bootstraps it from `HIPPIUS_MEM_MNEMONIC`.
  These were library-only when this doc was written. v2 promotes them to
  `hippius-mem` subcommands so a founder approves a joiner and the joiner
  bootstraps from their own subkey — no hex copying.
  > **Update (shipped #46/#51):** the CLI seam now exists — `hippius-mem join`,
  > `provision`, and `members` are real subcommands. Only `rotate_team_key`
  > remains library-only.

## hippius-mem work (small)

1. **`hippius-mem doctor` (new) — the "runs instantly" guarantee.** Decode
   `author_seed_hex` → SS58, check `team_key_hex` is 32 bytes, and do a real
   read/write probe against the bucket with the sub-token. Turns "paste and pray"
   into "paste and verify."
2. **Author-identity divergence.** `mint-token` derives the author SS58 from the
   *main* mnemonic; the console path uses a *fresh dedicated* subkey, so the two
   onboarding paths produce different authors. The **console bundle is
   canonical**; `mint-token` stays as the no-console CLI path with its docs noting
   it authors as the main account. (Optional later: teach `mint-token` to emit a
   fresh subkey so both paths converge.)
3. **Docs.** Replace the "mint-token + hand-copy team_key" runbook with "create a
   Memory key in the console → paste the bundle → `hippius-mem doctor`."

## HCFS alignment

Alignment is at the **identity layer**, and the **cipher already matches**. The
subkey is an sr25519 SS58 — the same identity scheme HCFS uses as its client
bearer — so the *same* dedicated subkey can later double as an HCFS client
identity, making "one subkey, both services" true. Both services encrypt with
**XChaCha20-Poly1305 (24-byte nonce)**; they differ only in key *derivation*
(HCFS from the mnemonic seed, memory from the shared team key) and in *where*
encryption sits — and for memory it sits squarely in the MPC (see
[Encryption boundary](#encryption-boundary-invariant)). No cipher harmonization
is needed.

## Non-goals (v1)

- No on-chain proxy registration.
- No `hippius-s3` backend change.
- No wrapped-key CLI (that is the v2 seam above).
- No cipher change (memory already uses XChaCha20-Poly1305, same as HCFS).
- No op-log / audit / retrieval changes.
- No move of encryption out of the MPC — the encryption boundary above is fixed.

## Testing

- **Console:** unit-test the bundle renderer (TOML + `.mcp.json` correctness,
  secret-shown-once); orchestration test with mocked `useApiBuckets` /
  `useApiTokens`.
- **hippius-mem:** tests for `doctor` (bad seed length, wrong key size, dead
  sub-token), reusing the existing console wire-contract tests that already pin
  the API shapes.
- **Live smoke:** console (staging) → bundle → `doctor` → `remember` / `recall`
  round-trip.

## Evidence trail (cross-repo, 2026-06-28)

- Console sub-token API + auth: `hippius-console` `src/lib/hooks/useApiTokens.ts`,
  `WalletAuthContext.tsx`; mirrored in `hippius-mem-core/src/identity/console.rs`.
- Backend binds sub-tokens to SS58: `hippius-s3`
  `hippius_s3/models/sub_token.py` (`SubTokenScope.account_id` = SS58),
  `api/sub_token_scopes.py`; buckets owned by `main_account_id`; a `sub_accounts`
  table existed and was dropped (migration 2025-06-03).
- Chain proxy + identity + gated writes: `thebrain` `runtime/mainnet/src/lib.rs`
  (`pallet_proxy`, `pallet_identity`), `pallets/marketplace`, `pallets/arion-pallet`.
- HCFS one-mnemonic identity + XChaCha20: `hcfs` `hcfs-client/src/drive/init.rs`,
  `drive/upload.rs`, `hcfs-chain-reporter`.
