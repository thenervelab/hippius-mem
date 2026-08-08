# Multi-admin design: m-of-n signer sets for the team manifest

**Date:** 2026-08-08
**Status:** Design only — explicitly not scheduled in this program
**Scope:** `hippius-mem-core` (`identity/manifest.rs`, `store/mod.rs`). Design and
open questions only; no implementation, no schema migration, no CLI change is
proposed to land from this document.

## Problem

The manifest recognizes exactly two authorities per team today: one founder
key, and an optional recovery key the founder names as a standby (manifest
format v2, `hippius-mem-core/src/identity/manifest.rs`). Both are single
keys — one signature authorizes a chain transition. A team that wants more
than one person able to add or remove members, name a recovery key, or
otherwise govern the team cannot express that: "founder" is a single point of
both capability and compromise, and "recovery" is a single point of failure
held in reserve, live at any moment (see learning 5 below). This document
generalizes the {founder, recovery} shape to an m-of-n signer set — a team
governed by any `m` of `n` designated admin keys — using what building the
two-key case (Phase B, Tasks 7-10 of the productization program) actually
taught, not a clean-room redesign.

## What Phase B taught, and that this design must carry forward

Building the recovery-key chain surfaced five facts about the trust model.
Each one shapes a specific part of the m-of-n design below, not just a
disclaimer at the end.

1. **The chain-of-custody election as built.** `load_manifest` re-derives
   trust from storage on every read: it keeps only manifests that verify and
   name the loading team, then elects the live one by walking ascending
   version groups from an anchor. Within one version group, `elect_from_group`
   ranks candidates by AUTHORITY, never by which object a listing happened to
   return first — a candidate the live manifest's own founder key signs beats
   one only its recovery key signs, at the same version, every time (`Authority::
   Founder` outranks `Authority::Recovery` — the ordering is a security control,
   not a label). The anchor is either the pinned founder's lowest-version
   manifest (an operator-config value the untrusted bucket cannot rewrite) or,
   unpinned, the genesis survivor — the lowest-version manifest among whatever
   verifies. Identity-point keys (the Ristretto all-zero point, which trivially
   "verifies" a forged signature over any message) are rejected globally inside
   `oplog::verify` itself, so every caller that treats a key as an
   authorization root — `authority_of`, `elect_live`'s anchor screen,
   `trusted_recovery_key` — inherits that rejection for free rather than
   re-implementing it per call site. An m-of-n scheme keeps this shape: election
   by authority-ranked version groups walked from a single anchor, with the
   identity-point screen enforced at the one choke point (signature
   verification), not scattered across authorization call sites.

2. **Recovery defends key LOSS, not COMPROMISE.** `recover_founder` is
   authorized purely by matching the live manifest's named recovery key — it
   does not, and structurally cannot, check whether the OLD founder key is
   still usable. So a founder who merely loses a device, while the key itself
   remains intact and unused, can still reclaim the team after a recovery has
   moved past them. Not through `MemoryStore`'s guarded convenience methods —
   `publish_membership` and `publish_recovery_key` both explicitly gate on
   `live.founder == self.author` (`store/mod.rs`), and once a recovery has
   happened `live.founder` names the recovery identity, so both correctly
   REJECT the old founder — but through the low-level free function
   underneath them, `publish_manifest` (`identity/manifest.rs`), which carries
   no such gate: it only checks `TeamManifest::verify()`, the manifest's OWN
   internal self-consistency (signature valid, `founder` decodes to
   `founder_key`), never who is CURRENTLY authorized. Any signer with a
   self-consistent manifest and bucket write access — the old founder's
   still-usable key, called through `publish_manifest` directly, or an
   equivalent raw bucket write with valid credentials — can write straight to
   the object key the recovery already occupies (one object per version; a
   write there overwrites, per `BlobStore::put`'s unconditional-overwrite
   contract). On the next election that overwritten manifest is signed by the
   SAME key that governed the version immediately before the recovery, so it
   passes the walk's Founder-authority check on its own terms. Recovery is a
   hedge against a key becoming unusable, not a way to revoke a key that is
   still usable. An m-of-n scheme inherits this exactly: any admin key that
   has not been affirmatively removed by a later, properly-authorized
   manifest remains able to act, however long it has sat idle.

3. **The founder-vs-recovery off-key tie is already solved; a founder-vs-founder
   one is the narrow residual; the risk m-of-n actually raises is a third,
   different thing.** Object keys are attacker-chosen — a manifest planted
   under a non-canonical key (`{team}/_manifest/!a`, say, rather than the
   canonical zero-padded version) sorts BEFORE every legitimate object — so an
   attacker holding a recovery key that a LIVE-but-early manifest still names
   could plant a manifest at a non-canonical key for the SAME version the
   genuine founder's next manifest occupies, using write access alone, no
   delete needed. `elect_from_group` exists precisely to defeat this: it ranks
   candidates by AUTHORITY, not by which object a listing returned first, so
   the founder-signed candidate at the canonical key always wins that tie
   regardless of where either object sits — this founder-vs-recovery case is
   already solved. What authority ranking does NOT arbitrate is a
   founder-vs-founder tie at an off-canonical key: two manifests both signed
   by the SAME live founder key rank equally, so the walk falls through to
   listing order there — the Task 9 residual, reachable in the two-key case
   only when two machines share one founder's key material and one of them
   writes off-canonical, an edge case there.

   **The risk m-of-n actually raises is neither of those — it is a silent
   lost-update overwrite at the CANONICAL key, which never produces a second
   object for the walk to see at all.** `manifest_key(team, version)` is a
   deterministic function of the version alone, and `BlobStore::put` is an
   unconditional overwrite. So when two HONEST, independently-authorized
   admins both observe live version `V` and each publish `V+1`, both writes
   target the exact same canonical object key, and the second write silently
   clobbers the first — no error, no warning, and no second candidate for
   `elect_from_group` to ever compare; the first admin's change is simply
   gone. In the two-key model this is rare: normal operation has one regular
   writer (the founder), and the recovery key acts only during an actual
   recovery, not as a second concurrent day-to-day writer. Under m-of-n,
   several admins independently managing the team day-to-day is ORDINARY
   operation, so this lost-update race is the NORMAL failure mode to design
   for, not a rare misconfiguration. A designed multi-admin scheme MUST close
   this at the write itself: a conditional write on publish (S3's
   `If-None-Match`-style "create only if this key does not already exist")
   makes the SECOND of two racing publishes to one version FAIL LOUDLY instead
   of silently overwriting, so the losing admin observes the conflict and
   republishes against the new live manifest instead of quietly losing their
   change. `BlobStore::put` today is unconditional ("overwriting any existing
   object at that key") — the trait itself would need a conditional variant
   before this fix could land. See [Open questions](#threshold-signatures-vs-multi-sig-lists).

4. **Delete-then-rechain residual.** Retirement is expressed by a later
   manifest, and the bucket is untrusted: an attacker holding a
   retired-but-still-usable recovery key, PLUS delete access to the bucket, can
   delete the manifests that retired it, rewinding the chain's anchor to a
   version that still names their key, and re-chain from there — the walk
   cannot detect this because every remaining object is genuine and mutually
   consistent, and `MemoryStore`'s monotonic version watermark does not help
   (the attacker re-chains to a HIGHER version than anything seen before, and
   the watermark only refuses lower ones). The documented mitigation is
   operational, not cryptographic: bucket object retention or versioning so a
   retiring manifest object cannot be deleted, plus pin hygiene (updating
   `founder_ss58` after a recovery). An m-of-n scheme does not remove this
   residual — a retired admin key plus delete access still rewinds the anchor
   the same way — and does not get to claim otherwise; the same operational
   mitigation is still the answer, now protecting more objects (every admin
   add/remove manifest, not just recovery-naming ones).

5. **A live recovery key is a full-power credential at any time, with write
   access alone.** `recover_founder` needs no cooperation from the founder,
   no proof the founder key is actually lost, and no delay — only a matching
   signature and write access to the bucket. It is not a break-glass mechanism
   gated on anything; it is a second, standing root of authority. This is the
   crux of the m-of-n vs. recovery tension addressed under
   [Open questions](#recovery-among-admins) below: any escape hatch that
   works when every other key is unavailable necessarily also works when every
   other key is merely inconvenient to reach, and a single unilateral key is
   what m-of-n exists to get away from.

## Generalizing {founder, recovery} to m-of-n

### The signer set

Today's `TeamManifest` carries one `founder_key: VerifyingKey` (the sole
signer of `sig`) and one optional `recovery_key: Option<VerifyingKey>` (a
second identity the CHAIN, not `verify()`, may let advance the manifest). An
m-of-n manifest format generalizes this to an admin set and a threshold:
an `admin_keys: BTreeSet<VerifyingKey>` (sorted, exactly like `members`, so
the signed bytes are a deterministic function of the *set* and iteration
order carries no information an attacker could exploit) and a `threshold: u32`
naming how many DISTINCT admin keys must co-sign a manifest for it to be
treated as authorized. `founder` need not disappear: it can stay as the
identity `founder_ss58` pins for ANCHOR purposes (whose genesis manifest do we
trust), separate from what governs subsequent transitions (m-of-n over the
live admin set) — the pin and the walk are already two independent concerns
in the code today (`load_manifest`'s two trust modes derive the SAME
`anchor_founder` value that `elect_live` then walks from identically), and
keeping that separation means the `founder_ss58` config field needs no schema
change to support m-of-n.

Sketch, not a proposed final API:

```
admin_keys: BTreeSet<VerifyingKey>   // was: founder_key (single)
threshold: u32                        // new: how many of admin_keys must co-sign
signatures: Vec<(VerifyingKey, Signature)>  // was: sig (single)
```

### Admin add/remove as chain acts

The productization program's standing rule — "every state change stays a
signed op; no side channels" — argues against a distinct "admin change" op
kind. Naming a recovery key today is not a special operation; it is an
ordinary manifest republish that happens to carry `Some(recovery_key)` inside
the same signed bytes `publish_membership` already uses to change `members`.
Adding or removing an admin should be the same shape: a new manifest version
whose `admin_keys` differs from the live one's, authorized exactly like any
other version transition — by reaching `threshold` signatures from the LIVE
(pre-change) admin set, not the candidate's own declared set. A candidate
cannot lower its own bar: the number of signatures required to accept version
`V+1` is a property the WALK reads off the live manifest at version `V`, never
a property the candidate at `V+1` asserts about itself — otherwise an attacker
holding one admin key could publish a manifest naming `threshold: 1` and
its own key as `admin_keys`, and nothing would stop it.

### `verify()` stays per-manifest; authorization stays in the walk

This split already exists in the two-key code and generalizes cleanly.
`TeamManifest::verify()` today proves a manifest is AUTHENTIC — the signature
checks out under `founder_key`, and `founder` decodes to exactly that key —
and nothing more; it does not ask whether `founder_key` is the team's real
founder. That question is answered entirely by `load_manifest`'s election,
which is separate from `verify()` by construction ("A signature proving a
manifest is authentic is therefore never enough to make it authoritative,"
per the module's own documentation). An m-of-n `verify()` should preserve
exactly this boundary: it checks that every listed `(key, signature)` pair is
authentic against the manifest's own signed bytes and that the listed keys are
pairwise distinct — internal well-formedness a manifest can prove about
itself, with no chain context required — while whether those keys are
CURRENT admins, and whether enough of them signed to clear `threshold`, is
answered by the walk (`authority_of` / `elect_from_group`), which is the only
place with access to what the LIVE manifest currently authorizes. Concretely,
`authority_of`'s single-key equality check (`candidate.founder_key ==
live.founder_key`, or `live.trusted_recovery_key() == candidate.founder_key`)
generalizes to a set-intersection cardinality check: at least `live.threshold`
of the candidate's authentically-signed keys must appear in `live.admin_keys`.

### Migration from v2 (recovery) manifests

The v1-to-v2 change already established the pattern a v2-to-v3 (m-of-n) change
would reuse: `signing_bytes` branches on a domain tag
(`hippius-memory-manifest/v1` vs. `.../v2`) that is the SAME byte length at a
FIXED offset, which is what makes a v1 message and a v2 message provably
unable to collide — the manifest's own documentation is explicit that this
argument does not carry over automatically to a domain tag of a DIFFERENT
length, and would need to be re-derived for any v3 tag. `TeamManifest` has no
`deny_unknown_fields`, so an old (v1/v2) binary reading a v3 manifest object
does not fail to DESERIALIZE it — it silently ignores the unrecognized
`admin_keys`/`threshold`/multi-signature fields, then `verify()` fails because
the signing bytes it reconstructs (still the v1/v2 shape) do not match what
was actually signed (the v3 shape) — so an old client fails CLOSED, via a
signature mismatch, without needing to recognize the new format at all. This
is the same "skip-not-fatal" property `load_manifest` already relies on for
junk and foreign-team objects; a v3 rollout should be designed to fail closed
the identical way, not a new mechanism.

The live-team migration path itself is a chain act, not a cutover: the
CURRENT founder (or recovery key, if that is who is live) publishes a v3
manifest at `live.version + 1` naming the initial `admin_keys` (which should
include the founder's own key, mirroring today's "the founder is always
inserted into members") and a `threshold`. This is authorized under a
one-time BRIDGE rule the walk needs, and only needs once per team: a v3
candidate is accepted from a v1/v2 live manifest if ANY of its authentically-
signed keys equals the live manifest's `founder_key` or trusted
`recovery_key` — exactly today's `authority_of` rule, just evaluated against a
candidate that happens to carry multiple signatures instead of one. Every hop
AFTER that first v3 manifest is ordinary m-of-n-against-the-live-admin-set.
No change is needed to the v1/v2 code path itself; the bridge is new match
arms in `authority_of`, not a rewrite of the existing ones.

## Open questions

### Threshold signatures vs multi-sig lists

Two shapes could realize "m-of-n signers," and this document does not choose
between them:

- **Multi-sig list.** The manifest carries a list of `(key, signature)` pairs,
  each independently verified with the exact primitive already in use
  (schnorrkel signature verification over `signing_bytes`); authorization asks
  whether enough of them are drawn from the live admin set. This is the shape
  sketched above — it reuses today's verification code unchanged, at the cost
  of a manifest whose size grows with `threshold` and a coordination step
  (collecting `m` signatures before publish) that does not exist today.
- **Threshold signature** (e.g., FROST-style threshold Schnorr). The admin set
  collaboratively produces ONE aggregate public key and, per publish, one
  ordinary-looking signature; `TeamManifest` would need no new fields beyond
  what it has today; `verify()` would be unchanged, keys and structure
  included. The cost moves entirely out of `manifest.rs` and into a new
  subsystem: a distributed key-generation ceremony, a signing-session
  coordination protocol among `m` of `n` parties, and — the open, unverified
  question — whether an aggregate-key/threshold-signature scheme is
  compatible with sr25519/schnorrkel verification as this codebase uses it
  today, or requires a distinct verification path entirely. That
  compatibility question is unresearched here and would need its own spike,
  in the same spirit as this program's other verification spikes, before
  either shape is committed to.

### Recovery among admins

Should "recovery" survive as a concept distinct from the admin set, or should
every admin simply hold recovery-equivalent power under threshold `m`? Neither
answer avoids the tension learning 5 names:

- **Recovery stays a separate root.** A single standing key can act alone,
  bypassing the m-of-n requirement entirely by design — otherwise a team that
  loses every admin key at once (not implausible for a small team) has no way
  back in. But a key that can act alone in that scenario can act alone in
  ANY scenario; nothing about the chain distinguishes "every admin is
  genuinely gone" from "one recovery key is being used early." This is
  exactly today's residual, unreduced.
- **No standalone recovery; a reduced threshold instead.** Some `m' < m` (down
  to `m' = 1`) admins could invoke a lower bar when "enough" of the set is
  lost. But the chain has no oracle for "these keys are gone" — a bucket-based
  system cannot distinguish a genuinely lost key from one whose holder simply
  did not sign this time. A reduced-threshold escape hatch is, from the
  chain's point of view, indistinguishable from a live admin choosing to
  invoke it whenever convenient — the same problem relocated, not solved.

No design closes this gap without either accepting a standing single-key risk
or asserting something about key availability the untrusted bucket cannot
verify. Recording the tension is this document's job; resolving it is not.

## Out of scope, and why this is not scheduled

This document is design and open questions only. It proposes no `TeamManifest`
field, no new domain tag, no `BlobStore` conditional-write method, no CLI
surface, and no test. Per the productization program's design
(`docs/plans/2026-08-07-productization-program-design.md`, Out of scope):
"Full multi-admin signer-set implementation (design doc only)." A real
implementation needs, at minimum: the threshold-signature-vs-multi-sig-list
choice resolved (including the compatibility spike above), a `BlobStore`
conditional-write primitive designed and verified against the Hippius
gateway's S3 compatibility, the recovery-among-admins question settled with
an explicit accepted risk rather than left open, and its own TDD-driven
implementation plan reviewed with the same adversarial rigor as Phase B. None
of that is scheduled in this program.
