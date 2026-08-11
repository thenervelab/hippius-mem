//! Arbitrary bytes into every deserializer a bucket object reaches.
//!
//! Every other hostile-input test in this crate hands the code a hand-built Rust
//! struct that was re-serialized to JSON. That is not the untrusted bucket's
//! primitive. The bucket's primitive is *arbitrary bytes at an attacker-chosen
//! key*: anyone with write access can PUT anything anywhere, and the reader has
//! to survive it. Nothing here had ever fed raw bytes to a wire type's
//! deserializer, so this file does.
//!
//! `cargo-fuzz` wants nightly and this workspace pins stable, so the mechanism is
//! a proptest over byte vectors: it runs in the ordinary suite on the pinned
//! toolchain, on every PR, and shrinks to a counterexample when it fails.
//!
//! # The vacuity trap, and how this file avoids it
//!
//! "Arbitrary bytes never yield a verified `X`" is **vacuously true if nothing
//! ever parses**, and uniform random bytes essentially never form valid JSON — so
//! a naive version of this test passes thousands of cases without once reaching a
//! verification function. Two strategies, with measured and *asserted* reach,
//! are the answer:
//!
//! 1. **Unstructured** — uniform bytes, `0..4096` of them. This is the real
//!    primitive and it is cheap, but its measured reach is **0%**: across all six
//!    types, not one input in 2048 got a value out of the reader it was fed to.
//!    It proves the readers do not panic and do not accept garbage; it does
//!    **not** exercise any verifier, and nothing here should be read as claiming
//!    it does.
//! 2. **Structurally biased** — take a genuine, correctly-signed value, serialize
//!    it, then either edit one to three bytes in place or truncate it at a random
//!    offset. This is the strategy that actually reaches the verifiers. Measured
//!    reach, as the fraction of generated inputs that deserialized into a value
//!    the honest producer never made, over four runs of 2048 cases per type:
//!
//!    | Type | reached the verifier | asserted floor |
//!    |---|---|---|
//!    | `Op` | 18-19% | 9% |
//!    | `TeamManifest` | 32-35% | 16% |
//!    | `WrappedKey` | 9% | 4% |
//!    | `AnchorRecord` | 14-17% | 7% |
//!    | `HeadPointer` | 25-27% | 12% |
//!    | `HeadWatermarks` | 14-16% | 7% |
//!
//! Every one of those rates is asserted against its own floor, so a wire-format
//! change that collapses the reach of ONE type turns this file red instead of
//! letting it rot into a test that checks nothing. Per-type rather than one shared
//! floor precisely so the guard stays sensitive: a single floor low enough for
//! `WrappedKey` would not notice `TeamManifest` losing three quarters of its
//! reach. The floors sit near half the observed rate — the run-to-run spread above
//! is roughly one percentage point, so that is a wide margin against flake and
//! still a long way above zero.
//!
//! `WrappedKey` is the laggard for a structural reason worth knowing: its
//! `ephemeral_public` and `ciphertext` fields serialize as JSON arrays of decimal
//! numbers, where an edit very often produces a leading zero, an empty element or
//! a value above 255 — all parse errors. The hex-and-base58 documents are far more
//! forgiving of a single byte.
//!
//! An edit is guaranteed to change the byte it lands on, but a changed byte is
//! not always a changed *value* — a `Ulid` decodes case-insensitively, for one —
//! so an input that round-trips to exactly the honest seed is counted separately
//! and excluded from the property. Reproducing the honest value is not a forgery.
//!
//! # What "verification fails" means per type, because it is not uniform
//!
//! Four of the six carry their own cryptography and the property is crisp: if the
//! bytes parse into something other than the honest value, verification must
//! fail. `Op` and `HeadPointer` are rejected on *either* a bad signature or a
//! broken `author`-to-`author_key` binding, so the assertion is that the
//! conjunction fails — not that both fail independently, which is false (an edit
//! to `lamport` breaks the signature and leaves the identity binding intact).
//!
//! [`AnchorRecord`] carries **no signature at all**. Its only cryptographic
//! binding is `root == merkle_root(leaves)`, and `read_anchor_records`
//! deliberately does *not* enforce it — a self-consistent forgery is meant to
//! flow through to `reconcile` to be reported rather than silently dropped. So
//! the property here is what is actually true: hostile bytes must not mint a
//! *new* leaf set that reproduces an anchored root (a second preimage), and every
//! record the reader hands back must satisfy the four invariants it promises to
//! filter on.
//!
//! Be honest about the strength of that second half. It is asserted on every
//! record the reader returns, but how often it can actually *catch* a dropped
//! filter depends on how often a byte edit produces a record violating that
//! particular filter, and the four are not equal. Mutation-verified: deleting the
//! `root`-vs-`receipt.root` filter fails this test reliably (those two fields are
//! 128 of the document's bytes, so the mismatch is generated constantly), while
//! deleting the `op_count`-vs-leaf-count filter did **not** fail a 2048-case run —
//! `op_count` is a single digit, and an edit lands on it only a couple of times a
//! run. The empty-leaves and duplicate-leaf filters are weaker still, since byte
//! editing cannot delete or repeat an array element at all. Those three are
//! covered by the targeted unit tests in `audit::batch`; this file is not their
//! primary guard and must not be mistaken for it.
//!
//! [`HeadWatermarks`] is **local state, not bucket wire**: it is read from a file
//! on this machine's disk, and its module puts "anyone who can write local disk"
//! explicitly out of scope — a corrupt or unknown-version file warns and behaves
//! as empty rather than erroring, so that a local attacker cannot brick the audit
//! by making the file undecodable. There is therefore no integrity guarantee here
//! to assert, and it would be wrong to write one: a well-formed file yields marks
//! by design, because that *is* what persistence means. What is true, and what is
//! asserted, is totality (arbitrary bytes never panic `load` or `observe`) plus
//! containment: a regression the audit reports must name an author whose key
//! literally appears in the file's bytes, under the address that key encodes to.
//! A fabricated mark matters because a *raised* mark is permanent and unclearable
//! against an honest author.

#![expect(
    clippy::panic_in_result_fn,
    reason = "these tests use `?` for fixture setup but assert on outcomes; the assertions are the test, not a crash to avoid"
)]

use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hippius_mem_core::{
    AnchorReceipt, AnchorRecord, AnchorRef, BatchMeta, Blake3Hash, BlobStore, HeadPointer,
    HeadWatermarks, MemoryBlobStore, NetworkPrefix, NoteId, Op, OpContent, OpKind, SecretKey,
    Signer, Sr25519Signer, TeamManifest, VerifiedHeads, WrappedKey, merkle_root, publish_head,
    read_anchor_records, read_heads, ss58_encode, unwrap_team_key, wrap_team_key,
};
use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestRunner};
use x25519_dalek::{PublicKey, StaticSecret};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Cases drawn per strategy per type. Each of the six types runs both
/// strategies, so a full pass is twelve runs of this many inputs.
const CASES: u32 = 2048;

/// Upper bound on an unstructured input's length. The bucket has no length
/// limit, but past a few kilobytes the extra bytes only make `serde_json` fail
/// further along the same path.
const UNSTRUCTURED_MAX_LEN: usize = 4096;

/// How many bytes one biased sample edits. Kept small on purpose: reach falls
/// off roughly geometrically per edit (most bytes of these documents sit inside
/// a constrained alphabet — hex, base58, Crockford base32 — where a wrong byte
/// is a parse error), and reach is the whole point of the biased strategy.
const MAX_EDITS: usize = 3;

/// How far either side of an edit site [`EditSource::Nearby`] may copy a
/// replacement byte from.
///
/// This is the knob that buys reach, and the reason it works is locality, not
/// schema knowledge. These documents are runs of same-alphabet characters —
/// a 128-character hex signature, a 48-character base58 address — so a byte
/// copied from a few positions away is very likely to be legal where it lands,
/// while a uniformly random byte is a parse error roughly 94 times in 100. Wide
/// enough to cross a field boundary sometimes (that is a useful case too),
/// narrow enough to stay inside a long field most of the time.
const NEIGHBOURHOOD: usize = 16;

/// Weight of copying a replacement byte from near the edit site.
const NEARBY_WEIGHT: u32 = 7;

/// Weight of drawing a replacement byte from the document's distinct byte set.
const ALPHABET_WEIGHT: u32 = 2;

/// Weight of drawing a replacement byte from the full `0..=255` range, so the
/// biased strategy is not closed over the seed document's own alphabet.
const RAW_WEIGHT: u32 = 1;

/// Weight of the edit operator against [`TRUNCATE_WEIGHT`].
const EDIT_WEIGHT: u32 = 9;

/// Weight of the truncation operator.
///
/// Low, and deliberately so: `serde_json::to_vec` emits compact JSON that ends in
/// `}`, so a truncated document essentially never parses. Truncation is a real
/// thing a bucket can serve (a half-written PUT, a range read) and is worth
/// covering, but every truncated sample is a sample that does not reach a
/// verifier, so it is held to a tenth of the draws.
const TRUNCATE_WEIGHT: u32 = 1;

/// Reach floors, in percent of generated inputs, one per type.
///
/// Each is roughly half the rate observed over four runs (see the module docs for
/// the measured table and for why they differ so much between types). The number
/// that matters is not any one of these but the fact that they are *asserted*: a
/// wire-format change that stops these documents parsing must make this file red,
/// not quietly turn the property above into a tautology.
mod floors {
    /// `Op`, observed 18-19%.
    pub(super) const OP: usize = 9;

    /// `TeamManifest`, observed 32-35%.
    pub(super) const TEAM_MANIFEST: usize = 16;

    /// `WrappedKey`, observed 9% — the numeric-array wire form is the least
    /// tolerant of a single edited byte.
    pub(super) const WRAPPED_KEY: usize = 4;

    /// `AnchorRecord`, observed 14-17%.
    pub(super) const ANCHOR_RECORD: usize = 7;

    /// `HeadPointer`, observed 25-27%.
    pub(super) const HEAD_POINTER: usize = 12;

    /// `HeadWatermarks`, observed 14-16%.
    pub(super) const HEAD_WATERMARKS: usize = 7;
}

/// The team every fixture belongs to.
const TEAM: &str = "wire-fuzz-team";

/// The key epoch the fixture team key is wrapped under.
const KEY_EPOCH: u64 = 7;

/// The `seq` the fixture anchor record is written at.
const ANCHOR_SEQ: u64 = 4;

// ---------------------------------------------------------------------------
// Reach accounting
// ---------------------------------------------------------------------------

/// What one generated input did when handed to the type's reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    /// The reader produced nothing: the bytes did not deserialize, or (for the
    /// watermark file) decoded to no marks at all.
    Nothing,

    /// The reader produced exactly the honest value the seed carries. A
    /// byte-level edit that round-trips to the same value is not a forgery, so
    /// this case is excluded from the property and from the reach floor.
    HonestValue,

    /// The reader produced a value the honest producer never made. This is the
    /// case the properties are about, and the case the reach floor counts.
    AlteredValue,
}

/// How far one run of a strategy actually got.
#[derive(Debug)]
struct Reach {
    /// Inputs drawn (including proptest's own re-runs during shrinking, which
    /// only happen on a failure the caller is about to report anyway).
    generated: usize,

    /// Inputs that reproduced the honest value exactly.
    honest: usize,

    /// Inputs that reached the verification under test with an altered value.
    altered: usize,
}

impl Reach {
    /// The altered-value reach as a whole percentage of generated inputs.
    ///
    /// Integer arithmetic so the reported number and the asserted number are
    /// computed the same way and cannot disagree at a boundary.
    fn altered_percent(&self) -> usize {
        if self.generated == 0 {
            return 0;
        }

        self.altered * 100 / self.generated
    }
}

/// Assert that the biased strategy still reaches the verifier often enough for
/// the property above it to mean anything.
///
/// This is the vacuity guard. Without it, a wire-format change that makes these
/// documents stop parsing would leave every property below passing with an empty
/// body, and nothing would say so.
fn assert_reach_floor(label: &str, reach: &Reach, floor_percent: usize) {
    assert!(
        reach.altered * 100 >= reach.generated * floor_percent,
        "{label}: the structurally-biased strategy reached the verifier with an altered value \
         only {}/{} times ({}%), below the {floor_percent}% floor. The property above this \
         assertion is therefore close to vacuous: it is passing because almost nothing parsed, \
         not because forgeries were rejected. Fix the strategy or the wire format, do not lower \
         the floor. ({} inputs reproduced the honest value exactly.)",
        reach.altered,
        reach.generated,
        reach.altered_percent(),
        reach.honest,
    );
}

/// Run `probe` over every input `strategy` draws, tallying how far each got.
///
/// `probe` returns the reach of one input and fails the case by returning a
/// [`TestCaseError`] — `prop_assert!` inside it shrinks as usual.
fn run_bytes_property<P>(label: &str, strategy: &BoxedStrategy<Vec<u8>>, probe: P) -> Reach
where
    P: Fn(&[u8]) -> Result<Reached, TestCaseError>,
{
    let generated = AtomicUsize::new(0);
    let honest = AtomicUsize::new(0);
    let altered = AtomicUsize::new(0);

    // `failure_persistence: None` on purpose. `proptest-regressions/` is tracked
    // in this repo, and a failure written there during a mutation-testing run
    // would pin a case that only fails under the mutation and turn the build
    // permanently red. The shrunk counterexample is reported in the assertion
    // message instead, which is what a reader needs.
    let config = ProptestConfig {
        cases: CASES,
        failure_persistence: None,
        ..ProptestConfig::default()
    };

    let outcome = TestRunner::new(config).run(strategy, |bytes| {
        generated.fetch_add(1, Ordering::Relaxed);

        match probe(&bytes)? {
            Reached::Nothing => {}
            Reached::HonestValue => {
                honest.fetch_add(1, Ordering::Relaxed);
            }
            Reached::AlteredValue => {
                altered.fetch_add(1, Ordering::Relaxed);
            }
        }

        Ok(())
    });

    assert!(
        outcome.is_ok(),
        "{label}: hostile bytes were accepted where verification had to fail. {}",
        outcome
            .as_ref()
            .err()
            .map_or_else(String::new, ToString::to_string),
    );

    Reach {
        generated: generated.load(Ordering::Relaxed),
        honest: honest.load(Ordering::Relaxed),
        altered: altered.load(Ordering::Relaxed),
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Uniform bytes: exactly what an attacker can PUT at a key they control.
///
/// Measured reach against every type in this file: 0 of 2048. It is here because
/// it is the honest primitive and it proves nothing panics, not because it
/// exercises a verifier.
fn unstructured_bytes() -> BoxedStrategy<Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..UNSTRUCTURED_MAX_LEN).boxed()
}

/// Where one edit's replacement byte comes from.
#[derive(Debug, Clone, Copy)]
enum EditSource {
    /// Copy the byte sitting `delta - NEIGHBOURHOOD` positions from the edit
    /// site, wrapping at the document's ends. `delta` is stored pre-biased so the
    /// arithmetic stays in `usize`.
    Nearby(usize),

    /// Take the entry at this index (modulo) of the document's distinct,
    /// ascending byte set.
    Alphabet(u8),

    /// Take this byte, whatever it is.
    Raw(u8),
}

/// Draw one replacement source, weighted toward the locality splice that
/// actually keeps documents parseable.
fn edit_source() -> impl Strategy<Value = EditSource> {
    prop_oneof![
        NEARBY_WEIGHT => (0..=NEIGHBOURHOOD * 2).prop_map(EditSource::Nearby),
        ALPHABET_WEIGHT => any::<u8>().prop_map(EditSource::Alphabet),
        RAW_WEIGHT => any::<u8>().prop_map(EditSource::Raw),
    ]
}

/// A genuine, correctly-produced document with one to three bytes edited in
/// place, or truncated at a random offset.
///
/// This is the strategy that reaches the verifiers; see the module docs for the
/// measured rates and [`NEIGHBOURHOOD`] for why the replacement byte usually
/// comes from near the edit site.
fn tampered_bytes(seed: Vec<u8>) -> BoxedStrategy<Vec<u8>> {
    let alphabet: Vec<u8> = seed
        .iter()
        .copied()
        .collect::<BTreeSet<u8>>()
        .into_iter()
        .collect();
    let len = seed.len();
    assert!(
        len > NEIGHBOURHOOD,
        "a seed document shorter than the splice window would underflow the neighbour index"
    );

    let edited = {
        let seed = seed.clone();

        prop::collection::vec((0..len, edit_source()), 1..=MAX_EDITS)
            .prop_map(move |edits| apply_edits(&seed, &alphabet, &edits))
    };

    // `0..len` rather than `0..=len`: cutting at `len` would hand back the
    // pristine document, which the edit arm already covers more usefully.
    let truncated = (0..len).prop_map(move |cut| seed[..cut].to_vec());

    prop_oneof![
        EDIT_WEIGHT => edited,
        TRUNCATE_WEIGHT => truncated,
    ]
    .boxed()
}

/// Apply `edits` to a copy of `seed`, guaranteeing each one changes the byte it
/// lands on.
///
/// A no-op edit would hand the property a pristine, correctly-signed document
/// and read as a forgery that verified, so a replacement that matched the byte
/// it replaces is rejected and the document's own alphabet is scanned for one
/// that differs. Two edits may still land on the same position and cancel; that
/// case is caught by the honest-value check in each probe rather than here.
fn apply_edits(seed: &[u8], alphabet: &[u8], edits: &[(usize, EditSource)]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let len = bytes.len();

    for &(position, source) in edits {
        let current = bytes[position];

        let candidate = match source {
            EditSource::Nearby(delta) => bytes[(position + len + delta - NEIGHBOURHOOD) % len],
            EditSource::Alphabet(index) => alphabet[usize::from(index) % alphabet.len()],
            EditSource::Raw(byte) => byte,
        };

        bytes[position] = if candidate == current {
            first_alphabet_byte_other_than(alphabet, current)
        } else {
            candidate
        };
    }

    bytes
}

/// The first byte in `alphabet` that is not `current`.
///
/// The fallback is unreachable — any JSON document holds at least two distinct
/// bytes, so the scan always finds one — but it is written out rather than
/// unwrapped so the workspace's panic lints stay honest.
fn first_alphabet_byte_other_than(alphabet: &[u8], current: u8) -> u8 {
    alphabet
        .iter()
        .copied()
        .find(|candidate| *candidate != current)
        .unwrap_or(current ^ 0x01)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A deterministic signer, so the seed documents (and therefore the measured
/// reach) are the same on every machine and every run.
fn signer(seed: u8) -> Result<Sr25519Signer, Box<dyn std::error::Error>> {
    Ok(Sr25519Signer::from_seed_with_prefix(
        &[seed; 32],
        NetworkPrefix::HIPPIUS,
    )?)
}

/// Turn any error into a case failure, for the fallible steps inside a probe.
fn tce(err: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(err.to_string())
}

/// Render fuzzed bytes for a failure message. These documents are JSON when they
/// matter, so the lossy string is what a reader actually wants to see.
fn rendered(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `WrappedKey` does not derive `PartialEq` (it is a ciphertext envelope, never
/// compared in production), so the honest-value check spells the comparison out.
fn same_wrapped_key(left: &WrappedKey, right: &WrappedKey) -> bool {
    left.epoch == right.epoch
        && left.ephemeral_public == right.ephemeral_public
        && left.ciphertext == right.ciphertext
}

/// The object key an anchor record for `author_key` at `seq` lives under.
///
/// Mirrors the module-private `anchor_record_key`, which is documented as
/// `{team}/_anchors/{author_key}/{seq:020}`. `read_anchor_records` does not check
/// a record against its own path (unlike `read_heads`), so this only has to land
/// under the prefix the reader lists.
fn anchor_key(author_key_hex: &str, seq: u64) -> String {
    format!("{TEAM}/_anchors/{author_key_hex}/{seq:020}")
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

#[test]
fn arbitrary_bytes_never_yield_a_verified_op() -> TestResult {
    let signer = signer(0x11)?;

    let seed = Op::create_signed(
        &signer,
        OpContent {
            op_id: ulid::Ulid::from(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef_u128),
            lamport: 12,
            key_epoch: KEY_EPOCH,
            kind: OpKind::Remember,
            note_id: "mem_01JBQ8Z5T7NKPXY6QW3R4V8M2C".parse::<NoteId>()?,
            object_key: format!("{TEAM}/notes/blob"),
            cid: Blake3Hash::new([0x5A; 32]),
            prev_op_hash: Blake3Hash::zero(),
        },
    );

    assert!(
        seed.verify_sig() && seed.verify_identity(),
        "the fixture op must itself verify, or the property below would pass for the wrong reason"
    );

    let probe = |bytes: &[u8]| {
        let Ok(op) = serde_json::from_slice::<Op>(bytes) else {
            return Ok(Reached::Nothing);
        };

        if op == seed {
            return Ok(Reached::HonestValue);
        }

        // The op-log read path rejects on EITHER check, so the conjunction is
        // what must fail. Asserting each one independently would be false: an
        // edit to `lamport` breaks the signature and leaves `author`/`author_key`
        // agreeing perfectly well.
        prop_assert!(
            !(op.verify_sig() && op.verify_identity()),
            "arbitrary bytes produced an op that both verified its signature and bound its \
             author to its author_key, but it is not the op the fixture signer minted: {}",
            rendered(bytes),
        );

        Ok(Reached::AlteredValue)
    };

    run_bytes_property("Op / unstructured", &unstructured_bytes(), probe);

    let reach = run_bytes_property(
        "Op / tampered",
        &tampered_bytes(serde_json::to_vec(&seed)?),
        probe,
    );
    assert_reach_floor("Op", &reach, floors::OP);

    Ok(())
}

#[test]
fn arbitrary_bytes_never_yield_a_verified_team_manifest() -> TestResult {
    let founder = signer(0x22)?;
    let member = signer(0x23)?;

    let members: BTreeSet<_> = [founder.author_ss58(), member.author_ss58()]
        .into_iter()
        .collect();

    let seed = TeamManifest::create_signed(&founder, TEAM.to_owned(), members, 3);

    assert!(
        seed.verify(),
        "the fixture manifest must itself verify, or the property below would pass for the wrong \
         reason"
    );

    let probe = |bytes: &[u8]| {
        let Ok(manifest) = serde_json::from_slice::<TeamManifest>(bytes) else {
            return Ok(Reached::Nothing);
        };

        if manifest == seed {
            return Ok(Reached::HonestValue);
        }

        prop_assert!(
            !manifest.verify(),
            "arbitrary bytes produced a team manifest that verified, but it is not the manifest \
             the fixture founder signed: {}",
            rendered(bytes),
        );

        Ok(Reached::AlteredValue)
    };

    run_bytes_property("TeamManifest / unstructured", &unstructured_bytes(), probe);

    let reach = run_bytes_property(
        "TeamManifest / tampered",
        &tampered_bytes(serde_json::to_vec(&seed)?),
        probe,
    );
    assert_reach_floor("TeamManifest", &reach, floors::TEAM_MANIFEST);

    Ok(())
}

#[test]
fn arbitrary_bytes_never_yield_an_unwrappable_team_key() -> TestResult {
    let recipient_secret = StaticSecret::from([0x33; 32]);
    let recipient_public = PublicKey::from(&recipient_secret).to_bytes();
    let team_key = SecretKey::from_bytes([0x44; 32]);

    let seed = wrap_team_key(TEAM, &team_key, &recipient_public, KEY_EPOCH)?;

    // The seed must be a GENUINE seal that this recipient can open. A placeholder
    // ciphertext would fail AEAD authentication no matter what the property did,
    // and every rejection below would be unattributable.
    assert!(
        unwrap_team_key(TEAM, &seed, &recipient_secret, KEY_EPOCH).is_ok(),
        "the fixture wrap must itself open, or every rejection below would be an AEAD failure on \
         bogus input rather than the property doing work"
    );

    let probe = |bytes: &[u8]| {
        let Ok(wrapped) = serde_json::from_slice::<WrappedKey>(bytes) else {
            return Ok(Reached::Nothing);
        };

        if same_wrapped_key(&wrapped, &seed) {
            return Ok(Reached::HonestValue);
        }

        prop_assert!(
            unwrap_team_key(TEAM, &wrapped, &recipient_secret, KEY_EPOCH).is_err(),
            "arbitrary bytes produced a wrapped team key that opened under the recipient's \
             secret, but it is not the wrap `wrap_team_key` produced: {}",
            rendered(bytes),
        );

        Ok(Reached::AlteredValue)
    };

    run_bytes_property("WrappedKey / unstructured", &unstructured_bytes(), probe);

    let reach = run_bytes_property(
        "WrappedKey / tampered",
        &tampered_bytes(serde_json::to_vec(&seed)?),
        probe,
    );
    assert_reach_floor("WrappedKey", &reach, floors::WRAPPED_KEY);

    Ok(())
}

#[test]
fn arbitrary_bytes_never_yield_a_trusted_anchor_record() -> TestResult {
    let author = signer(0x55)?;
    let author_key_hex = author.verifying_key().to_hex();

    let leaves = vec![
        Blake3Hash::new([0x01; 32]),
        Blake3Hash::new([0x02; 32]),
        Blake3Hash::new([0x03; 32]),
    ];
    let root = merkle_root(&leaves);

    let seed = AnchorRecord {
        seq: ANCHOR_SEQ,
        author_key: author.verifying_key(),
        root,
        meta: BatchMeta {
            team: TEAM.to_owned(),
            first_lamport: 1,
            last_lamport: 3,
            op_count: leaves.len(),
        },
        leaves,
        receipt: AnchorReceipt {
            root,
            reference: AnchorRef::Local { seq: ANCHOR_SEQ },
        },
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let probe = |bytes: &[u8]| {
        let Ok(record) = serde_json::from_slice::<AnchorRecord>(bytes) else {
            return Ok(Reached::Nothing);
        };

        // An `AnchorRecord` carries no signature: `meta` is unbound, so an edit
        // there yields a record that is neither the honest one nor a forgery of
        // anything cryptographic. The one binding it does carry is the Merkle
        // root over its leaves, and that must not be forgeable — a leaf set other
        // than the anchored one must never reproduce the anchored root. An empty
        // leaf set is excluded: `merkle_root([])` is the zero hash by definition
        // and proves nothing, which is exactly why the reader drops it.
        if !record.leaves.is_empty() && record.root == merkle_root(&record.leaves) {
            prop_assert!(
                record.leaves == seed.leaves && record.root == seed.root,
                "arbitrary bytes produced an anchor record whose root is reproduced by a leaf \
                 set the honest record never anchored: {}",
                rendered(bytes),
            );
        }

        // Route the same bytes through the actual reader. Everything it hands
        // back must satisfy the four invariants it promises to filter on;
        // anything else is a poisoned record reaching `history`/`reconcile`.
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
        runtime
            .block_on(blob.put(&anchor_key(&author_key_hex, ANCHOR_SEQ), bytes.to_vec()))
            .map_err(tce)?;

        let accepted = runtime
            .block_on(read_anchor_records(&blob, TEAM))
            .map_err(tce)?;

        for record in &accepted {
            prop_assert!(
                !record.leaves.is_empty(),
                "read_anchor_records returned a record carrying no leaves: {}",
                rendered(bytes),
            );
            prop_assert!(
                record.root == record.receipt.root,
                "read_anchor_records returned a record whose root disagrees with its receipt \
                 root: {}",
                rendered(bytes),
            );
            prop_assert!(
                record.meta.op_count == record.leaves.len(),
                "read_anchor_records returned a record whose op_count disagrees with its leaf \
                 count: {}",
                rendered(bytes),
            );

            let mut distinct = HashSet::with_capacity(record.leaves.len());
            prop_assert!(
                record.leaves.iter().all(|leaf| distinct.insert(*leaf)),
                "read_anchor_records returned a record containing a duplicate leaf: {}",
                rendered(bytes),
            );
        }

        if record == seed {
            return Ok(Reached::HonestValue);
        }

        Ok(Reached::AlteredValue)
    };

    run_bytes_property("AnchorRecord / unstructured", &unstructured_bytes(), probe);

    let reach = run_bytes_property(
        "AnchorRecord / tampered",
        &tampered_bytes(serde_json::to_vec(&seed)?),
        probe,
    );
    assert_reach_floor("AnchorRecord", &reach, floors::ANCHOR_RECORD);

    Ok(())
}

#[test]
fn arbitrary_bytes_never_yield_a_verified_head_pointer() -> TestResult {
    let author = signer(0x66)?;

    let seed = HeadPointer::create_signed(&author, TEAM, 21, Blake3Hash::new([0x7C; 32]));

    assert!(
        seed.verify_sig() && seed.verify_identity(),
        "the fixture head must itself verify, or the property below would pass for the wrong \
         reason"
    );

    let probe = |bytes: &[u8]| {
        let Ok(head) = serde_json::from_slice::<HeadPointer>(bytes) else {
            return Ok(Reached::Nothing);
        };

        if head == seed {
            return Ok(Reached::HonestValue);
        }

        // As with `Op`: `read_heads` rejects on either check, so the conjunction
        // is what must fail. An edit to `lamport` leaves the identity binding
        // intact and breaks only the signature.
        prop_assert!(
            !(head.verify_sig() && head.verify_identity()),
            "arbitrary bytes produced a head pointer that both verified its signature and bound \
             its author to its author_key, but it is not the head the fixture signer minted: {}",
            rendered(bytes),
        );

        Ok(Reached::AlteredValue)
    };

    run_bytes_property("HeadPointer / unstructured", &unstructured_bytes(), probe);

    let reach = run_bytes_property(
        "HeadPointer / tampered",
        &tampered_bytes(serde_json::to_vec(&seed)?),
        probe,
    );
    assert_reach_floor("HeadPointer", &reach, floors::HEAD_POINTER);

    Ok(())
}

#[test]
fn arbitrary_bytes_never_forge_a_head_watermark() -> TestResult {
    let author = signer(0x77)?;
    let honest_lamport = 31;
    let honest_tip = Blake3Hash::new([0x9E; 32]);
    let head = HeadPointer::create_signed(&author, TEAM, honest_lamport, honest_tip);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    // Build the seed file through production code rather than by hand: the file
    // format (`WatermarkFile`, `HeadWatermark`) is module-private, so hand-writing
    // JSON here would silently drift the day the format changes.
    let published: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    runtime.block_on(publish_head(&published, TEAM, &head))?;
    let verified: VerifiedHeads = runtime.block_on(read_heads(&published, TEAM))?;
    assert_eq!(
        verified.len(),
        1,
        "the fixture head must survive read_heads, or there would be no mark to persist"
    );

    let dir = tempfile::TempDir::new()?;
    let seed_path = dir.path().join("seed-watermarks.json");
    let marks = HeadWatermarks::load(seed_path.clone());
    assert!(
        marks.observe(&verified).is_empty(),
        "the first observation of an author records a mark and reports nothing; a regression here \
         would mean the fixture, not the fuzzer, moved a head backward"
    );
    let seed_bytes = std::fs::read(&seed_path)?;

    // The comparison set: no heads served at all, so `observe` reports one
    // regression per remembered mark. That makes the returned vector a faithful,
    // public-API view of the marks the file decoded into — the only view there
    // is, since the mark map is private.
    let unserved: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::new());
    let no_heads: VerifiedHeads = runtime.block_on(read_heads(&unserved, TEAM))?;
    assert!(
        no_heads.is_empty(),
        "the comparison set must be empty for a regression to stand in for a remembered mark"
    );

    let fuzz_path: PathBuf = dir.path().join("fuzzed-watermarks.json");

    let probe = |bytes: &[u8]| {
        std::fs::write(&fuzz_path, bytes).map_err(tce)?;

        // Both calls are infallible by contract; reaching the next line at all is
        // the totality half of the property.
        let marks = HeadWatermarks::load(fuzz_path.clone());
        let regressions = marks.observe(&no_heads);

        for regression in &regressions {
            // Containment: a mark can only ever name a key the file's bytes
            // actually carry. `VerifyingKey` deserializes from 64 lowercase hex
            // characters and `to_hex` emits exactly that form, so this is an
            // exact substring check, not an approximation.
            let key_hex = regression.author_key.to_hex();
            prop_assert!(
                bytes
                    .windows(key_hex.len())
                    .any(|window| window == key_hex.as_bytes()),
                "the audit reported a regression against an author key that does not appear in \
                 the watermark file's bytes: {key_hex}",
            );

            // Attribution: `HeadRegression::author` is documented as DERIVED from
            // `author_key`, never stored beside it, so a corrupt file must not be
            // able to attribute a mark to an address its key does not encode to.
            prop_assert!(
                regression.author == ss58_encode(&regression.author_key, NetworkPrefix::HIPPIUS),
                "the audit attributed a regression to an address that is not its own author \
                 key's: {}",
                regression.author.as_str(),
            );
        }

        if regressions.is_empty() {
            return Ok(Reached::Nothing);
        }

        let honest = regressions.len() == 1
            && regressions[0].author_key == author.verifying_key()
            && regressions[0].remembered_lamport == honest_lamport
            && regressions[0].remembered_tip == honest_tip;

        if honest {
            return Ok(Reached::HonestValue);
        }

        Ok(Reached::AlteredValue)
    };

    run_bytes_property(
        "HeadWatermarks / unstructured",
        &unstructured_bytes(),
        probe,
    );

    let reach = run_bytes_property(
        "HeadWatermarks / tampered",
        &tampered_bytes(seed_bytes),
        probe,
    );
    assert_reach_floor("HeadWatermarks", &reach, floors::HEAD_WATERMARKS);

    Ok(())
}
