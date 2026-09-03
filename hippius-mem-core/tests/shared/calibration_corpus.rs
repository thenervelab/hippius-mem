// The labelled retrieval-calibration corpus: real note summaries plus
// paraphrase queries, each labelled with the summary it should retrieve.
//
// Not a test target of its own (files in a `tests/` SUBDIRECTORY are not
// compiled as integration tests). It is `include!`d by both
// `tests/retrieval_quality.rs`, which asserts against it, and
// `examples/calibrate.rs`, which prints the distribution for a human tuning the
// floor — so the measurement and the gate can never drift onto different data.
//
// Plain `//` comments throughout: an `include!`d file is spliced mid-module, so
// inner `//!` docs would be a compile error at every call site.

/// A snapshot of the real team-note summaries (the text `recall` embeds).
const SUMMARIES: &[&str] = &[
    "Off-chain subkey only: every user-callable thebrain chain write is gated, so a memory subkey has no on-chain action",
    "The production anchor threshold is 16 ops; a sealed batch becomes a Merkle root, anchored locally by default or on-chain with --features chain",
    "Removing a member does not revoke their access — you must also revoke their sub-token at the gateway and rotate the team key",
    "The index is a disposable cache rebuildable from the shared op-log; refresh replays the log and applies teammates' tombstones",
    "reconcile in local mode detects accidental op-log loss, not adversarial suppression — that needs the chain feature plus chain readback",
    "recall is lexical keyword-overlap (HashEmbedder), not semantic — a paraphrase with no shared tokens will not match",
    "A team is open until a founder publishes a signed TeamManifest; after that only current members' ops converge",
    "Note content is encrypted with XChaCha20-Poly1305 under the shared team_key_hex; only ciphertext ever leaves the process",
    "author_seed_hex is unique per machine; the SS58 author identity is derived from it, so never reuse one seed across machines",
    "The op-log envelope is cleartext by design — it carries metadata but never note content",
    "A note is one self-contained fact: summary is surfaced by recall, full body only by get",
];

/// Paraphrase queries chosen to share few or no words with their target summary,
/// each paired with the index in `SUMMARIES` it should retrieve.
const QUERIES: &[(&str, usize)] = &[
    ("how do I fully cut off a teammate who left the team", 2),
    ("is my data scrambled before it leaves my computer", 7),
    (
        "can the system tell if someone deliberately erased history",
        4,
    ),
    ("if my local search cache is wiped can I rebuild it", 3),
    (
        "difference between the short preview and the full text of a note",
        10,
    ),
    (
        "how many operations before a batch gets notarized on chain",
        1,
    ),
    ("why won't a reworded search find the right note", 5),
    ("each machine needs its own signing key for attribution", 8),
];

/// Cosine of two equal-length, already-L2-normalized vectors → dot product.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}
