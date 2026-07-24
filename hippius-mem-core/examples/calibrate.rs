//! Calibrate the semantic relevance floor against the REAL note corpus.
//!
//! Embeds a snapshot of the team's note summaries plus a battery of paraphrase
//! queries (each labelled with the note it *should* retrieve), then prints, per
//! model, where the intended note ranks and at what cosine — and the best cosine
//! of any WRONG note. Each target is also scored against the model's PRODUCTION
//! floor (`EmbedModel::default_floor`): `recall@floor` counts how many clear it,
//! because a target below the floor is dropped from `recall` even at rank 0 —
//! the edge that rank alone hides. The floor we want sits below the worst
//! true-match cosine and above the best false-match cosine. Measuring this beats
//! guessing a constant.
//!
//! Run: `cargo run --release --example calibrate --features embeddings`

#![expect(
    clippy::print_stdout,
    reason = "this is a calibration tool; its entire purpose is to print the cosine distribution"
)]

use hippius_mem_core::{EmbedModel, Embedder, FastEmbedder};

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

fn evaluate(model: EmbedModel) -> Result<(), Box<dyn std::error::Error>> {
    // threshold 0.0: we want the RAW cosines, not a pre-floored view.
    let embedder = FastEmbedder::try_with(model, 0.0)?;

    let docs: Vec<String> = SUMMARIES.iter().map(|s| (*s).to_owned()).collect();
    let doc_vecs = embedder.embed(&docs)?;

    // The PRODUCTION gate: `recall` drops any semantic candidate scoring below
    // this model's calibrated floor, so a target under it vanishes from results
    // even when it is the top-ranked note. Rank hides that; floor-survival is
    // the metric that maps to what a user actually sees.
    let floor = model.default_floor();
    println!("\n================ model: {model}  (production floor {floor:.2}) ================");
    let mut worst_true = f32::INFINITY; // lowest cosine among intended matches
    let mut best_false = f32::NEG_INFINITY; // highest cosine among wrong notes
    let mut top1_hits = 0_usize;
    let mut floor_survivors = 0_usize; // targets clearing `floor` → recall@floor

    for &(query, target) in QUERIES {
        let qvec = &embedder.embed(&[query.to_owned()])?[0];
        // Score every summary, remember the ranking.
        let mut scored: Vec<(usize, f32)> = doc_vecs
            .iter()
            .enumerate()
            .map(|(i, v)| (i, cosine(qvec, v)))
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1));

        let rank = scored
            .iter()
            .position(|&(i, _)| i == target)
            .unwrap_or(usize::MAX);
        let target_cos = scored
            .iter()
            .find(|&&(i, _)| i == target)
            .map_or(0.0, |&(_, c)| c);
        let best_wrong = scored
            .iter()
            .find(|&&(i, _)| i != target)
            .map_or(0.0, |&(_, c)| c);

        worst_true = worst_true.min(target_cos);
        best_false = best_false.max(best_wrong);
        if rank == 0 {
            top1_hits += 1;
        }
        let survives = target_cos >= floor;
        if survives {
            floor_survivors += 1;
        }

        // Survival is primary, rank secondary: DROP = below floor (gone in
        // production, even at rank 0); TOP1 = surfaced first; RANK = cleared the
        // floor but out-ranked by noise the floor still admits.
        let mark = if !survives {
            "DROP"
        } else if rank == 0 {
            "TOP1"
        } else {
            "RANK"
        };
        println!(
            "  [{mark}] target#{target} rank {rank} cos {target_cos:.3}  (best wrong {best_wrong:.3})"
        );
        println!("        q: {query}");
        for &(i, c) in scored.iter().take(2) {
            println!("          {c:.3}  {}", SUMMARIES[i]);
        }
    }

    println!("  ---------------------------------------------");
    println!("  top-1 accuracy : {top1_hits}/{}", QUERIES.len());
    println!(
        "  recall@floor   : {floor_survivors}/{}  (targets clearing the {floor:.2} floor; the rest are DROPPED)",
        QUERIES.len()
    );
    println!("  worst true-match cosine : {worst_true:.3}  (floor must be <= this to keep all)");
    println!("  best false-match cosine : {best_false:.3}  (floor must be >  this to drop noise)");
    let midpoint = f32::midpoint(worst_true, best_false);
    println!("  suggested floor (midpoint): {midpoint:.3}");

    // Write-time dedup calibration. The dedup gate (`store::DEDUP_THRESHOLD`,
    // 0.9) refuses a new note whose summary cosine to an existing one clears the
    // threshold. The risk is a FALSE positive: two genuinely distinct notes that
    // happen to embed close would see the second refused. The highest cosine
    // between any two DISTINCT summaries is that false-duplicate ceiling, so the
    // threshold must sit ABOVE it. Reported here against the real corpus so 0.9
    // can be checked (and lowered/raised) rather than guessed.
    let mut ceiling = f32::NEG_INFINITY;
    let mut closest = (0_usize, 0_usize);
    for (i, vi) in doc_vecs.iter().enumerate() {
        for (j, vj) in doc_vecs.iter().enumerate().skip(i + 1) {
            let c = cosine(vi, vj);
            if c > ceiling {
                ceiling = c;
                closest = (i, j);
            }
        }
    }
    println!("  dedup false-dup ceiling : {ceiling:.3}  (DEDUP_THRESHOLD must be > this)");
    println!("        closest distinct pair:");
    println!("          {}", SUMMARIES[closest.0]);
    println!("          {}", SUMMARIES[closest.1]);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for model in [EmbedModel::MiniLmL6V2, EmbedModel::BgeSmallEnV15] {
        evaluate(model)?;
    }
    Ok(())
}
