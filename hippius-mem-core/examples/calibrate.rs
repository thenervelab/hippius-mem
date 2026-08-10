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

// The corpus and `cosine` live in one shared file so this tool and the
// asserted gate in `tests/retrieval_quality.rs` can never measure different
// data. See that file's header for why it sits under `tests/shared/`.
include!("../tests/shared/calibration_corpus.rs");

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
