//! Real semantic embeddings via a local ONNX model (`fastembed`).
//!
//! This is the dense [`Embedder`] the index's seam was built for: it replaces
//! the deterministic, keyword-overlap [`HashEmbedder`](super::HashEmbedder)
//! fallback with `sentence-transformers/all-MiniLM-L6-v2`, a 384-dimension
//! sentence model run locally through ONNX Runtime. Retrieval stays **private
//! and offline**: text is embedded in-process, never sent to a third-party API,
//! so the encryption boundary and the "works without an external service"
//! property both hold — the only network use is the one-time model download into
//! `fastembed`'s own cache on first construction.
//!
//! Gated behind the opt-in `embeddings` feature so the heavy ONNX Runtime stack
//! never enters the default build (same discipline as `chain` / `console`).

use std::fmt;
use std::sync::{Mutex, PoisonError};

use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};

use crate::error::MemError;
use crate::index::Embedder;

/// Output dimensionality of `all-MiniLM-L6-v2`.
///
/// Fixed by the model choice below; [`FastEmbedder::dim`] returns it so the
/// index can size and compare query/document vectors. Changing [`MODEL`] means
/// changing this constant in lock-step — the two are a unit.
const MINILM_DIM: usize = 384;

/// The bundled model. `all-MiniLM-L6-v2` is the small, fast default: ~90 MB,
/// strong retrieval quality for short text, and the size that keeps first-run
/// download and per-query latency low. Swapping it is a one-line change here
/// plus [`MINILM_DIM`].
const MODEL: EmbeddingModel = EmbeddingModel::AllMiniLML6V2;

/// Minimum cosine similarity at which a candidate counts as a semantic match.
///
/// `fastembed` returns **L2-normalized** vectors (verified in its
/// `text_embedding::output` transformer, which calls `normalize` on every row),
/// so cosine equals the dot product and lands in `[-1, 1]`. Unlike the
/// bag-of-tokens [`HashEmbedder`](super::HashEmbedder) — whose disjoint texts
/// score *exactly* `0.0`, making `> 0.0` the right floor — a dense model returns
/// small NON-zero cosines (~0.0–0.25) for unrelated sentences. A floor of `> 0.0`
/// would readmit that noise, so the semantic leg needs a calibrated minimum: 0.3
/// sits above the unrelated-pair band and below the related-pair band (~0.4+) for
/// `MiniLM`. It is intentionally conservative — too high drops true matches, and
/// the lexical leg still surfaces exact-term hits the semantic leg floors out.
const RELEVANCE_FLOOR: f32 = 0.3;

/// A dense, local [`Embedder`] backed by a `fastembed` ONNX sentence model.
///
/// # Concurrency
///
/// `fastembed::TextEmbedding::embed` takes `&mut self`, but [`Embedder::embed`]
/// is `&self`, so the model lives behind a [`Mutex`] that supplies that interior
/// mutability and makes the whole type `Sync` (it is `Send + Sync` by
/// propagation, not by hand — the model is `Send`). [`Embedder::embed`] is
/// **synchronous** and never `.await`s while the guard is held, so a
/// `std::sync::Mutex` is correct here rather than `tokio::sync::Mutex`; this
/// mirrors `InMemoryIndex`'s own `entries` lock and respects the workspace
/// `await_holding_lock = deny` lint. The lock serializes inference, which is
/// acceptable: embedding runs once per query and per write, not on a contended
/// hot path.
pub struct FastEmbedder {
    model: Mutex<TextEmbedding>,
}

impl fmt::Debug for FastEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written because `fastembed::TextEmbedding` is not `Debug` (it wraps
        // an ONNX Runtime session). Name the model and dimensionality — the
        // identifying facts — rather than attempting to render the session.
        f.debug_struct("FastEmbedder")
            .field("model", &"all-MiniLM-L6-v2")
            .field("dim", &MINILM_DIM)
            .finish()
    }
}

impl FastEmbedder {
    /// Load `all-MiniLM-L6-v2`, downloading it into `fastembed`'s cache on first
    /// use.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Embedding`] if the model cannot be loaded — a failed
    /// download (offline first run), a corrupt cache, or an ONNX Runtime
    /// initialization failure. The caller surfaces this at startup so an
    /// embeddings-unavailable boot fails loudly instead of silently degrading.
    pub fn try_new() -> Result<Self, MemError> {
        // `show_download_progress(false)`: the server's stdout is the MCP protocol
        // channel (diagnostics go to stderr via `tracing`), so a progress bar must
        // never be written there. Defaults otherwise — the cache dir is
        // `fastembed`'s standard location.
        let model = TextEmbedding::try_new(
            InitOptions::new(MODEL).with_show_download_progress(false),
        )
        .map_err(|err| MemError::Embedding(err.to_string()))?;
        Ok(Self {
            model: Mutex::new(model),
        })
    }
}

impl Embedder for FastEmbedder {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
        // Recover from a poisoned lock rather than propagate the panic: a prior
        // panicked embed leaves the model logically intact (ONNX inference does
        // not mutate caller-visible state), so `into_inner` is the right call,
        // matching `InMemoryIndex`'s poison handling.
        let mut guard = self.model.lock().unwrap_or_else(PoisonError::into_inner);
        // `embed` takes `Vec<S: AsRef<str>>`; borrow each `String` as `&str` so no
        // clone of the query/summaries is made. `None` keeps fastembed's default
        // batch size (256).
        let docs: Vec<&str> = texts.iter().map(String::as_str).collect();
        guard
            .embed(docs, None)
            .map_err(|err| MemError::Embedding(err.to_string()))
    }

    fn dim(&self) -> usize {
        MINILM_DIM
    }

    fn relevance_threshold(&self) -> f32 {
        RELEVANCE_FLOOR
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "the ignored live test asserts on a known-good model load + embed"
    )]

    use super::{FastEmbedder, MINILM_DIM, RELEVANCE_FLOOR};
    use crate::index::Embedder;

    /// Cosine of two equal-length, already-L2-normalized vectors (the shape
    /// `fastembed` returns), so cosine reduces to the dot product.
    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    // Live model test: downloads ~90 MB on first run and needs the native ONNX
    // Runtime, so it is `#[ignore]`d in CI — run explicitly with
    // `cargo test --features embeddings -- --ignored`. This mirrors the
    // `s3-integration` live-round-trip test's ignored-by-default discipline.
    #[test]
    #[ignore = "downloads the all-MiniLM model and runs native ONNX Runtime"]
    fn semantic_similarity_orders_related_above_unrelated() {
        let embedder = FastEmbedder::try_new().expect("model loads");
        assert_eq!(embedder.dim(), MINILM_DIM, "MiniLM is 384-dimensional");

        let texts = [
            "the database connection pool must be closed on shutdown".to_owned(),
            "remember to release db connections when the service stops".to_owned(),
            "the office coffee machine is on the third floor".to_owned(),
        ];
        let vectors = embedder.embed(&texts).expect("embedding succeeds");
        assert_eq!(vectors.len(), 3);
        assert!(vectors.iter().all(|v| v.len() == MINILM_DIM));

        let related = cosine(&vectors[0], &vectors[1]);
        let unrelated = cosine(&vectors[0], &vectors[2]);
        assert!(
            related > unrelated,
            "a paraphrase must score above an unrelated sentence: related {related} vs unrelated {unrelated}"
        );
        assert!(
            related >= RELEVANCE_FLOOR,
            "a true paraphrase must clear the relevance floor: {related} < {RELEVANCE_FLOOR}"
        );
        assert!(
            unrelated < RELEVANCE_FLOOR,
            "an unrelated sentence must fall below the floor: {unrelated} >= {RELEVANCE_FLOOR}"
        );
    }
}
