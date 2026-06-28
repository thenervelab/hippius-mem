//! Real semantic embeddings via a local ONNX model (`fastembed`).
//!
//! This is the dense [`Embedder`] the index's seam was built for: it replaces
//! the deterministic, keyword-overlap [`HashEmbedder`](super::HashEmbedder)
//! fallback with a real sentence model run locally through ONNX Runtime.
//! Retrieval stays **private and offline**: text is embedded in-process, never
//! sent to a third-party API, so the encryption boundary and the "works without
//! an external service" property both hold — the only network use is the
//! one-time model download into `fastembed`'s own cache on first construction.
//!
//! Gated behind the opt-in `embeddings` feature so the heavy ONNX Runtime stack
//! never enters the default build (same discipline as `chain` / `console`).

use std::fmt;
use std::sync::{Mutex, PoisonError};

use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};

use crate::error::MemError;
use crate::index::Embedder;

/// A local embedding model bundled by `fastembed`.
///
/// A small, owned enum rather than re-exporting `fastembed::EmbeddingModel`: it
/// keeps the dependency out of this crate's public API (callers and config name
/// a model without depending on `fastembed`), and bounds the set to the
/// short-text retrieval models we have calibrated. Both current variants are
/// 384-dimensional, so swapping between them needs no index resize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmbedModel {
    /// `sentence-transformers/all-MiniLM-L6-v2` — the small, fast default
    /// (~90 MB, 384-dim). Strong general paraphrase retrieval for short text.
    MiniLmL6V2,
    /// `BAAI/bge-small-en-v1.5` — a same-size (384-dim) alternative that often
    /// edges out `MiniLM` on retrieval benchmarks; selectable when a corpus needs
    /// the extra recall.
    BgeSmallEnV15,
}

impl EmbedModel {
    /// The `fastembed` model this maps to.
    fn fastembed(self) -> EmbeddingModel {
        match self {
            Self::MiniLmL6V2 => EmbeddingModel::AllMiniLML6V2,
            Self::BgeSmallEnV15 => EmbeddingModel::BGESmallENV15,
        }
    }

    /// Output dimensionality. Both bundled models are 384-dimensional; kept as a
    /// method (not a crate const) so adding a different-width model later is a
    /// local change with no silently-wrong shared constant.
    #[must_use]
    pub fn dim(self) -> usize {
        match self {
            Self::MiniLmL6V2 | Self::BgeSmallEnV15 => 384,
        }
    }

    /// Parse a config/CLI model name (case-insensitive). Accepts both the full
    /// HuggingFace-style id and a short alias.
    ///
    /// Returns `None` for an unknown name so the caller can report the offending
    /// value rather than silently falling back to a model the operator did not ask
    /// for.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "all-minilm-l6-v2" | "minilm" | "minilm-l6-v2" => Some(Self::MiniLmL6V2),
            "bge-small-en-v1.5" | "bge-small" | "bge" => Some(Self::BgeSmallEnV15),
            _ => None,
        }
    }

    /// The model's **calibrated** default semantic relevance floor: the minimum
    /// cosine at which a candidate counts as a match, used when the deployment
    /// does not override it.
    ///
    /// The floor lives with the model, not as one global constant, because each
    /// model has its own cosine scale. `fastembed` returns L2-normalized vectors
    /// (verified in its `text_embedding::output` transformer), so cosine is the
    /// dot product in `[-1, 1]`; a dense model gives small NON-zero cosines for
    /// unrelated text, so the floor must sit above that noise band and below the
    /// true-paraphrase band. These values come from measuring real note summaries
    /// against paraphrase queries (`examples/calibrate.rs`): `MiniLM` separates
    /// cleanly around `0.25`, while `bge-small` compresses everything into a high
    /// `~0.55–0.71` band and needs a correspondingly higher floor.
    #[must_use]
    pub fn default_floor(self) -> f32 {
        match self {
            Self::MiniLmL6V2 => 0.25,
            Self::BgeSmallEnV15 => 0.55,
        }
    }
}

impl fmt::Display for EmbedModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::MiniLmL6V2 => "all-MiniLM-L6-v2",
            Self::BgeSmallEnV15 => "bge-small-en-v1.5",
        };
        f.write_str(name)
    }
}

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
    // Stored, not hard-coded in the trait methods, so model and floor travel
    // together with the constructed embedder: a different model brings its own
    // dimensionality and its own calibrated floor.
    dim: usize,
    threshold: f32,
}

impl fmt::Debug for FastEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written because `fastembed::TextEmbedding` is not `Debug` (it wraps
        // an ONNX Runtime session). Name the identifying facts and mark the model
        // field non-exhaustively rather than attempting to render the session.
        f.debug_struct("FastEmbedder")
            .field("dim", &self.dim)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

impl FastEmbedder {
    /// Load the default model ([`EmbedModel::MiniLmL6V2`]) at its calibrated
    /// default relevance floor ([`EmbedModel::default_floor`]).
    ///
    /// # Errors
    ///
    /// See [`FastEmbedder::try_with`].
    pub fn try_new() -> Result<Self, MemError> {
        Self::try_with(EmbedModel::MiniLmL6V2, EmbedModel::MiniLmL6V2.default_floor())
    }

    /// Load `model` and rank with `threshold` as the semantic relevance floor,
    /// downloading the model into `fastembed`'s cache on first use.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Embedding`] if the model cannot be loaded — a failed
    /// download (offline first run), a corrupt cache, or an ONNX Runtime
    /// initialization failure. The caller surfaces this at startup so an
    /// embeddings-unavailable boot fails loudly instead of silently degrading.
    pub fn try_with(model: EmbedModel, threshold: f32) -> Result<Self, MemError> {
        // `show_download_progress(false)`: the server's stdout is the MCP protocol
        // channel (diagnostics go to stderr via `tracing`), so a progress bar must
        // never be written there. Defaults otherwise — the cache dir is
        // `fastembed`'s standard location.
        let inner = TextEmbedding::try_new(
            InitOptions::new(model.fastembed()).with_show_download_progress(false),
        )
        .map_err(|err| MemError::Embedding(err.to_string()))?;
        Ok(Self {
            model: Mutex::new(inner),
            dim: model.dim(),
            threshold,
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
        self.dim
    }

    fn relevance_threshold(&self) -> f32 {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "the ignored live test asserts on a known-good model load + embed"
    )]

    use super::{EmbedModel, FastEmbedder};
    use crate::index::Embedder;

    #[test]
    fn model_names_parse_case_insensitively() {
        assert_eq!(EmbedModel::parse("MiniLM"), Some(EmbedModel::MiniLmL6V2));
        assert_eq!(
            EmbedModel::parse("all-minilm-l6-v2"),
            Some(EmbedModel::MiniLmL6V2)
        );
        assert_eq!(
            EmbedModel::parse(" BGE-Small "),
            Some(EmbedModel::BgeSmallEnV15)
        );
        assert_eq!(EmbedModel::parse("gpt-9"), None);
        // Both bundled models share the index width, so a swap needs no resize.
        assert_eq!(EmbedModel::MiniLmL6V2.dim(), 384);
        assert_eq!(EmbedModel::BgeSmallEnV15.dim(), 384);
        // The calibrated floors differ per model (measured, not guessed).
        assert!(EmbedModel::MiniLmL6V2.default_floor() < EmbedModel::BgeSmallEnV15.default_floor());
    }

    /// Cosine of two equal-length, already-L2-normalized vectors (the shape
    /// `fastembed` returns), so cosine reduces to the dot product.
    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    // Live model test: downloads the model on first run and needs the native ONNX
    // Runtime, so it is `#[ignore]`d in CI — run explicitly with
    // `cargo test --features embeddings -- --ignored`. This mirrors the
    // `s3-integration` live-round-trip test's ignored-by-default discipline.
    #[test]
    #[ignore = "downloads the all-MiniLM model and runs native ONNX Runtime"]
    fn semantic_similarity_orders_related_above_unrelated() {
        let embedder = FastEmbedder::try_new().expect("model loads");
        assert_eq!(embedder.dim(), 384, "MiniLM is 384-dimensional");
        let floor = EmbedModel::MiniLmL6V2.default_floor();
        assert!((embedder.relevance_threshold() - floor).abs() < f32::EPSILON);

        let texts = [
            "the database connection pool must be closed on shutdown".to_owned(),
            "remember to release db connections when the service stops".to_owned(),
            "the office coffee machine is on the third floor".to_owned(),
        ];
        let vectors = embedder.embed(&texts).expect("embedding succeeds");
        assert_eq!(vectors.len(), 3);
        assert!(vectors.iter().all(|v| v.len() == 384));

        let related = cosine(&vectors[0], &vectors[1]);
        let unrelated = cosine(&vectors[0], &vectors[2]);
        assert!(
            related > unrelated,
            "a paraphrase must score above an unrelated sentence: related {related} vs unrelated {unrelated}"
        );
        assert!(
            related >= floor,
            "a true paraphrase must clear the default floor: {related} < {floor}"
        );
        assert!(
            unrelated < floor,
            "an unrelated sentence must fall below the default floor: {unrelated} >= {floor}"
        );
    }
}
