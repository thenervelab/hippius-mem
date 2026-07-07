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
use std::path::{Path, PathBuf};
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
///
/// [`BgeSmallEnV15`](Self::BgeSmallEnV15) is the [`Default`]: calibration
/// (`examples/calibrate.rs`) shows it clears its relevance floor on every probe
/// paraphrase — including near-synonyms like *scrambled*↔*encrypted* that
/// `MiniLM` drops below its own floor — at the cost of a higher noise band the
/// caller re-ranks. The `#[default]` variant keeps that one choice in a single
/// place the constructor and the config default both read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EmbedModel {
    /// `sentence-transformers/all-MiniLM-L6-v2` — the leaner alternative
    /// (~90 MB, 384-dim). Separates related from unrelated text cleanly around a
    /// low `0.25` floor, but drops more genuine near-synonyms below it; pick it
    /// when precision matters more than recall.
    MiniLmL6V2,
    /// `BAAI/bge-small-en-v1.5` — the default (same 384-dim, so no index resize).
    /// Higher recall: it clears its calibrated `0.55` floor on paraphrases
    /// `MiniLM` misses, trading a compressed high cosine band (more noise) that
    /// the LLM caller re-ranks away.
    #[default]
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
    /// Load the default model ([`EmbedModel::default`]) at its calibrated
    /// default relevance floor ([`EmbedModel::default_floor`]).
    ///
    /// # Errors
    ///
    /// See [`FastEmbedder::try_with`].
    pub fn try_new() -> Result<Self, MemError> {
        let model = EmbedModel::default();
        Self::try_with(model, model.default_floor())
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
        // never be written there.
        let mut options = InitOptions::new(model.fastembed()).with_show_download_progress(false);
        // Anchor the model cache to one per-machine directory. Left to fastembed,
        // it caches under `./.fastembed_cache` relative to the process CWD — which
        // for the MCP server is each served repo — so the ~90 MB model would be
        // re-downloaded into every repo's working tree. `None` means the operator
        // already steered fastembed via its own env knobs, so leave its resolution
        // untouched (see `default_cache_dir`).
        if let Some(cache_dir) = default_cache_dir() {
            options = options.with_cache_dir(cache_dir);
        }
        let inner =
            TextEmbedding::try_new(options).map_err(|err| MemError::Embedding(err.to_string()))?;
        Ok(Self {
            model: Mutex::new(inner),
            dim: model.dim(),
            threshold,
        })
    }
}

/// The per-machine directory fastembed should cache downloaded models in, or
/// `None` to leave fastembed's own resolution untouched.
///
/// fastembed's default cache is `./.fastembed_cache`, resolved against the
/// process CWD — which for the MCP server is each repository it serves — so the
/// default drops the ~90 MB model into every repo's tree. Anchoring the cache to
/// one per-machine location downloads the model once per machine instead.
/// Returns `None` (defer to fastembed) when the operator has already directed
/// fastembed elsewhere, or when there is no home directory to anchor to.
fn default_cache_dir() -> Option<PathBuf> {
    // fastembed reads `FASTEMBED_CACHE_DIR` itself and `HF_HOME` takes precedence
    // over an explicit `with_cache_dir` (fastembed docs, "Model cache"), so when
    // either is set the operator's choice must win — do not override it.
    let override_present =
        std::env::var_os("FASTEMBED_CACHE_DIR").is_some() || std::env::var_os("HF_HOME").is_some();
    // `var_os`, not `var`: a non-UTF-8 cache path is still a valid path, and it
    // is only a presence/base lookup — no reason to reject it as `VarError`.
    let non_empty = |var| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
    };
    let xdg = non_empty("XDG_CACHE_HOME");
    let home = non_empty("HOME");
    resolve_cache_dir(override_present, xdg.as_deref(), home.as_deref())
}

/// Pure cache-directory decision, split from [`default_cache_dir`] so the branch
/// logic is unit-testable without mutating process-global environment variables
/// (`std::env::set_var` is `unsafe` and racy under a parallel test harness).
///
/// `xdg_cache` and `home` are the caller's already-cleaned `XDG_CACHE_HOME` and
/// `$HOME` (empty values dropped). Precedence follows the XDG base-directory
/// spec: an explicit `XDG_CACHE_HOME` is itself the cache root, otherwise the
/// cache lives under `$HOME/.cache`.
fn resolve_cache_dir(
    override_present: bool,
    xdg_cache: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if override_present {
        return None;
    }
    let base = match xdg_cache {
        Some(dir) => dir.to_path_buf(),
        None => home?.join(".cache"),
    };
    Some(base.join("hippius-mem").join("fastembed"))
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

    use std::path::{Path, PathBuf};

    use proptest::prelude::*;

    use super::{EmbedModel, FastEmbedder, resolve_cache_dir};
    use crate::index::Embedder;

    #[test]
    fn cache_dir_prefers_xdg_then_home_and_defers_to_operator() {
        // XDG_CACHE_HOME is itself the cache root — used verbatim, not suffixed.
        assert_eq!(
            resolve_cache_dir(false, Some(Path::new("/xdg")), Some(Path::new("/home/u"))),
            Some(PathBuf::from("/xdg/hippius-mem/fastembed"))
        );
        // No XDG override → anchor under `$HOME/.cache`.
        assert_eq!(
            resolve_cache_dir(false, None, Some(Path::new("/home/u"))),
            Some(PathBuf::from("/home/u/.cache/hippius-mem/fastembed"))
        );
        // An operator env override wins even when both bases resolve — we must
        // not clobber a chosen FASTEMBED_CACHE_DIR / HF_HOME location.
        assert_eq!(
            resolve_cache_dir(true, Some(Path::new("/xdg")), Some(Path::new("/home/u"))),
            None
        );
        // No override and nothing to anchor to → defer to fastembed's own default.
        assert_eq!(resolve_cache_dir(false, None, None), None);
    }

    proptest! {
        // The override knob always defers, regardless of the resolved bases: an
        // operator who set FASTEMBED_CACHE_DIR / HF_HOME is never overridden.
        #[test]
        fn override_always_defers(seg in "[^\\x00/]{1,40}") {
            let home = PathBuf::from("/home").join(&seg);
            let xdg = PathBuf::from("/xdg").join(&seg);
            prop_assert_eq!(resolve_cache_dir(true, Some(&xdg), Some(&home)), None);
            prop_assert_eq!(resolve_cache_dir(true, None, Some(&home)), None);
        }

        // Without an override or XDG_CACHE_HOME the cache is anchored under
        // `$HOME/.cache`, and every resolved path ends at `hippius-mem/fastembed`.
        #[test]
        fn home_anchors_under_dot_cache(seg in "[^\\x00/]{1,40}") {
            let home = PathBuf::from("/home").join(&seg);
            let got = resolve_cache_dir(false, None, Some(&home));
            let want = home.join(".cache").join("hippius-mem").join("fastembed");
            prop_assert_eq!(got.as_deref(), Some(want.as_path()));
            prop_assert!(want.ends_with(Path::new("hippius-mem").join("fastembed")));
        }
    }

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
    #[ignore = "downloads the default embedding model and runs native ONNX Runtime"]
    fn semantic_similarity_orders_related_above_unrelated() {
        // Exercise whatever `EmbedModel::default()` resolves to, so the test
        // tracks the shipped default rather than pinning a specific model.
        let model = EmbedModel::default();
        let embedder = FastEmbedder::try_new().expect("model loads");
        assert_eq!(
            embedder.dim(),
            model.dim(),
            "the default model's index width"
        );
        let floor = model.default_floor();
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
