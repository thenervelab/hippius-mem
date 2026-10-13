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
use std::sync::{Condvar, Mutex, PoisonError};

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
    /// Higher recall: it clears its calibrated `0.51` floor on paraphrases
    /// `MiniLM` misses, trading a compressed high cosine band (more noise) that
    /// the LLM caller re-ranks away. The floor was remeasured with the BGE
    /// query-instruction prefix (`examples/calibrate.rs`).
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

    /// The model's **calibrated** default semantic relevance floor: a candidate
    /// counts as a match only when its cosine is STRICTLY above this (the
    /// ranker filters `score > floor`), used when the deployment does not
    /// override it.
    ///
    /// The floor lives with the model, not as one global constant, because each
    /// model has its own cosine scale. `fastembed` returns L2-normalized vectors
    /// (verified in its `text_embedding::output` transformer), so cosine is the
    /// dot product in `[-1, 1]`; a dense model gives small NON-zero cosines for
    /// unrelated text, so the floor must sit above that noise band and below the
    /// true-paraphrase band. These values come from measuring real note summaries
    /// against paraphrase queries (`examples/calibrate.rs`): `MiniLM` separates
    /// cleanly around `0.25`, while `bge-small` compresses into a high band
    /// (`~0.52–0.68` with the query-instruction prefix) and needs a
    /// correspondingly higher floor.
    #[must_use]
    pub fn default_floor(self) -> f32 {
        match self {
            Self::MiniLmL6V2 => 0.25,
            Self::BgeSmallEnV15 => 0.51,
        }
    }

    /// Instruction prefixed onto QUERY texts for this model, if it was trained
    /// asymmetrically. Document vectors stay unprefixed ([`Embedder::embed`]).
    ///
    /// `BGE-small-en-v1.5` was trained with this exact string (BAAI model card);
    /// `MiniLM` is symmetric and needs none. `fastembed` does not apply the prefix
    /// itself — the caller must.
    #[must_use]
    pub fn query_instruction(self) -> Option<&'static str> {
        match self {
            Self::MiniLmL6V2 => None,
            Self::BgeSmallEnV15 => {
                Some("Represent this sentence for searching relevant passages: ")
            }
        }
    }
}

impl EmbedModel {
    /// The vector space this model embeds into (see
    /// [`Embedder::vector_space`]): its name, since the two bundled models share
    /// a width.
    #[must_use]
    pub fn vector_space(self) -> String {
        self.to_string()
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
/// `await_holding_lock = deny` lint. The lock serializes inference. A sync can
/// embed many summaries at once while a query waits, so each hold covers one
/// batch only and a query goes ahead of the next one (see `BatchedModel`).
pub struct FastEmbedder {
    model: BatchedModel<TextEmbedding>,
    // Stored, not hard-coded in the trait methods, so model and floor travel
    // together with the constructed embedder: a different model brings its own
    // dimensionality and its own calibrated floor.
    dim: usize,
    threshold: f32,
    /// BGE query-instruction prefix, or `None` for a symmetric model (`MiniLM`).
    query_prefix: Option<&'static str>,
    /// The model's name: the vector space its embeddings live in.
    space: String,
}

impl fmt::Debug for FastEmbedder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written because `fastembed::TextEmbedding` is not `Debug` (it wraps
        // an ONNX Runtime session). Name the identifying facts and mark the model
        // field non-exhaustively rather than attempting to render the session.
        f.debug_struct("FastEmbedder")
            .field("dim", &self.dim)
            .field("threshold", &self.threshold)
            .field("query_prefix", &self.query_prefix)
            .field("space", &self.space)
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
        // for the MCP server is each served repo — so the ~130 MB model would be
        // re-downloaded into every repo's working tree. `None` means the operator
        // already steered fastembed via its own env knobs, so leave its resolution
        // untouched (see `default_cache_dir`).
        if let Some(cache_dir) = default_cache_dir() {
            options = options.with_cache_dir(cache_dir);
        }
        let inner =
            TextEmbedding::try_new(options).map_err(|err| MemError::Embedding(err.to_string()))?;
        Ok(Self {
            model: BatchedModel::new(inner),
            dim: model.dim(),
            threshold,
            query_prefix: model.query_instruction(),
            space: model.vector_space(),
        })
    }
}

/// The directory fastembed should cache downloaded models in, or `None` to
/// leave fastembed's own resolution untouched.
///
/// fastembed's default cache is `./.fastembed_cache`, resolved against the
/// process CWD — which for the MCP server is each repository it serves — so the
/// default drops the ~130 MB model into every repo's tree. This anchors the cache
/// to one machine-wide location so the model downloads once per machine instead.
/// Returns `None` only when the operator has already directed fastembed via its
/// own env knobs; otherwise it always yields a CWD-independent path (never the
/// per-repo default), falling back to the machine temp dir when there is no
/// absolute home base to anchor to.
fn default_cache_dir() -> Option<PathBuf> {
    // fastembed reads `FASTEMBED_CACHE_DIR` itself and `HF_HOME` takes precedence
    // over an explicit `with_cache_dir` (fastembed docs, "Model cache"), so when
    // either is set the operator's choice must win — do not override it.
    let override_present =
        std::env::var_os("FASTEMBED_CACHE_DIR").is_some() || std::env::var_os("HF_HOME").is_some();
    // `var_os`, not `var`: a non-UTF-8 cache path is still a valid path, and this
    // is only a base lookup — no reason to reject it as `VarError`.
    let env_path = |var| std::env::var_os(var).map(PathBuf::from);
    let xdg = env_path("XDG_CACHE_HOME");
    let home = env_path("HOME");
    if let Some(dir) = resolve_cache_dir(override_present, xdg.as_deref(), home.as_deref()) {
        return Some(dir);
    }
    // No absolute home base (a bare container can leave both HOME and
    // XDG_CACHE_HOME unset), yet an operator override still means "defer to
    // fastembed". Otherwise anchor to the machine temp dir — still
    // CWD-independent — rather than let fastembed fall back to
    // `./.fastembed_cache` and re-cache the model under every served repo.
    if override_present {
        return None;
    }
    Some(std::env::temp_dir().join("hippius-mem").join("fastembed"))
}

/// Pure cache-directory decision, split from [`default_cache_dir`] so the branch
/// logic is unit-testable without mutating process-global environment variables
/// (`std::env::set_var` is `unsafe` and racy under a parallel test harness).
///
/// Returns `None` when the operator set an override, or when neither candidate
/// is an **absolute** base. Absoluteness is the point of the pin: a relative env
/// value resolves against the process CWD — each served repo — which is the very
/// per-repo caching this avoids, and the XDG base-directory spec likewise
/// mandates ignoring a relative `XDG_CACHE_HOME`. Precedence follows that spec:
/// an absolute `XDG_CACHE_HOME` is itself the cache root, otherwise the cache
/// lives under `$HOME/.cache`.
fn resolve_cache_dir(
    override_present: bool,
    xdg_cache: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if override_present {
        return None;
    }
    let base = match xdg_cache.filter(|p| p.is_absolute()) {
        Some(dir) => dir.to_path_buf(),
        None => home.filter(|p| p.is_absolute())?.join(".cache"),
    };
    Some(base.join("hippius-mem").join("fastembed"))
}

/// Texts per model run, and per hold of the model lock.
///
/// This is the batch size fastembed 5.17 used by default when the whole input
/// went to it in one call, so chunking here moves no batch boundary and changes
/// no vector. That holds for the unquantized models [`EmbedModel`] offers. A
/// dynamically quantized model must embed its whole input as one batch (its
/// vectors depend on the batch), so adding one means not chunking it.
const EMBED_BATCH: usize = 256;

/// A model behind a lock that a short embed can take between the batches of a
/// bulk one.
///
/// A bulk embed (more than one [`EMBED_BATCH`] of texts) runs batch by batch
/// and, before each batch, waits until no short embed (a query, or one written
/// summary) is pending. A short embed therefore waits for at most the batch in
/// flight, however large the bulk embed is. Holding the lock across a whole
/// corpus embed made a one-text query embed wait for all of it; releasing the
/// lock between batches is not enough on its own, because `std::sync::Mutex` is
/// not fair and a loop that unlocks and re-locks usually takes the lock back
/// before a woken waiter runs.
///
/// Short embeds are not ordered among themselves, and a steady stream of them
/// delays a bulk embed for as long as it lasts. Both are acceptable: a short
/// embed is one model run, and the bulk embed is a background sync.
struct BatchedModel<M> {
    model: Mutex<M>,
    /// Short embeds that have arrived and not yet finished.
    short_pending: Mutex<usize>,
    /// Signalled when `short_pending` returns to zero.
    short_done: Condvar,
}

impl<M> BatchedModel<M> {
    fn new(model: M) -> Self {
        Self {
            model: Mutex::new(model),
            short_pending: Mutex::new(0),
            short_done: Condvar::new(),
        }
    }

    /// Run `run` over `texts`, one [`EMBED_BATCH`] per call, and return the
    /// vectors in input order.
    fn embed(
        &self,
        texts: &[String],
        run: impl Fn(&mut M, Vec<&str>) -> Result<Vec<Vec<f32>>, MemError>,
    ) -> Result<Vec<Vec<f32>>, MemError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        if texts.len() <= EMBED_BATCH {
            let _pending = self.announce_short();
            return self.run_batch(texts, &run);
        }

        let mut vectors = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(EMBED_BATCH) {
            self.wait_for_short_embeds();
            vectors.extend(self.run_batch(chunk, &run)?);
        }
        Ok(vectors)
    }

    fn run_batch(
        &self,
        texts: &[String],
        run: &impl Fn(&mut M, Vec<&str>) -> Result<Vec<Vec<f32>>, MemError>,
    ) -> Result<Vec<Vec<f32>>, MemError> {
        // Borrow each `String` as `&str` so no clone of the texts is made.
        let docs: Vec<&str> = texts.iter().map(String::as_str).collect();
        // Recover from a poisoned lock rather than propagate the panic: a prior
        // panicked embed leaves the model logically intact (ONNX inference does
        // not mutate caller-visible state), matching `InMemoryIndex`'s poison
        // handling.
        let mut model = self.model.lock().unwrap_or_else(PoisonError::into_inner);
        run(&mut model, docs)
    }

    /// Count a short embed as pending until the returned guard drops.
    fn announce_short(&self) -> ShortPending<'_> {
        let mut pending = self
            .short_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *pending += 1;
        ShortPending {
            pending: &self.short_pending,
            done: &self.short_done,
        }
    }

    /// Block until no short embed is pending. Never called with the model lock
    /// held, so a short embed can always finish and wake this.
    fn wait_for_short_embeds(&self) {
        let mut pending = self
            .short_pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while *pending > 0 {
            pending = self
                .short_done
                .wait(pending)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// One pending short embed; dropping it (on return, error or unwind) lets a
/// waiting bulk embed continue once it was the last.
struct ShortPending<'a> {
    pending: &'a Mutex<usize>,
    done: &'a Condvar,
}

impl Drop for ShortPending<'_> {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        *pending -= 1;
        if *pending == 0 {
            self.done.notify_all();
        }
    }
}

impl Embedder for FastEmbedder {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
        self.model.embed(texts, |model, docs| {
            // `docs` is at most `EMBED_BATCH` long, so this is one ONNX run.
            model
                .embed(docs, Some(EMBED_BATCH))
                .map_err(|err| MemError::Embedding(err.to_string()))
        })
    }

    fn dim(&self) -> usize {
        self.dim
    }

    fn vector_space(&self) -> String {
        self.space.clone()
    }

    fn relevance_threshold(&self) -> f32 {
        self.threshold
    }

    fn embed_queries(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, MemError> {
        let Some(prefix) = self.query_prefix else {
            return self.embed(texts);
        };
        let prefixed: Vec<String> = texts
            .iter()
            .map(|text| {
                let mut out = String::with_capacity(prefix.len() + text.len());
                out.push_str(prefix);
                out.push_str(text);
                out
            })
            .collect();
        self.embed(&prefixed)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "the ignored live test asserts on a known-good model load + embed"
    )]

    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread;
    use std::time::Duration;

    use proptest::prelude::*;

    use super::{BatchedModel, EMBED_BATCH, EmbedModel, FastEmbedder, resolve_cache_dir};
    use crate::error::MemError;
    use crate::index::Embedder;

    /// A fake model: the log of batch sizes it was run on.
    fn log_batch(log: &mut Vec<usize>, docs: &[&str]) -> Vec<Vec<f32>> {
        log.push(docs.len());
        docs.iter().map(|_| vec![0.0]).collect()
    }

    #[test]
    fn a_bulk_embed_runs_one_batch_per_model_call_and_keeps_input_order() {
        // Each vector carries its text's number, so a reordered or dropped batch
        // shows up in the output.
        let texts: Vec<String> = (0..EMBED_BATCH * 2 + 3).map(|i| i.to_string()).collect();
        let model = BatchedModel::new(Vec::new());

        let vectors = model
            .embed(&texts, |log: &mut Vec<usize>, docs| {
                log.push(docs.len());
                docs.iter()
                    .map(|doc| {
                        let n: f32 = doc
                            .parse()
                            .map_err(|_| MemError::Embedding(format!("bad test text {doc}")))?;
                        Ok(vec![n])
                    })
                    .collect()
            })
            .expect("the fake model never fails on numeric text");

        assert_eq!(
            *model.model.lock().expect("no run panicked"),
            vec![EMBED_BATCH, EMBED_BATCH, 3]
        );
        let order: Vec<String> = vectors.iter().map(|v| v[0].to_string()).collect();
        assert_eq!(order, texts);
    }

    #[test]
    fn a_bulk_embed_stops_at_the_first_failing_batch() {
        let texts: Vec<String> = vec!["x".to_owned(); EMBED_BATCH + 1];
        let model = BatchedModel::new(0_usize);

        let result = model.embed(&texts, |runs, _docs| {
            *runs += 1;
            Err(MemError::Embedding("model failed".to_owned()))
        });

        assert!(matches!(result, Err(MemError::Embedding(_))));
        assert_eq!(*model.model.lock().expect("no run panicked"), 1);
    }

    #[test]
    fn an_empty_embed_does_not_run_the_model() {
        let model = BatchedModel::new(Vec::new());
        let vectors = model
            .embed(&[], |log: &mut Vec<usize>, docs| Ok(log_batch(log, &docs)))
            .expect("nothing to fail");
        assert!(vectors.is_empty());
        assert!(model.model.lock().expect("no run panicked").is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "waits on wall-clock time")]
    fn a_bulk_embed_waits_while_a_short_embed_is_pending() {
        // Issue #125: a query embed waited for a whole corpus embed. A pending
        // short embed must hold every bulk batch back, including the first.
        let bulk: Vec<String> = vec!["bulk".to_owned(); EMBED_BATCH + 2];
        let model = BatchedModel::new(Vec::new());
        let (ran, batch_ran) = mpsc::channel();

        thread::scope(|scope| {
            let pending = model.announce_short();
            scope.spawn(|| {
                model
                    .embed(&bulk, |log: &mut Vec<usize>, docs| {
                        ran.send(docs.len()).expect("the test is listening");
                        Ok(log_batch(log, &docs))
                    })
                    .expect("the fake model never fails");
            });

            // A bulk embed that ignored the pending short one would run its first
            // batch at once. Waiting can only miss a broken gate, never fail a
            // working one.
            assert_eq!(
                batch_ran.recv_timeout(Duration::from_millis(200)),
                Err(RecvTimeoutError::Timeout),
                "no bulk batch may run while a short embed is pending"
            );

            drop(pending);
            assert_eq!(batch_ran.recv().ok(), Some(EMBED_BATCH));
        });

        assert_eq!(
            *model.model.lock().expect("no run panicked"),
            vec![EMBED_BATCH, 2]
        );
    }

    #[test]
    fn a_failed_short_embed_is_no_longer_pending() {
        // Otherwise one failed query would park every later bulk embed for good.
        let model = BatchedModel::new(());
        let result = model.embed(&["query".to_owned()], |(), _docs| {
            Err(MemError::Embedding("model failed".to_owned()))
        });

        assert!(matches!(result, Err(MemError::Embedding(_))));
        assert_eq!(*model.short_pending.lock().expect("no holder panicked"), 0);
    }

    #[test]
    fn each_model_names_its_own_vector_space() {
        // Both are 384 wide, so the name is all that tells their vectors apart.
        assert_eq!(
            EmbedModel::MiniLmL6V2.dim(),
            EmbedModel::BgeSmallEnV15.dim()
        );
        assert_ne!(
            EmbedModel::MiniLmL6V2.vector_space(),
            EmbedModel::BgeSmallEnV15.vector_space()
        );
    }

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
        // A relative XDG_CACHE_HOME is ignored (it would resolve against the CWD,
        // the per-repo bug); resolution falls through to `$HOME/.cache`.
        assert_eq!(
            resolve_cache_dir(
                false,
                Some(Path::new("relative/cache")),
                Some(Path::new("/home/u"))
            ),
            Some(PathBuf::from("/home/u/.cache/hippius-mem/fastembed"))
        );
        // Neither candidate is absolute → no anchor here (the boundary then uses
        // the temp dir); we must not build a CWD-relative cache path.
        assert_eq!(
            resolve_cache_dir(false, Some(Path::new("rel")), Some(Path::new("also/rel"))),
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

        // A relative base (no leading `/`) is never used — it would resolve
        // against the process CWD and re-land the model under a served repo.
        #[test]
        fn relative_bases_are_ignored(seg in "[^\\x00/]{1,40}") {
            let rel = PathBuf::from(&seg);
            prop_assert!(!rel.is_absolute());
            prop_assert_eq!(resolve_cache_dir(false, Some(&rel), None), None);
            prop_assert_eq!(resolve_cache_dir(false, None, Some(&rel)), None);
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
        // BGE is asymmetric; MiniLM is not. The prefix string is the BAAI card's
        // exact instruction, including the trailing space after the colon.
        assert_eq!(EmbedModel::MiniLmL6V2.query_instruction(), None);
        assert_eq!(
            EmbedModel::BgeSmallEnV15.query_instruction(),
            Some("Represent this sentence for searching relevant passages: ")
        );
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
