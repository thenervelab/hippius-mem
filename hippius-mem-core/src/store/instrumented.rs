//! A measuring [`BlobStore`] decorator: per-operation call counts, time spent
//! inside the wrapped store, and bytes moved.
//!
//! It exists so "where does a cold sync spend its time" is answered with numbers
//! rather than log archaeology. The criterion benches wrap an in-memory store in it
//! to report how many round-trips each phase makes, and `hippius-mem profile` wraps
//! the real S3 gateway in it (underneath the local cache, so only real network
//! traffic is counted) to split each phase's wall clock into gateway time and
//! local CPU time.
//!
//! # Read-only mode
//!
//! [`InstrumentedBlobStore::read_only`] refuses every `put` and `delete` with
//! [`MemError::Storage`] before it reaches the wrapped store. A profiling run
//! against a team's real bucket must never write to it, and the one write a read
//! path can issue — `sync`'s best-effort index checkpoint — already treats a
//! failed put as "the next sync takes the slow path", so refusing it changes no
//! result, only skips that write.
//!
//! # Busy time is not wall time
//!
//! Each call's duration is added to its operation's `busy` total. Calls that run
//! concurrently (the op-log and note-blob fetches do) each contribute their full
//! duration, so `busy` can exceed the wall clock of the phase that issued them. It
//! answers "how much gateway time did this phase consume", not "how long did the
//! phase take".

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::{BlobStore, MemError};

/// Counters for one kind of [`BlobStore`] operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpStats {
    /// Calls made, including ones that returned an error.
    pub calls: u64,
    /// Summed time spent inside the wrapped store (see the module docs: this can
    /// exceed wall time when calls overlap).
    pub busy: Duration,
    /// Payload bytes moved: returned by a successful `get`, or sent by a `put`.
    /// Always zero for `list` and `delete`.
    pub bytes: u64,
}

impl OpStats {
    /// The counters accumulated since `earlier` was taken.
    ///
    /// Saturating, so a mismatched pair (an `earlier` taken from a different
    /// store) yields zeros rather than a panic or a wrapped value.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            calls: self.calls.saturating_sub(earlier.calls),
            busy: self.busy.saturating_sub(earlier.busy),
            bytes: self.bytes.saturating_sub(earlier.bytes),
        }
    }

    fn record(&mut self, elapsed: Duration, bytes: u64) {
        self.calls += 1;
        self.busy += elapsed;
        self.bytes += bytes;
    }
}

/// A point-in-time copy of every operation's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlobStats {
    /// `list` calls. A paginated S3 listing is ONE call here: the pages are
    /// fetched inside the wrapped store.
    pub list: OpStats,
    /// `get` calls.
    pub get: OpStats,
    /// `put` calls, including ones refused in read-only mode.
    pub put: OpStats,
    /// `delete` calls, including ones refused in read-only mode.
    pub delete: OpStats,
}

impl BlobStats {
    /// The counters accumulated since `earlier` was taken — the cost of whatever
    /// ran between the two [`InstrumentedBlobStore::stats`] calls.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            list: self.list.since(&earlier.list),
            get: self.get.since(&earlier.get),
            put: self.put.since(&earlier.put),
            delete: self.delete.since(&earlier.delete),
        }
    }

    /// Summed busy time across all four operations.
    #[must_use]
    pub fn busy(&self) -> Duration {
        self.list.busy + self.get.busy + self.put.busy + self.delete.busy
    }
}

/// Whether writes pass through to the wrapped store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriteMode {
    PassThrough,
    Refuse,
}

/// A [`BlobStore`] decorator that measures every call it forwards.
///
/// See the module docs for what is measured and for read-only mode.
pub struct InstrumentedBlobStore {
    inner: Arc<dyn BlobStore>,
    writes: WriteMode,
    stats: Mutex<BlobStats>,
}

impl std::fmt::Debug for InstrumentedBlobStore {
    // `dyn BlobStore` is not `Debug`; the counters are what matters here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstrumentedBlobStore")
            .field("writes", &self.writes)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl InstrumentedBlobStore {
    /// Measure `inner`, forwarding every call including writes.
    #[must_use]
    pub fn new(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            inner,
            writes: WriteMode::PassThrough,
            stats: Mutex::new(BlobStats::default()),
        }
    }

    /// Measure `inner`, refusing every `put` and `delete` (see the module docs).
    #[must_use]
    pub fn read_only(inner: Arc<dyn BlobStore>) -> Self {
        Self {
            writes: WriteMode::Refuse,
            ..Self::new(inner)
        }
    }

    /// The counters accumulated so far. Take one before and one after a phase and
    /// diff them with [`BlobStats::since`].
    #[must_use]
    pub fn stats(&self) -> BlobStats {
        *self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    // A sync method, so the std mutex guard can never be held across an await.
    fn record(&self, pick: fn(&mut BlobStats) -> &mut OpStats, elapsed: Duration, bytes: u64) {
        let mut stats = self.stats.lock().unwrap_or_else(PoisonError::into_inner);
        pick(&mut stats).record(elapsed, bytes);
    }

    fn refuse(&self, verb: &str, key: &str) -> Result<(), MemError> {
        match self.writes {
            WriteMode::PassThrough => Ok(()),
            WriteMode::Refuse => Err(MemError::Storage(format!(
                "{verb} of {key} refused: this blob store is read-only (a measuring run \
                 must not write to the bucket)"
            ))),
        }
    }
}

/// Byte length as `u64`, saturating on the (theoretical) platform where `usize`
/// is wider.
fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[async_trait]
impl BlobStore for InstrumentedBlobStore {
    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), MemError> {
        let started = Instant::now();
        let size = len_u64(bytes.len());
        let result = match self.refuse("put", key) {
            Ok(()) => self.inner.put(key, bytes).await,
            Err(err) => Err(err),
        };
        self.record(|stats| &mut stats.put, started.elapsed(), size);
        result
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, MemError> {
        let started = Instant::now();
        let result = self.inner.get(key).await;
        let size = result.as_ref().map_or(0, |bytes| len_u64(bytes.len()));
        self.record(|stats| &mut stats.get, started.elapsed(), size);
        result
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, MemError> {
        let started = Instant::now();
        let result = self.inner.list(prefix).await;
        self.record(|stats| &mut stats.list, started.elapsed(), 0);
        result
    }

    async fn delete(&self, key: &str) -> Result<(), MemError> {
        let started = Instant::now();
        let result = match self.refuse("delete", key) {
            Ok(()) => self.inner.delete(key).await,
            Err(err) => Err(err),
        };
        self.record(|stats| &mut stats.delete, started.elapsed(), 0);
        result
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;
    use crate::MemoryBlobStore;

    type TestResult = Result<(), MemError>;

    fn memory() -> Arc<dyn BlobStore> {
        Arc::new(MemoryBlobStore::default())
    }

    #[tokio::test]
    async fn counts_calls_and_bytes_per_operation() -> TestResult {
        let store = InstrumentedBlobStore::new(memory());

        store.put("t/a", vec![0; 5]).await?;
        store.put("t/b", vec![0; 7]).await?;
        store.get("t/a").await?;
        store.list("t/").await?;
        store.delete("t/b").await?;

        let stats = store.stats();
        assert_eq!((stats.put.calls, stats.put.bytes), (2, 12));
        assert_eq!((stats.get.calls, stats.get.bytes), (1, 5));
        assert_eq!((stats.list.calls, stats.list.bytes), (1, 0));
        assert_eq!((stats.delete.calls, stats.delete.bytes), (1, 0));
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_get_counts_the_call_but_no_bytes() -> TestResult {
        let store = InstrumentedBlobStore::new(memory());

        let missing = store.get("t/absent").await;

        assert!(matches!(missing, Err(MemError::NotFound { .. })));
        assert_eq!(store.stats().get.calls, 1);
        assert_eq!(store.stats().get.bytes, 0);
        Ok(())
    }

    #[tokio::test]
    async fn since_isolates_one_phase() -> TestResult {
        let store = InstrumentedBlobStore::new(memory());
        store.put("t/a", vec![1; 3]).await?;
        let before = store.stats();

        store.get("t/a").await?;
        store.get("t/a").await?;
        let phase = store.stats().since(&before);

        assert_eq!(phase.put.calls, 0);
        assert_eq!((phase.get.calls, phase.get.bytes), (2, 6));
        Ok(())
    }

    #[tokio::test]
    async fn read_only_refuses_writes_before_they_reach_the_store() -> TestResult {
        let inner = memory();
        inner.put("t/kept", vec![9]).await?;
        let store = InstrumentedBlobStore::read_only(inner.clone());

        let put = store.put("t/new", vec![1]).await;
        let delete = store.delete("t/kept").await;

        assert!(matches!(put, Err(MemError::Storage(_))));
        assert!(matches!(delete, Err(MemError::Storage(_))));
        assert!(matches!(
            inner.get("t/new").await,
            Err(MemError::NotFound { .. })
        ));
        assert_eq!(inner.get("t/kept").await?, vec![9]);
        assert_eq!(store.stats().put.calls, 1);
        assert_eq!(store.stats().delete.calls, 1);
        Ok(())
    }

    #[tokio::test]
    async fn read_only_still_forwards_reads() -> TestResult {
        let inner = memory();
        inner.put("t/a", vec![4, 2]).await?;
        let store = InstrumentedBlobStore::read_only(inner);

        assert_eq!(store.get("t/a").await?, vec![4, 2]);
        assert_eq!(store.list("t/").await?, vec!["t/a".to_owned()]);
        Ok(())
    }
}
