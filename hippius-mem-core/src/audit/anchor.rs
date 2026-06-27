//! The audit-anchor seam: where a batch's Merkle root gets committed.
//!
//! Phase 2 anchors the op-log cheaply by batching op hashes into a [`merkle`]
//! tree and committing only the *root* on-chain. This module is the seam that
//! commits a root somewhere durable: the [`AuditAnchor`] trait, two always-compiled
//! fakes ([`NoopAnchor`], [`RecordingAnchor`]) that cover the logic in tests and
//! the no-chain runtime, and — behind the `chain` feature — a real [`SubxtAnchor`]
//! that submits a `frame_system::remark_with_event` extrinsic to the Hippius
//! chain.
//!
//! # On-chain sink: `remark_with_event`
//!
//! The root is anchored with `System::remark_with_event(remark: Vec<u8>)`, the
//! generic FRAME audit primitive: any signed sr25519 account may call it, it is
//! always permitted, and it emits `System.Remarked { sender, hash }`. It carries
//! a fee (`Pays::Yes`) and is weighted by remark length, so anchoring one root
//! per batch — rather than one per op — is what keeps the cost bounded. We do not
//! depend on the Hippius runtime's pallets: a remark is understood by every
//! Substrate chain, which keeps this seam decoupled from runtime upgrades.
//!
//! # Why a trait seam
//!
//! [`crate::store::MemoryStore::history`] reads an [`AnchorReceipt`]'s
//! [`AnchorRef`] to point a
//! reader at where a root was committed, then proves a specific op under that
//! root with a Merkle inclusion proof. Keeping anchoring behind a trait lets the
//! default runtime use [`NoopAnchor`] (no chain, no fee) while tests assert on
//! [`RecordingAnchor`] and production opts into [`SubxtAnchor`] — without any of
//! them knowing how the others work.
//!
//! [`merkle`]: crate::audit::merkle

use crate::domain::Blake3Hash;
use crate::error::MemError;
use serde::{Deserialize, Serialize};

/// Domain-separation tag prefixing every anchor payload (see [`anchor_payload`]).
///
/// Versioned so a future payload layout (`/v2`) is distinguishable on-chain
/// without ambiguity: a reader keys off the exact tag before trusting the bytes.
const ANCHOR_TAG: &[u8] = b"hippius-memory-anchor/v1";

/// Width of a [`Blake3Hash`] root in bytes — the fixed root region of a payload.
const ROOT_LEN: usize = 32;

/// Describes the op-log batch whose Merkle root is being anchored.
///
/// Travels inside the on-chain remark alongside the root so a reader can locate
/// the exact ops the root commits to — `team`'s op-log over the lamport-clock
/// half-open-ish inclusive range `[first_lamport, last_lamport]`.
///
/// # Wire contract
///
/// This is a plain data struct serialized with serde's default (field-order)
/// JSON shape; `op_count` is a redundant cross-check on the range. New fields
/// must be added as `Option`/`#[serde(default)]` so older payloads still parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchMeta {
    /// The team whose op-log this batch belongs to.
    pub team: String,
    /// Lamport clock of the earliest op in the batch (inclusive).
    pub first_lamport: u64,
    /// Lamport clock of the latest op in the batch (inclusive).
    pub last_lamport: u64,
    /// Number of ops in the batch — the Merkle tree's leaf count.
    pub op_count: usize,
}

/// Where a Merkle root was anchored.
///
/// Modeled as a closed enum rather than a nullable on-chain field: a root is
/// *either* recorded locally (no chain configured) *or* committed on-chain, and
/// `history` must handle both, so an exhaustive match is the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorRef {
    /// Recorded locally without touching a chain. `seq` orders local anchors.
    Local {
        /// Monotonic local sequence number assigned at anchoring time.
        seq: u64,
    },
    /// Committed on-chain by a `remark_with_event` extrinsic.
    OnChain {
        /// Hex (`0x`-prefixed) hash of the block that included the extrinsic.
        block_hash: String,
        /// Hex (`0x`-prefixed) hash of the anchoring extrinsic itself.
        extrinsic_hash: String,
    },
}

/// The outcome of anchoring a root: the root and where it landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorReceipt {
    /// The Merkle root that was anchored.
    pub root: Blake3Hash,
    /// Where the root was anchored — `history` resolves the proof location from this.
    pub reference: AnchorRef,
}

/// The exact bytes committed in an anchor remark: `tag ++ root ++ JSON(meta)`.
///
/// Layout, in order:
/// 1. [`ANCHOR_TAG`] (`b"hippius-memory-anchor/v1"`, 24 bytes) — domain tag.
/// 2. `root.as_bytes()` (32 bytes) — the anchored Merkle root.
/// 3. `serde_json(meta)` (variable) — the [`BatchMeta`] as JSON.
///
/// The fixed-width tag and root prefix mean a reader can split the payload
/// without a length field: the JSON tail is whatever follows the first 56 bytes.
/// [`parse_anchor_payload`] is the exact inverse.
///
/// Pure and deterministic: the tag and root are fixed inputs and serde renders a
/// struct in stable field-declaration order, so equal inputs yield equal bytes.
///
/// # Errors
///
/// Returns [`MemError::Serialize`] if `meta` cannot be rendered as JSON. For the
/// current plain-data [`BatchMeta`] this has no reachable failure mode, but the
/// fallible signature keeps the serde boundary honest rather than papering over
/// it with a panic.
pub fn anchor_payload(root: &Blake3Hash, meta: &BatchMeta) -> Result<Vec<u8>, MemError> {
    let meta_json = serde_json::to_vec(meta)?;
    let mut payload = Vec::with_capacity(ANCHOR_TAG.len() + ROOT_LEN + meta_json.len());
    payload.extend_from_slice(ANCHOR_TAG);
    payload.extend_from_slice(root.as_bytes());
    payload.extend_from_slice(&meta_json);
    Ok(payload)
}

/// Parse an [`anchor_payload`] back into its root and [`BatchMeta`].
///
/// The exact inverse of [`anchor_payload`]: `parse(payload(root, meta))` yields
/// `(root, meta)`.
///
/// # Errors
///
/// Returns [`MemError::Storage`] if `bytes` does not begin with [`ANCHOR_TAG`]
/// or is too short to contain the 32-byte root (a malformed or foreign payload),
/// and [`MemError::Serialize`] if the JSON tail is not a valid [`BatchMeta`].
pub fn parse_anchor_payload(bytes: &[u8]) -> Result<(Blake3Hash, BatchMeta), MemError> {
    let after_tag = bytes
        .strip_prefix(ANCHOR_TAG)
        .ok_or_else(|| MemError::Storage("anchor payload: missing domain tag".to_owned()))?;
    if after_tag.len() < ROOT_LEN {
        return Err(MemError::Storage(format!(
            "anchor payload: truncated root, need {} bytes, got {}",
            ROOT_LEN,
            after_tag.len()
        )));
    }
    let (root_bytes, meta_json) = after_tag.split_at(ROOT_LEN);
    // The split guarantees exactly `LEN` bytes, so the array conversion holds.
    let root = Blake3Hash::new(root_bytes.try_into().map_err(|_| {
        MemError::Storage("anchor payload: root slice was not 32 bytes".to_owned())
    })?);
    let meta = serde_json::from_slice(meta_json)?;
    Ok((root, meta))
}

/// The anchoring seam: commit a batch's Merkle root somewhere durable.
///
/// Object-safe and `Send + Sync`, so callers hold an `Arc<dyn AuditAnchor>` and
/// share it across tasks on a multithreaded runtime. It uses [`macro@async_trait`]
/// rather than native `async fn` in trait because `dyn` dispatch is required and
/// native async-fn-in-trait is not yet `dyn`-compatible — the same rationale as
/// [`crate::store::BlobStore`].
#[async_trait::async_trait]
pub trait AuditAnchor: Send + Sync {
    /// Anchor `root` (committing `meta` alongside it) and report where it landed.
    ///
    /// # Errors
    ///
    /// Returns [`MemError::Storage`] if the underlying sink (e.g. a chain) fails
    /// to commit the root.
    async fn anchor(&self, root: Blake3Hash, meta: BatchMeta) -> Result<AnchorReceipt, MemError>;

    /// Upcast to [`Any`](std::any::Any) so a caller can recover the concrete
    /// anchor and reach chain-only operations the trait does not expose.
    ///
    /// The reconcile path uses this to downcast to [`SubxtAnchor`] and read a
    /// committed root back from the chain (a trust-minimized check the bucket
    /// cannot forge). Returning `&dyn Any` rather than naming `SubxtAnchor`
    /// keeps this trait decoupled from the `chain`-gated type — the default
    /// fakes simply return themselves and a non-chain build never downcasts.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// An [`AuditAnchor`] that anchors nothing: the default when chain anchoring is off.
///
/// Returns a [`AnchorRef::Local`] receipt with `seq: 0` and performs no I/O — the
/// roots still flow through `history`, just without an on-chain reference.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAnchor;

#[async_trait::async_trait]
impl AuditAnchor for NoopAnchor {
    async fn anchor(&self, root: Blake3Hash, _meta: BatchMeta) -> Result<AnchorReceipt, MemError> {
        Ok(AnchorReceipt {
            root,
            reference: AnchorRef::Local { seq: 0 },
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// An [`AuditAnchor`] that records every anchored `(root, meta)` for assertions.
///
/// Used by tests to verify the batching/scheduling layer drives anchoring as
/// expected. Each call gets the next local sequence number (its index in the
/// record), so [`RecordingAnchor::anchored`] returns calls in anchoring order.
#[derive(Debug, Default)]
pub struct RecordingAnchor {
    // `Mutex` gives interior mutability behind the `&self` the trait dictates.
    // The guard is never held across an `.await` (there is none in `anchor`),
    // so this stays sound under the `await_holding_lock` lint and a Send future.
    records: std::sync::Mutex<Vec<(Blake3Hash, BatchMeta)>>,
}

impl RecordingAnchor {
    /// Create an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every `(root, meta)` anchored so far, in anchoring order.
    #[must_use]
    pub fn anchored(&self) -> Vec<(Blake3Hash, BatchMeta)> {
        // A poisoned lock means a prior holder panicked; the recorded data is
        // still structurally valid, so recover it rather than propagate panic.
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[async_trait::async_trait]
impl AuditAnchor for RecordingAnchor {
    async fn anchor(&self, root: Blake3Hash, meta: BatchMeta) -> Result<AnchorReceipt, MemError> {
        // Scope the guard so it is dropped before the receipt is built; the seq
        // is the record's index, assigned under the lock to stay monotonic.
        let seq = {
            let mut records = self
                .records
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let seq = records.len() as u64;
            records.push((root, meta));
            seq
        };
        Ok(AnchorReceipt {
            root,
            reference: AnchorRef::Local { seq },
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "chain")]
pub use self::subxt_anchor::SubxtAnchor;

#[cfg(feature = "chain")]
mod subxt_anchor {
    use super::{
        AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta, anchor_payload, parse_anchor_payload,
    };
    use crate::domain::Blake3Hash;
    use crate::error::MemError;
    use core::fmt;
    use subxt::config::substrate::H256;
    use subxt::dynamic::{self, Value};
    use subxt::{OnlineClient, PolkadotConfig};
    use subxt_signer::sr25519::Keypair;

    /// An [`AuditAnchor`] that commits roots on the Hippius chain via a
    /// `System::remark_with_event` extrinsic, signed by an sr25519 key.
    ///
    /// Built behind the `chain` feature so the default build never pulls the
    /// heavy `subxt` stack. Live submission needs a funded sr25519 account and a
    /// reachable node, so the anchoring path is exercised only by an `#[ignore]`d
    /// integration test — unit tests cover the always-compiled fakes instead.
    pub struct SubxtAnchor {
        client: OnlineClient<PolkadotConfig>,
        signer: Keypair,
    }

    impl fmt::Debug for SubxtAnchor {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            // Never render the keypair: its `Debug` would leak secret-key bytes.
            f.debug_struct("SubxtAnchor")
                .field("signer", &"<redacted sr25519 keypair>")
                .finish_non_exhaustive()
        }
    }

    impl SubxtAnchor {
        /// Connect to the node at `ws_url` and load the sr25519 signer from
        /// `signer_seed` (a 32-byte `MiniSecretKey` seed).
        ///
        /// `from_url` fetches chain metadata eagerly, so an unreachable URL fails
        /// here rather than at submission time.
        ///
        /// # Errors
        ///
        /// Returns [`MemError::Storage`] if the node is unreachable or its
        /// metadata cannot be loaded, or if `signer_seed` is not a valid seed.
        pub async fn connect(ws_url: &str, signer_seed: [u8; 32]) -> Result<Self, MemError> {
            let client = OnlineClient::<PolkadotConfig>::from_url(ws_url)
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;
            let signer = Keypair::from_secret_key(signer_seed)
                .map_err(|e| MemError::Storage(e.to_string()))?;
            Ok(Self { client, signer })
        }

        /// Read back the Merkle root committed on-chain at an anchor location.
        ///
        /// Fetches the block named by `block_hash`, finds the anchoring extrinsic
        /// inside it whose hash matches `extrinsic_hash`, decodes the remark
        /// payload, and returns the root it committed. The reconciler compares
        /// that against the bucket's [`AnchorRecord`](crate::audit::batch::AnchorRecord)
        /// `root`, so a record the bucket forged — even one internally consistent
        /// (`root == merkle_root(leaves)`) — is caught when the chain disagrees.
        ///
        /// # Honest limits of what subxt 0.50 can read back
        ///
        /// - **Archive node required.** Reading an arbitrary historical block by
        ///   hash needs a node that still retains that block. A pruned full node
        ///   may no longer have it; this returns [`MemError::Storage`] rather than
        ///   silently passing — "could not verify" must never read as "verified".
        /// - **No extrinsic-hash index.** Substrate maintains no map from an
        ///   extrinsic hash to its location, and subxt exposes none. So the lookup
        ///   key is `block_hash` (fetch the block), and `extrinsic_hash` only
        ///   disambiguates the extrinsic *within* that block. Direct lookup by
        ///   extrinsic hash alone would require an external indexer.
        /// - **CI-untested.** Like [`SubxtAnchor::anchor`], this compiles under
        ///   `--features chain` but is exercised only against a live archive node;
        ///   there is no chain in CI.
        ///
        /// # Errors
        ///
        /// [`MemError::Storage`] if `block_hash` is not a valid hash, the block
        /// cannot be fetched (e.g. not retained by the node), the extrinsics
        /// cannot be read, the named extrinsic is absent from the block, or its
        /// remark does not decode as an anchor payload.
        pub async fn read_anchored_root(
            &self,
            block_hash: &str,
            extrinsic_hash: &str,
        ) -> Result<Blake3Hash, MemError> {
            let parsed: H256 = block_hash.parse().map_err(|e| {
                MemError::Storage(format!(
                    "anchor block hash {block_hash:?} is not a valid H256: {e}"
                ))
            })?;

            let at_block = self.client.at_block(parsed).await.map_err(|e| {
                MemError::Storage(format!(
                    "could not fetch anchor block {block_hash} \
                     (an archive node retaining this block is required): {e}"
                ))
            })?;
            let extrinsics = at_block
                .extrinsics()
                .fetch()
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;

            for extrinsic in extrinsics.iter() {
                let extrinsic = extrinsic.map_err(|e| MemError::Storage(e.to_string()))?;
                // No extrinsic-hash index exists, so match within the fetched
                // block. `{:#x}` mirrors how `anchor` rendered the receipt hash.
                if format!("{:#x}", extrinsic.hash()) != extrinsic_hash {
                    continue;
                }
                // `remark_with_event` carries one field — the payload bytes.
                let field = extrinsic.iter_call_data_fields().next().ok_or_else(|| {
                    MemError::Storage(format!(
                        "anchor extrinsic {extrinsic_hash} has no call-data fields"
                    ))
                })?;
                let payload: Vec<u8> = field.decode_as::<Vec<u8>>().map_err(|e| {
                    MemError::Storage(format!(
                        "anchor extrinsic {extrinsic_hash} remark did not decode as bytes: {e}"
                    ))
                })?;
                let (root, _meta) = parse_anchor_payload(&payload)?;
                return Ok(root);
            }
            Err(MemError::Storage(format!(
                "anchor extrinsic {extrinsic_hash} not found in block {block_hash}"
            )))
        }
    }

    #[async_trait::async_trait]
    impl AuditAnchor for SubxtAnchor {
        async fn anchor(
            &self,
            root: Blake3Hash,
            meta: BatchMeta,
        ) -> Result<AnchorReceipt, MemError> {
            let payload = anchor_payload(&root, &meta)?;
            // Dynamic call: one unnamed field — the `remark: Vec<u8>` bytes —
            // so no compile-time runtime metadata codegen is needed.
            let call = dynamic::tx(
                "System",
                "remark_with_event",
                vec![Value::from_bytes(&payload)],
            );

            // `subxt`'s errors are operation-generic (like the S3 `SdkError`),
            // so every stage collapses into the one `Storage` category.
            let mut txs = self
                .client
                .tx()
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;
            let in_block = txs
                .sign_and_submit_then_watch_default(&call, &self.signer)
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?
                .wait_for_finalized()
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;
            // Confirm the extrinsic dispatched successfully (System.ExtrinsicSuccess),
            // not merely that it was included — a remark can be included yet fail.
            in_block
                .wait_for_success()
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;

            // Full `0x`-prefixed lowercase hex via `LowerHex`; `H256`'s `Display`
            // abbreviates, which would lose the hash, so format with `{:#x}`.
            let reference = AnchorRef::OnChain {
                block_hash: format!("{:#x}", in_block.block_hash()),
                extrinsic_hash: format!("{:#x}", in_block.extrinsic_hash()),
            };
            Ok(AnchorReceipt { root, reference })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on known-valid fixtures where construction cannot fail"
    )]

    use super::*;
    use proptest::prelude::*;

    fn meta() -> BatchMeta {
        BatchMeta {
            team: "acme".to_owned(),
            first_lamport: 1,
            last_lamport: 9,
            op_count: 9,
        }
    }

    fn root(byte: u8) -> Blake3Hash {
        Blake3Hash::new([byte; 32])
    }

    #[tokio::test]
    async fn noop_returns_local_receipt() {
        let receipt = NoopAnchor.anchor(root(7), meta()).await.unwrap();
        assert_eq!(
            receipt,
            AnchorReceipt {
                root: root(7),
                reference: AnchorRef::Local { seq: 0 },
            }
        );
    }

    #[tokio::test]
    async fn recording_anchor_records_in_order() {
        let anchor = RecordingAnchor::new();

        let first = anchor.anchor(root(1), meta()).await.unwrap();
        let second = anchor.anchor(root(2), meta()).await.unwrap();

        assert_eq!(first.reference, AnchorRef::Local { seq: 0 });
        assert_eq!(second.reference, AnchorRef::Local { seq: 1 });

        let recorded = anchor.anchored();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], (root(1), meta()));
        assert_eq!(recorded[1], (root(2), meta()));
    }

    #[test]
    fn anchor_payload_contains_root_and_is_deterministic() {
        let payload = anchor_payload(&root(0xAB), &meta()).unwrap();

        assert!(
            payload.starts_with(ANCHOR_TAG),
            "payload must carry the tag"
        );
        let root_region = &payload[ANCHOR_TAG.len()..ANCHOR_TAG.len() + ROOT_LEN];
        assert_eq!(
            root_region,
            root(0xAB).as_bytes(),
            "root bytes must be embedded"
        );
        assert_eq!(
            payload,
            anchor_payload(&root(0xAB), &meta()).unwrap(),
            "equal inputs must yield equal bytes"
        );
    }

    #[test]
    fn parse_rejects_missing_tag_and_truncation() {
        assert!(parse_anchor_payload(b"").is_err());
        assert!(parse_anchor_payload(b"not-an-anchor").is_err());
        // Correct tag but no room for the 32-byte root.
        let mut short = ANCHOR_TAG.to_vec();
        short.extend_from_slice(&[0u8; 8]);
        assert!(parse_anchor_payload(&short).is_err());
        // Correct tag + root but a non-JSON tail.
        let mut bad_json = ANCHOR_TAG.to_vec();
        bad_json.extend_from_slice(&[0u8; 32]);
        bad_json.extend_from_slice(b"{not json");
        assert!(parse_anchor_payload(&bad_json).is_err());
    }

    // Reachable only with `--features chain`. No live chain in CI: connecting to
    // an unroutable address must surface a mapped `MemError`, never panic —
    // proving the real subxt path compiles, runs, and categorizes its errors.
    #[cfg(feature = "chain")]
    #[tokio::test]
    async fn subxt_connect_to_dead_url_errs() {
        let result = SubxtAnchor::connect("ws://127.0.0.1:1", [7u8; 32]).await;
        assert!(matches!(result, Err(MemError::Storage(_))));
    }

    prop_compose! {
        fn arb_meta()(
            team in ".{0,64}",
            first_lamport in any::<u64>(),
            last_lamport in any::<u64>(),
            op_count in any::<usize>(),
        ) -> BatchMeta {
            BatchMeta { team, first_lamport, last_lamport, op_count }
        }
    }

    proptest! {
        #[test]
        fn payload_parse_round_trips(
            bytes in proptest::array::uniform32(any::<u8>()),
            meta in arb_meta(),
        ) {
            let root = Blake3Hash::new(bytes);
            let payload = anchor_payload(&root, &meta).unwrap();
            let (parsed_root, parsed_meta) = parse_anchor_payload(&payload).unwrap();
            prop_assert_eq!(parsed_root, root);
            prop_assert_eq!(parsed_meta, meta);
        }
    }
}
