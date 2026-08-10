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
/// range `[first_lamport, last_lamport]`, inclusive on both ends (matching the
/// per-field docs below).
///
/// # Wire contract
///
/// This is a plain data struct serialized with serde's default (field-order)
/// JSON shape; `op_count` is the batch's Merkle leaf count, cross-checked against
/// the stored leaves at read time by
/// [`read_anchor_records`](crate::audit::batch::read_anchor_records) — a record
/// whose `op_count` disagrees with its `leaves` is rejected. New fields must be
/// added as `Option`/`#[serde(default)]` so older payloads still parse.
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
/// Returns [`MemError::Malformed`] if `bytes` does not begin with [`ANCHOR_TAG`]
/// or is too short to contain the 32-byte root (a malformed or foreign payload),
/// and [`MemError::Serialize`] if the JSON tail is not a valid [`BatchMeta`].
pub fn parse_anchor_payload(bytes: &[u8]) -> Result<(Blake3Hash, BatchMeta), MemError> {
    let after_tag = bytes
        .strip_prefix(ANCHOR_TAG)
        .ok_or_else(|| MemError::Malformed("anchor payload: missing domain tag".to_owned()))?;
    if after_tag.len() < ROOT_LEN {
        return Err(MemError::Malformed(format!(
            "anchor payload: truncated root, need {} bytes, got {}",
            ROOT_LEN,
            after_tag.len()
        )));
    }
    let (root_bytes, meta_json) = after_tag.split_at(ROOT_LEN);
    // The split guarantees exactly `LEN` bytes, so the array conversion holds.
    let root = Blake3Hash::new(root_bytes.try_into().map_err(|_| {
        MemError::Malformed("anchor payload: root slice was not 32 bytes".to_owned())
    })?);
    let meta = serde_json::from_slice(meta_json)?;
    Ok((root, meta))
}

/// Decode the account that signed an anchoring extrinsic from its SCALE-encoded
/// address bytes.
///
/// Lifted verbatim out of [`SubxtAnchor::read_anchored_root`] because it is pure
/// byte decoding: no client, no chain metadata, no I/O. The live readback around
/// it genuinely cannot run in CI, but this can. Every
/// [`RootMismatch::ChainSignerMismatch`](crate::audit::reconcile::RootMismatch)
/// verdict is an accusation against a named account, and it rests on the byte
/// layout decoded here.
///
/// What the fixture tests around this DO and do NOT cover, stated separately
/// because it is easy to conflate them: they pin how THIS function reads a
/// 33-byte `MultiAddress::Id`, given those bytes. They do NOT protect against a
/// `subxt` upgrade. Such an upgrade would change the OUTPUT of
/// `Extrinsic::address_bytes()` — the INPUT handed to this function — and every
/// fixture test here would stay green while production broke. Pinning that
/// assumption against subxt's actual output needs the node round-trip no CI job
/// can run. What is pinned here is our own byte-layout assumption, not that the
/// assumption still matches the encoder upstream.
///
/// `address_bytes` is exactly what subxt's `Extrinsic::address_bytes()` returns:
/// `None` for an unsigned extrinsic, otherwise the SCALE-encoded `MultiAddress`.
/// A normal sr25519 signer is `MultiAddress::Id(AccountId32)` — the variant byte
/// `0x00` followed by 32 account bytes. `extrinsic_hash` only names the extrinsic
/// in the error messages; it takes no part in the decoding.
///
/// Compiled for the `chain` feature and for `cfg(test)` (the same gate
/// [`ChainRootReader`](crate::audit::reconcile) uses) so the default-feature test
/// job exercises it too, without the default *build* pulling anything in.
///
/// # Errors
///
/// [`MemError::Storage`] if the extrinsic is unsigned, or if the address is not a
/// 33-byte `MultiAddress::Id`. An anchor that cannot be attributed is surfaced as
/// an error — "could not verify" is not "verified" — never a silent pass and
/// never a guessed account.
#[cfg(any(feature = "chain", test))]
fn decode_remark_signer(
    address_bytes: Option<&[u8]>,
    extrinsic_hash: &str,
) -> Result<[u8; 32], MemError> {
    // An unsigned extrinsic, or any non-Id / wrong-length address, is an anchor
    // we cannot attribute — surface it as an error, never a silent pass.
    let address = address_bytes.ok_or_else(|| {
        MemError::Storage(format!(
            "anchor extrinsic {extrinsic_hash} is unsigned; its anchoring \
             account cannot be verified against the record's author"
        ))
    })?;

    if address.first() == Some(&0x00) && address.len() == 33 {
        let mut account = [0u8; 32];
        account.copy_from_slice(&address[1..]);
        Ok(account)
    } else {
        Err(MemError::Storage(format!(
            "anchor extrinsic {extrinsic_hash} signer is not a MultiAddress::Id \
             account ({} address bytes); cannot attribute it to an author",
            address.len()
        )))
    }
}

/// Decode the Merkle root an anchoring extrinsic's remark committed.
///
/// The companion to [`decode_remark_signer`], lifted out of
/// [`SubxtAnchor::read_anchored_root`] for the same reason: `remark` is the
/// already-SCALE-decoded remark payload, so recovering the root from it is pure
/// and testable without a node. The `BatchMeta` travelling beside the root is
/// deliberately dropped — the reconciler compares roots, and the meta is
/// re-derived from the bucket's own record.
///
/// # Errors
///
/// [`MemError::Malformed`] if `remark` is not an [`anchor_payload`] (wrong domain
/// tag or a truncated root), and [`MemError::Serialize`] if its JSON tail is not
/// a [`BatchMeta`] — see [`parse_anchor_payload`].
#[cfg(any(feature = "chain", test))]
fn decode_remark_payload(remark: &[u8]) -> Result<Blake3Hash, MemError> {
    let (root, _meta) = parse_anchor_payload(remark)?;
    Ok(root)
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
        AnchorReceipt, AnchorRef, AuditAnchor, BatchMeta, anchor_payload, decode_remark_payload,
        decode_remark_signer,
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
    /// heavy `subxt` stack.
    ///
    /// # What is and is not tested
    ///
    /// Live submission needs a funded sr25519 account and a reachable node, so
    /// neither [`SubxtAnchor::anchor`] nor the node-driven part of
    /// [`SubxtAnchor::read_anchored_root`] runs anywhere in CI — there is no
    /// chain in CI and no integration test (ignored or otherwise) that supplies
    /// one. Specifically **untested**: the submit-and-wait-for-success path, the
    /// finality gate, the canonical-hash-at-height reorg check, the
    /// extrinsic-hash match within the fetched block, and the metadata-driven
    /// `Vec<u8>` decode of the remark field.
    ///
    /// What IS tested, in the ordinary unit suite: the pure decode paths lifted
    /// out of the readback — `decode_remark_signer` and `decode_remark_payload`
    /// in the parent module — against committed byte fixtures, the
    /// always-compiled [`NoopAnchor`]/[`RecordingAnchor`] fakes, the
    /// [`anchor_payload`]/[`parse_anchor_payload`] codec, and (under `chain`)
    /// that [`SubxtAnchor::connect`] maps an unreachable node to a
    /// [`MemError::Storage`]. The comparison logic consuming the readback is
    /// covered separately through a mock
    /// [`ChainRootReader`](crate::audit::reconcile).
    ///
    /// [`NoopAnchor`]: super::NoopAnchor
    /// [`RecordingAnchor`]: super::RecordingAnchor
    /// [`parse_anchor_payload`]: super::parse_anchor_payload
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
        /// metadata cannot be loaded, or [`MemError::Identity`] if `signer_seed`
        /// is not a valid sr25519 seed (a key-material fault, not a backend one).
        pub async fn connect(ws_url: &str, signer_seed: &[u8; 32]) -> Result<Self, MemError> {
            let client = OnlineClient::<PolkadotConfig>::from_url(ws_url)
                .await
                .map_err(|e| MemError::Storage(e.to_string()))?;
            // A bad seed is a key-material fault, not a storage one — and the seed
            // is secret, so the error carries a fixed message, never the cause.
            // Borrowed in, copied once into subxt's `Keypair` (itself zeroize-on-drop)
            // rather than copied across the call boundary onto the caller's stack.
            let signer = Keypair::from_secret_key(*signer_seed).map_err(|_| {
                MemError::Identity("anchor signer seed is not a valid sr25519 seed")
            })?;
            Ok(Self { client, signer })
        }

        /// Read back the Merkle root committed on-chain at an anchor location.
        ///
        /// Fetches the block named by `block_hash`, confirms that block is on
        /// the finalized chain (see below), finds the anchoring extrinsic inside
        /// it whose hash matches `extrinsic_hash`, decodes the remark payload,
        /// and returns the root it committed. The reconciler compares that
        /// against the bucket's [`AnchorRecord`](crate::audit::batch::AnchorRecord)
        /// `root`, so a record the bucket forged — even one internally consistent
        /// (`root == merkle_root(leaves)`) — is caught when the chain disagrees.
        ///
        /// # Finality check
        ///
        /// Fetching `block_hash`'s header proves only that this node once SAW
        /// that block — an archive node can retain a block that was later
        /// reorged out of the canonical chain, so a bucket could anchor a
        /// remark on an orphaned block and this readback would otherwise trust
        /// it. Two documented subxt facts close that gap:
        /// [`OnlineClient::at_current_block`] resolves to "the current
        /// finalized block at the time of instantiation" (its own doc
        /// comment), so its height IS the finalized head; and the `Backend`
        /// trait's `block_number_to_hash` (reached via `at_block(number: u64)`)
        /// "return[s] `None` in the event that multiple block hashes
        /// correspond to the given number (i.e. if the number is greater than
        /// that of the latest finalized block and some forks exist)" — i.e. it
        /// is unambiguous for any height at or below the finalized head. So:
        /// reject any anchor block above the finalized height outright, then
        /// require the canonical hash AT that height to equal `block_hash`.
        /// Both must hold, or the block is not proven finalized.
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
        /// - **Node half is CI-untested.** Fetching the block, the finality
        ///   gate, the canonical-hash-at-height check, the extrinsic-hash match
        ///   and the metadata-driven remark decode all need a live archive
        ///   node; there is no chain in CI and no integration test supplies
        ///   one. The pure decoding this ends in is split out into
        ///   `decode_remark_signer` / `decode_remark_payload` and IS pinned by
        ///   committed byte fixtures in the ordinary unit suite.
        ///
        /// # Errors
        ///
        /// [`MemError::Storage`] if `block_hash` is not a valid hash, the block
        /// cannot be fetched (e.g. not retained by the node), the finalized head
        /// or the canonical block at its height cannot be resolved, the
        /// extrinsics cannot be read, the named extrinsic is absent from the
        /// block, or its remark does not decode as an anchor payload.
        /// [`MemError::AnchorNotFinalized`] if `block_hash` is above the
        /// finalized head or is not the canonical block at its height (an
        /// orphaned/reorged-out block the node still retains).
        pub(crate) async fn read_anchored_root(
            &self,
            block_hash: &str,
            extrinsic_hash: &str,
        ) -> Result<crate::audit::reconcile::AnchoredExtrinsic, MemError> {
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

            let finalized_height = self
                .client
                .at_current_block()
                .await
                .map_err(|e| {
                    MemError::Storage(format!(
                        "could not resolve the finalized head to check anchor block \
                         {block_hash} for finality: {e}"
                    ))
                })?
                .block_number();
            let anchor_height = at_block.block_number();
            if anchor_height > finalized_height {
                return Err(MemError::AnchorNotFinalized {
                    block_hash: block_hash.to_owned(),
                });
            }
            // `anchor_height <= finalized_height` makes `block_number_to_hash`
            // unambiguous for this height (see the doc section above), so the
            // hash it names is THE canonical block there.
            let canonical = self.client.at_block(anchor_height).await.map_err(|e| {
                MemError::Storage(format!(
                    "could not resolve the canonical block at height {anchor_height} \
                     to check anchor block {block_hash} for finality: {e}"
                ))
            })?;
            if canonical.block_hash() != parsed {
                return Err(MemError::AnchorNotFinalized {
                    block_hash: block_hash.to_owned(),
                });
            }

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
                // Extract the signing account so the reconciler can confirm WHO
                // anchored this. `address_bytes()` is the SCALE-encoded
                // MultiAddress, and decoding it is pure — so it lives in
                // `decode_remark_signer`, where fixtures can pin it without a
                // node. Same for the root the remark committed.
                let signer = decode_remark_signer(extrinsic.address_bytes(), extrinsic_hash)?;
                let root = decode_remark_payload(&payload)?;
                return Ok(crate::audit::reconcile::AnchoredExtrinsic { root, signer });
            }
            Err(MemError::Storage(format!(
                "anchor extrinsic {extrinsic_hash} not found in block {block_hash}"
            )))
        }
    }

    /// The chain-readback seam `reconcile_with_chain` depends on. Splitting it
    /// behind a trait lets the reconciler's trust-minimized root comparison run
    /// against a mock reader in a plain `cargo test`; this impl carries the real,
    /// CI-untested live-node readback by delegating to the inherent method above.
    /// `#[async_trait]` mirrors `BlobStore` — the future must be `Send` for the
    /// multithreaded MCP runtime.
    #[async_trait::async_trait]
    impl crate::audit::reconcile::ChainRootReader for SubxtAnchor {
        async fn read_anchored_root(
            &self,
            block_hash: &str,
            extrinsic_hash: &str,
        ) -> Result<crate::audit::reconcile::AnchoredExtrinsic, MemError> {
            SubxtAnchor::read_anchored_root(self, block_hash, extrinsic_hash).await
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
    use crate::domain::NetworkPrefix;
    use crate::identity::ss58_encode;
    use crate::oplog::VerifyingKey;
    use proptest::prelude::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ensure(cond: bool, msg: &str) -> TestResult {
        if cond { Ok(()) } else { Err(msg.into()) }
    }

    fn ensure_eq<T: PartialEq + std::fmt::Debug>(left: &T, right: &T, msg: &str) -> TestResult {
        if left == right {
            Ok(())
        } else {
            Err(format!("{msg}: {left:?} != {right:?}").into())
        }
    }

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
        let result = SubxtAnchor::connect("ws://127.0.0.1:1", &[7u8; 32]).await;
        assert!(matches!(result, Err(MemError::Storage(_))));
    }

    // ------------------------------------------------------------------
    // Decode-path fixtures for the chain anchor readback.
    //
    // `read_anchored_root` underwrites `Verification::ChainVerified`, the only
    // non-bucket-only attestation this product makes, and every
    // `RootMismatch::ChainSignerMismatch` verdict — an accusation against a
    // named account — rests on the byte layouts pinned below. The node
    // round-trip cannot run in CI; this byte decoding can, and it is what a
    // `subxt` upgrade would silently change.
    //
    // Provenance is the whole point of these constants: NEITHER was produced by
    // calling the code it pins. A fixture regenerated from the current encoder
    // re-encodes under whatever the new behaviour is, so it can never catch a
    // compat break (the trap the TeamManifest v1 fixture documents). Both were
    // assembled outside Rust from independently published definitions — see
    // each constant for exactly which, and for what it can and cannot prove.
    // ------------------------------------------------------------------

    /// Interpolated into the decoders' error messages only; never decoded.
    const FIXTURE_EXTRINSIC_HASH: &str =
        "0x9f2b4c6d8e0a1c3e5f70819293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6";

    /// `//Alice`'s sr25519 public key — the canonical published Substrate test
    /// vector, already pinned by this crate's SS58 codec test
    /// (`identity::tests::ALICE_HEX`).
    ///
    /// Held separately from the address fixture below rather than sliced out of
    /// it on purpose: slicing would re-derive the expectation using the very
    /// account offset under test, so an offset change would move both sides
    /// together and prove nothing.
    const ALICE_ACCOUNT_HEX: &str =
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

    /// `//Alice`'s SS58 address under Hippius' prefix 42 — the account name a
    /// `ChainSignerMismatch` would actually accuse. Published Substrate vector.
    const ALICE_SS58: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    /// A `MultiAddress::Id(AccountId32)` as it appears in the address region of
    /// a signed Substrate extrinsic — what `Extrinsic::address_bytes()` hands to
    /// `decode_remark_signer`.
    ///
    /// Assembled from two external, published facts, not from this crate and not
    /// from `subxt`: `0x00` is `Id`, the first variant of upstream
    /// `sp_runtime::MultiAddress` (`Id, Index, Raw, Address32, Address20`), so
    /// SCALE gives it index 0; the 32 bytes after it are [`ALICE_ACCOUNT_HEX`].
    ///
    /// Proves: a change to the expected variant index, to the account offset, or
    /// to what `address_bytes()` returns stops this decoding to Alice. Does NOT
    /// prove: that a live Hippius node's signed extrinsics really carry this
    /// address region — only the node round-trip no CI job can run shows that.
    const ALICE_MULTI_ADDRESS_ID_HEX: &str = concat!(
        // MultiAddress::Id variant index.
        "00",
        // AccountId32 — //Alice.
        "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
    );

    /// The root committed by [`ANCHOR_REMARK_PAYLOAD_HEX`], as `Blake3Hash::to_hex`
    /// renders it. Chosen to be visibly ordered so a misread offset is obvious
    /// rather than plausible.
    const ANCHOR_REMARK_ROOT_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    /// An anchor remark payload as it sits inside a `System::remark_with_event`
    /// call — what `decode_remark_payload` receives once subxt has SCALE-decoded
    /// the remark field into bytes.
    ///
    /// Hand-assembled from the layout documented on [`anchor_payload`] by hexing
    /// each part outside Rust, never by calling the encoder. Segment by segment
    /// below: the ASCII domain tag, the 32-byte root, then the `BatchMeta` JSON.
    ///
    /// Proves: the on-chain payload wire format is frozen — changing
    /// [`ANCHOR_TAG`], the root width or its offset, or a `BatchMeta` field name
    /// breaks this. Every other payload test builds its input with the same
    /// encoder it then parses, so all of them would survive such a change.
    const ANCHOR_REMARK_PAYLOAD_HEX: &str = concat!(
        // b"hippius-memory-anchor/v1"
        "686970706975732d6d656d6f72792d616e63686f722f7631",
        // 32-byte Merkle root
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        // {"team":"acme",
        "7b227465616d223a2261636d65222c",
        // "first_lamport":1,
        "2266697273745f6c616d706f7274223a312c",
        // "last_lamport":9,
        "226c6173745f6c616d706f7274223a392c",
        // "op_count":9}
        "226f705f636f756e74223a397d",
    );

    /// The error text `decode_remark_signer` produced, or a marker naming the
    /// account it wrongly decoded to.
    ///
    /// Returning a string for the success case (instead of unwrapping) keeps a
    /// decoder that wrongly ACCEPTS malformed bytes failing the assertion below
    /// with its bogus account in the message, which is the failure mode these
    /// tests exist to catch.
    fn signer_decode_outcome(address_bytes: Option<&[u8]>) -> String {
        match decode_remark_signer(address_bytes, FIXTURE_EXTRINSIC_HASH) {
            Ok(account) => format!("<decoded to account {}>", hex::encode(account)),
            Err(e) => e.to_string(),
        }
    }

    /// The [`decode_remark_payload`] counterpart of [`signer_decode_outcome`].
    fn payload_decode_outcome(remark: &[u8]) -> String {
        match decode_remark_payload(remark) {
            Ok(root) => format!("<decoded to root {}>", root.to_hex()),
            Err(e) => e.to_string(),
        }
    }

    /// The signer decode path, exercised without a node.
    ///
    /// Asserts both halves of what attribution needs: the raw `AccountId32` the
    /// reconciler compares against `record.author_key`, and the SS58 address a
    /// human reads in the resulting accusation.
    #[test]
    fn a_multi_address_id_decodes_to_the_account_it_names() -> TestResult {
        let address = hex::decode(ALICE_MULTI_ADDRESS_ID_HEX)?;

        let signer = decode_remark_signer(Some(&address), FIXTURE_EXTRINSIC_HASH)?;

        ensure_eq(
            &hex::encode(signer).as_str(),
            &ALICE_ACCOUNT_HEX,
            "the decoded signer must be the AccountId32 the address carried",
        )?;
        // The exact conversion `verify_on_chain_roots` performs before naming an
        // account in a `ChainSignerMismatch`, so the pinned value is the one a
        // reader of that verdict would be accused by.
        ensure_eq(
            &ss58_encode(&VerifyingKey::new(signer), NetworkPrefix::HIPPIUS).as_str(),
            &ALICE_SS58,
            "the decoded signer must resolve to //Alice's published SS58 address",
        )
    }

    /// An address that is not a `MultiAddress::Id` must be an error, never a
    /// confidently wrong signer: a wrong signer here is a false accusation
    /// against whichever account those 32 bytes happen to name.
    ///
    /// The three guards are exercised separately and their messages checked, so
    /// this cannot pass by having every case fail at the same place.
    #[test]
    fn a_malformed_signer_address_is_rejected_not_misread() -> TestResult {
        let address = hex::decode(ALICE_MULTI_ADDRESS_ID_HEX)?;

        // Guard 1 — the `Option`: an unsigned extrinsic has no address at all.
        // Its own message, because "nobody signed it" and "the address is shaped
        // wrong" are different facts about an unverifiable anchor.
        let unsigned = signer_decode_outcome(None);
        ensure(
            unsigned.contains("is unsigned"),
            &format!("an unsigned extrinsic must be reported as such, got: {unsigned}"),
        )?;

        // Guard 2 — the VARIANT byte, held at the correct 33-byte length so the
        // length check cannot be what fires. `MultiAddress::Index` (variant 1)
        // carries a compact account index, not an `AccountId32`; reading its tail
        // as one would attribute the anchor to 32 bytes that are not an account.
        // A decoder that checked only the length would accept this.
        let mut wrong_variant = address.clone();
        wrong_variant[0] = 0x01;
        let variant_err = signer_decode_outcome(Some(&wrong_variant));
        ensure(
            variant_err.contains("not a MultiAddress::Id")
                && variant_err.contains("(33 address bytes)"),
            &format!(
                "a non-Id variant at the right length must be rejected \
                 by the variant check, got: {variant_err}"
            ),
        )?;

        // Guard 3 — the LENGTH, held at the correct variant byte. Every prefix
        // truncation lands here rather than at the variant check (byte 0
        // survives every non-empty cut), so these are one failure point sharing
        // a message; the reported byte count is what distinguishes them, and
        // asserting it proves the length actually reached the check.
        let mut lengths: Vec<usize> = vec![0, 1, 16, address.len() - 1];
        // Over-long too: a 34-byte address must not decode by ignoring the tail.
        let mut too_long = address.clone();
        too_long.push(0xFF);
        lengths.push(too_long.len());

        for len in lengths {
            let bytes = if len > address.len() {
                &too_long[..len]
            } else {
                &address[..len]
            };
            let err = signer_decode_outcome(Some(bytes));
            ensure(
                err.contains("not a MultiAddress::Id")
                    && err.contains(&format!("({len} address bytes)")),
                &format!("a {len}-byte address must be rejected by the length check, got: {err}"),
            )?;
        }
        Ok(())
    }

    /// The remark payload decode path, exercised without a node.
    #[test]
    fn an_anchor_remark_decodes_to_the_root_it_committed() -> TestResult {
        let remark = hex::decode(ANCHOR_REMARK_PAYLOAD_HEX)?;

        let decoded = decode_remark_payload(&remark)?;

        ensure_eq(
            &decoded.to_hex().as_str(),
            &ANCHOR_REMARK_ROOT_HEX,
            "the decoded remark must yield the root the payload committed",
        )
    }

    /// A truncated or foreign remark must be an error, never a wrong root: a
    /// wrong root here reads as a `ChainDisagreement` against an honest author.
    ///
    /// The cuts are placed to land in three genuinely different regions of the
    /// payload, and each expects that region's own message — so a decoder that
    /// collapsed every failure into one check would fail here.
    #[test]
    fn a_malformed_anchor_remark_is_rejected_not_misread() -> TestResult {
        let remark = hex::decode(ANCHOR_REMARK_PAYLOAD_HEX)?;
        let tag_len = ANCHOR_TAG.len();

        // (cut, the region it lands in, the message that region must produce)
        let cases = [
            (0_usize, "inside the domain tag", "missing domain tag"),
            (tag_len - 1, "inside the domain tag", "missing domain tag"),
            (tag_len, "past the tag, inside the root", "truncated root"),
            (
                tag_len + ROOT_LEN - 1,
                "past the tag, inside the root",
                "truncated root",
            ),
            (
                tag_len + ROOT_LEN,
                "past the root, inside the JSON tail",
                "serialize error",
            ),
            (
                remark.len() - 1,
                "past the root, inside the JSON tail",
                "serialize error",
            ),
        ];
        for (cut, region, expected) in cases {
            let err = payload_decode_outcome(&remark[..cut]);
            ensure(
                err.contains(expected),
                &format!(
                    "a {cut}-byte prefix falls {region} and must fail with \
                     {expected:?}, got: {err}"
                ),
            )?;
        }

        // A well-formed remark from somewhere else entirely: chains carry plenty
        // of unrelated `System::remark` traffic, and none of it is an anchor.
        let foreign = payload_decode_outcome(b"gm");
        ensure(
            foreign.contains("missing domain tag"),
            &format!("a foreign remark must be rejected by the domain tag, got: {foreign}"),
        )
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
