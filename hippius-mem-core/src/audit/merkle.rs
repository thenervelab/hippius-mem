//! A binary Merkle tree over [`Blake3Hash`] leaves with inclusion proofs.
//!
//! # Domain separation
//!
//! Leaves and internal nodes are hashed with a distinct one-byte prefix:
//! a leaf is `H(0x00 ++ leaf_bytes)` and an internal node is
//! `H(0x01 ++ left ++ right)`. The prefix is what defends against
//! second-preimage / leaf-vs-node confusion: an internal node's preimage is 64
//! bytes (`left ++ right`) while a leaf preimage is 32 bytes, so without the
//! prefix an attacker could take an internal node's two children and present
//! them as if they were a leaf's preimage (or vice versa), forging a proof for
//! a value that was never a leaf. The prefix puts leaf hashes and node hashes
//! in disjoint input spaces, so no node hash can ever collide with a leaf hash
//! by construction.
//!
//! # Odd levels
//!
//! When a tree level has an odd number of nodes, the last node is duplicated
//! and paired with itself (`H(0x01 ++ last ++ last)`) — the common
//! Bitcoin-style rule. This makes every level above the leaves a full binary
//! layer without padding with a distinguished constant.
//!
//! The duplicate-node rule has a known weakness (the CVE-2012-2459 class):
//! because a lone node is hashed against a copy of itself, two *different* leaf
//! multisets can map to the same root, so the root alone does not uniquely
//! commit to the leaf count. That is acceptable here: our leaves are unique op
//! hashes and the leaf count is fixed per anchored batch, so the ambiguous
//! shapes that the attack relies on cannot arise — a verifier always checks a
//! proof against the exact batch it anchored.
//!
//! # Prove / verify share one hashing definition
//!
//! [`merkle_root`], [`inclusion_proof`], and [`verify_proof`] all route every
//! hash through the private [`hash_leaf`] and [`hash_node`] helpers. This is
//! deliberate: if the prover and the verifier ever disagreed on the leaf
//! prefix, the node prefix, or the child order, every proof would silently
//! fail (or, worse, a wrong proof could verify). One definition, used in both
//! directions, removes that drift by construction.

use crate::domain::Blake3Hash;
use crate::error::MemError;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for a leaf hash input.
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for an internal-node hash input.
const NODE_PREFIX: u8 = 0x01;

/// Which side a proof step's sibling sits on, relative to the running node.
///
/// At each level the verifier must combine the running node and its sibling in
/// the *same order* the tree builder used, or the recomputed root is garbage.
/// `Side` records that order: it names where the sibling is, so the verifier
/// knows whether to hash `(sibling, node)` or `(node, sibling)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    /// The sibling is the left child; hash as `H(node_prefix ++ sibling ++ node)`.
    Left,
    /// The sibling is the right child; hash as `H(node_prefix ++ node ++ sibling)`.
    Right,
}

/// A Merkle inclusion proof: the sibling path from a leaf up to the root.
///
/// `siblings` is ordered bottom-up — index 0 is the sibling at the leaf level,
/// the last entry is the sibling just below the root. A single-leaf tree has an
/// empty `siblings` vector (the leaf hash *is* the root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the proven leaf in the original leaf slice.
    pub leaf_index: usize,
    /// Sibling hash and its side, one entry per tree level, bottom-up.
    pub siblings: Vec<(Blake3Hash, Side)>,
}

/// Hash a leaf with the leaf domain-separation prefix: `H(0x00 ++ leaf_bytes)`.
fn hash_leaf(leaf: &Blake3Hash) -> Blake3Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(leaf.as_bytes());
    Blake3Hash::new(hasher.finalize().into())
}

/// Hash two children with the node prefix: `H(0x01 ++ left ++ right)`.
fn hash_node(left: &Blake3Hash, right: &Blake3Hash) -> Blake3Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    Blake3Hash::new(hasher.finalize().into())
}

/// Build every tree level bottom-up: `levels[0]` is the leaf-hash layer and the
/// final level is the single-element root layer.
///
/// Each layer halves the one below it, duplicating a lone trailing node so the
/// parent layer is always full (the odd-level rule from the module docs). The
/// returned outer vector is never empty — it is seeded with the leaf layer —
/// so callers may index its last element. An empty leaf slice yields
/// `vec![vec![]]`, which `merkle_root` handles via its empty-slice convention.
fn build_levels(leaves: &[Blake3Hash]) -> Vec<Vec<Blake3Hash>> {
    let leaf_layer: Vec<Blake3Hash> = leaves.iter().map(hash_leaf).collect();
    let mut levels = vec![leaf_layer];
    while levels[levels.len() - 1].len() > 1 {
        let current = &levels[levels.len() - 1];
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = &pair[0];
            // A trailing lone node (odd layer) is paired with itself.
            let right = pair.get(1).unwrap_or(left);
            next.push(hash_node(left, right));
        }
        levels.push(next);
    }
    levels
}

/// The Merkle root over `leaves`, domain-separated per the module docs.
///
/// The empty slice convention is `Blake3Hash::zero()` (BLAKE3 never produces
/// the all-zero digest for real input, so it is an unambiguous "no leaves"
/// sentinel). A single leaf yields its domain-separated leaf hash.
#[must_use]
pub fn merkle_root(leaves: &[Blake3Hash]) -> Blake3Hash {
    if leaves.is_empty() {
        return Blake3Hash::zero();
    }
    let levels = build_levels(leaves);
    // Non-empty input always reduces to a one-element top layer.
    let root_layer = &levels[levels.len() - 1];
    root_layer[0]
}

/// Build the inclusion proof for the leaf at `leaf_index`.
///
/// # Errors
///
/// Returns [`MemError::Malformed`] when `leaf_index` is out of range for
/// `leaves` (including any index into an empty slice).
pub fn inclusion_proof(leaves: &[Blake3Hash], leaf_index: usize) -> Result<MerkleProof, MemError> {
    if leaf_index >= leaves.len() {
        return Err(MemError::Malformed(format!(
            "merkle inclusion_proof: leaf_index {leaf_index} out of range for {} leaves",
            leaves.len()
        )));
    }

    let levels = build_levels(leaves);
    let mut siblings = Vec::with_capacity(levels.len().saturating_sub(1));
    let mut index = leaf_index;
    // Walk every level except the root layer, collecting the sibling and the
    // side it sits on. `index` is the position within the *current* layer; the
    // parent position is `index / 2`.
    for layer in &levels[..levels.len() - 1] {
        if index % 2 == 1 {
            // Right child: its sibling is the node to the left.
            siblings.push((layer[index - 1], Side::Left));
        } else {
            // Left child: sibling to the right, or itself when this node is the
            // odd trailing one that the builder duplicated.
            let sibling = if index + 1 < layer.len() {
                layer[index + 1]
            } else {
                layer[index]
            };
            siblings.push((sibling, Side::Right));
        }
        index /= 2;
    }

    Ok(MerkleProof {
        leaf_index,
        siblings,
    })
}

/// Recompute the root from `leaf` and `proof` and compare it to `root`.
///
/// Uses the same domain separation and child order as the builder, so it needs
/// only the leaf and its sibling path — never the original leaf slice.
#[must_use]
pub fn verify_proof(root: Blake3Hash, leaf: Blake3Hash, proof: &MerkleProof) -> bool {
    let mut node = hash_leaf(&leaf);
    // `proof.leaf_index` is not consulted: the leaf's position is determined
    // entirely by the `Side` of each step (which child the running node is), so
    // the index is descriptive metadata, not part of what is verified.
    for (sibling, side) in &proof.siblings {
        node = match side {
            Side::Left => hash_node(sibling, &node),
            Side::Right => hash_node(&node, sibling),
        };
    }
    node == root
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on known-valid fixtures where construction cannot fail"
    )]

    use super::*;
    use proptest::prelude::*;

    /// A distinct, deterministic leaf for fixture trees.
    fn leaf(n: u8) -> Blake3Hash {
        Blake3Hash::new([n; 32])
    }

    #[test]
    fn single_leaf_root_is_domain_separated_leaf_hash() {
        let a = leaf(1);
        assert_eq!(merkle_root(&[a]), hash_leaf(&a));
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(merkle_root(&[]), Blake3Hash::zero());
    }

    #[test]
    fn two_leaf_root_matches_manual() {
        let a = leaf(1);
        let b = leaf(2);
        let expected = hash_node(&hash_leaf(&a), &hash_leaf(&b));
        assert_eq!(merkle_root(&[a, b]), expected);
    }

    #[test]
    fn out_of_range_index_errors() {
        let leaves = [leaf(1), leaf(2)];
        assert!(inclusion_proof(&leaves, 0).is_ok());
        assert!(inclusion_proof(&leaves, 1).is_ok());
        assert!(inclusion_proof(&leaves, 2).is_err());
        assert!(inclusion_proof(&[], 0).is_err());
    }

    #[test]
    fn odd_leaf_count_proof_verifies() {
        for count in [3usize, 5, 7] {
            let leaves: Vec<Blake3Hash> =
                (0..count).map(|i| leaf(u8::try_from(i).unwrap())).collect();
            let root = merkle_root(&leaves);
            for index in 0..count {
                let proof = inclusion_proof(&leaves, index).unwrap();
                assert!(
                    verify_proof(root, leaves[index], &proof),
                    "proof for leaf {index} of {count} failed to verify"
                );
            }
        }
    }

    prop_compose! {
        fn arb_leaf()(bytes in proptest::array::uniform32(any::<u8>())) -> Blake3Hash {
            Blake3Hash::new(bytes)
        }
    }

    prop_compose! {
        fn arb_leaves_and_index()
            (leaves in proptest::collection::vec(arb_leaf(), 1..=64))
            (index in 0..leaves.len(), leaves in Just(leaves))
            -> (Vec<Blake3Hash>, usize) {
            (leaves, index)
        }
    }

    proptest! {
        #[test]
        fn every_leaf_proof_verifies((leaves, index) in arb_leaves_and_index()) {
            let root = merkle_root(&leaves);
            let proof = inclusion_proof(&leaves, index).unwrap();
            prop_assert!(verify_proof(root, leaves[index], &proof));
        }
    }

    proptest! {
        #[test]
        fn wrong_leaf_or_root_fails((leaves, index) in arb_leaves_and_index()) {
            let root = merkle_root(&leaves);
            let proof = inclusion_proof(&leaves, index).unwrap();

            // Flip one byte of the leaf: a different leaf must not verify under
            // the honest root.
            let mut wrong_bytes = *leaves[index].as_bytes();
            wrong_bytes[0] ^= 0xFF;
            let wrong_leaf = Blake3Hash::new(wrong_bytes);
            prop_assert!(!verify_proof(root, wrong_leaf, &proof));

            // Flip one byte of the root: the honest leaf must not verify under a
            // different root.
            let mut wrong_root_bytes = *root.as_bytes();
            wrong_root_bytes[0] ^= 0xFF;
            let wrong_root = Blake3Hash::new(wrong_root_bytes);
            prop_assert!(!verify_proof(wrong_root, leaves[index], &proof));
        }
    }

    prop_compose! {
        fn arb_multi_leaves_and_index()
            (leaves in proptest::collection::vec(arb_leaf(), 2..=64))
            (index in 0..leaves.len(), leaves in Just(leaves))
            -> (Vec<Blake3Hash>, usize) {
            (leaves, index)
        }
    }

    proptest! {
        /// A proof whose sibling PATH is tampered — a mutated sibling hash, a
        /// truncated path, or an extended path — must NOT verify under the honest
        /// root. `verify_proof` ignores `leaf_index`, so the sibling path is the
        /// whole of what it checks; these are its adversarial cases, the gap the
        /// wrong-leaf / wrong-root proptests above did not cover.
        #[test]
        fn tampered_proof_path_fails((leaves, index) in arb_multi_leaves_and_index()) {
            let root = merkle_root(&leaves);
            let leaf = leaves[index];
            let proof = inclusion_proof(&leaves, index).unwrap();
            prop_assert!(!proof.siblings.is_empty(), "a multi-leaf tree has a non-empty path");

            // (a) Mutate one byte of a sibling hash.
            let mut tampered = proof.clone();
            let mut bytes = *tampered.siblings[0].0.as_bytes();
            bytes[0] ^= 0xFF;
            tampered.siblings[0].0 = Blake3Hash::new(bytes);
            prop_assert!(!verify_proof(root, leaf, &tampered), "a mutated sibling must not verify");

            // (b) Truncate the path by one step: the recomputation stops short of the
            // root, so the running node cannot equal it.
            let mut truncated = proof.clone();
            truncated.siblings.pop();
            prop_assert!(!verify_proof(root, leaf, &truncated), "a truncated path must not verify");

            // (c) Extend the path by one bogus step past the root level.
            let mut extended = proof.clone();
            extended.siblings.push((leaf, Side::Right));
            prop_assert!(!verify_proof(root, leaf, &extended), "an extended path must not verify");
        }
    }

    #[test]
    fn flipped_sibling_side_fails() {
        // On a two-leaf tree the sibling differs from the running node, so flipping
        // its `Side` swaps the child order into `hash_node(sibling, node)` — a
        // different, non-commutative hash — and the proof must not verify.
        let leaves = [leaf(1), leaf(2)];
        let root = merkle_root(&leaves);
        let mut proof = inclusion_proof(&leaves, 0).unwrap();
        assert!(
            verify_proof(root, leaves[0], &proof),
            "sanity: the honest proof verifies"
        );
        proof.siblings[0].1 = match proof.siblings[0].1 {
            Side::Left => Side::Right,
            Side::Right => Side::Left,
        };
        assert!(
            !verify_proof(root, leaves[0], &proof),
            "flipping the sibling side must break the proof"
        );
    }
}
