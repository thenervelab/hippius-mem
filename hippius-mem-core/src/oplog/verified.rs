//! [`VerifiedOps`] — a witness that a set of ops passed [`OpLogStore`]'s read
//! verification, so [`converge`](super::converge) can require it by type.
//!
//! The op-log lives in an untrusted bucket. [`OpLogStore::read_verified`] is the
//! one place that checks each op's signature, its author-SS58 binding, its team
//! prefix, and its per-author hash chain, dropping anything that fails.
//! [`converge`](super::converge) trusts its input completely — it folds
//! latest-wins state without re-checking any of that — so feeding it raw bucket
//! objects would converge forged or foreign ops as if genuine.
//!
//! `VerifiedOps` moves that precondition from a doc comment into the type: it is
//! minted only at the tail of `read_verified` and its transforms preserve the
//! property, so a caller cannot hand `converge` an unverified `Vec<Op>` by
//! mistake.
//!
//! [`OpLogStore`]: super::OpLogStore
//! [`OpLogStore::read_verified`]: super::OpLogStore

use std::ops::Deref;

use super::op::Op;

/// A set of ops that passed [`OpLogStore`](super::OpLogStore)'s read
/// verification — signature, author-SS58 binding, team-prefix, and per-author
/// hash-chain checks — held so [`converge`](super::converge) can demand it by
/// type.
///
/// This is a *witness*, not a validate-at-construction value: there is no cheap
/// runtime check that re-proves verification, so the invariant is upheld by
/// restricting construction rather than by re-validating. The inner `Vec<Op>` is
/// private, and the only routes that produce a `VerifiedOps` are
/// [`from_verified`](Self::from_verified) — the trust boundary, called once
/// inside `read_verified` — and the verified-preserving transforms
/// [`filter`](Self::filter) / [`partition`](Self::partition) /
/// [`concat`](Self::concat), because a subset or union of a verified set is
/// still verified. Read access is `Deref` to `[Op]`.
///
/// Deliberately absent (each would mint the witness without the checks — see
/// axiom `rust_quality_182_construction_bypass_audit`): `DerefMut`, `Default`,
/// `Deserialize`, and any `From<Vec<Op>>`. The audit surface is exactly the four
/// constructors in this module.
#[derive(Debug)]
pub struct VerifiedOps(Vec<Op>);

impl VerifiedOps {
    /// Wrap `ops` as verified. THE trust boundary.
    ///
    /// The caller asserts every op in `ops` was produced by
    /// [`OpLogStore::read_verified`](super::OpLogStore)'s checks. Scoped
    /// `pub(in crate::oplog)`, not `pub(crate)`, so ONLY this module tree can mint
    /// a witness from a raw vector: `read_verified` (its one production call site)
    /// and this module's tests. Every other consumer — `store::MemoryStore` and
    /// beyond — can obtain a `VerifiedOps` only from `read_all` and narrow it with
    /// the verified-preserving transforms, never fabricate one. Adding a call site
    /// means re-establishing the verification guarantee there.
    pub(in crate::oplog) fn from_verified(ops: Vec<Op>) -> Self {
        Self(ops)
    }

    /// Keep only the ops matching `keep`, staying verified.
    ///
    /// A subset of a verified set is verified, so the result is a `VerifiedOps` —
    /// this is what lets `history` narrow to one note, and membership filtering
    /// narrow to current members, and still feed `converge`. Consumes `self`, so
    /// no op is cloned.
    #[must_use]
    pub(crate) fn filter(self, keep: impl Fn(&Op) -> bool) -> VerifiedOps {
        VerifiedOps(self.0.into_iter().filter(keep).collect())
    }

    /// Split into `(matching, rest)` by `left`; both halves stay verified.
    ///
    /// Used to separate the snapshot base (`lamport <= L`) from the incremental
    /// tail — each half is a subset of a verified set. Consumes `self`.
    #[must_use]
    pub(crate) fn partition(self, left: impl Fn(&Op) -> bool) -> (VerifiedOps, VerifiedOps) {
        let (matching, rest): (Vec<Op>, Vec<Op>) = self.0.into_iter().partition(left);
        (VerifiedOps(matching), VerifiedOps(rest))
    }

    /// Concatenate two verified sets into one still-verified set.
    ///
    /// The union of two verified sets is verified. Used by the incremental-sync
    /// safety valve to reassemble base + tail before a full replay.
    #[must_use]
    pub(crate) fn concat(mut self, other: VerifiedOps) -> VerifiedOps {
        self.0.extend(other.0);
        self
    }
}

impl Deref for VerifiedOps {
    type Target = [Op];

    fn deref(&self) -> &[Op] {
        &self.0
    }
}
