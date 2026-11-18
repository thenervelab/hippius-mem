//! `hippius-mem verify-history`: check a note's anchor proofs offline.
//!
//! Input is the JSON the `history` tool returns (`hippius-mem call history
//! '{"id":"mem_..."}'`). For every op that carries an anchor proof the command
//! recomputes the Merkle path from the op's hash and compares it with the
//! root in the proof. It needs no config, no key and no network, so someone
//! with only the file can run it.
//!
//! What a valid proof establishes is narrower than it sounds, and the output
//! says so. The proof covers the op's hash and nothing else in the file: the
//! op id, kind and author printed beside it are labels the file could have
//! been edited to say, because the op's signed bytes are not in a `history`
//! result to recompute the hash from. And it shows the op is included under
//! that root. Whether the root itself is
//! trustworthy depends on where it was anchored. A root anchored on-chain can
//! be compared with the chain by anyone; a root recorded locally comes from
//! the same bucket as the proof, so the check shows the file is consistent
//! with itself and nothing more. The command prints the block and extrinsic
//! to look up and does not contact a chain.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};

use anyhow::Context as _;
use hippius_mem_core::{AnchorRef, Blake3Hash, MerkleProof, verify_proof};
use serde::Deserialize;

/// The fields of the `history` tool's result this command reads. Unknown
/// fields are ignored, so a newer server's output still verifies.
#[derive(Debug, Deserialize)]
struct History {
    note_id: String,
    entries: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    op_id: String,
    kind: String,
    author: String,
    op_hash: String,
    anchor: Option<Anchor>,
}

#[derive(Debug, Deserialize)]
struct Anchor {
    root: String,
    reference: AnchorRef,
    proof: MerkleProof,
}

/// How many ops fell into each outcome.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    valid: usize,
    pending: usize,
    invalid: usize,
}

/// Verify the history in the file named by the one argument (`-` for stdin).
///
/// # Errors
///
/// Returns an error if the input cannot be read or is not a `history` result,
/// if any proof does not verify, and if there was no proof to verify: a file
/// with every anchor removed must not pass as a verified history.
pub(crate) fn run(args: &[String]) -> anyhow::Result<()> {
    let [source] = args else {
        anyhow::bail!("usage: hippius-mem verify-history <file | ->");
    };
    let text = if source == "-" {
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text)?;
        text
    } else {
        std::fs::read_to_string(source).with_context(|| format!("reading {source} failed"))?
    };
    let history: History =
        serde_json::from_str(&text).context("the input is not a `history` result")?;

    let (report, tally) = verify(&history);
    std::io::stdout().write_all(report.as_bytes())?;
    verdict(&tally)
}

/// Whether `tally` is a verified history: no invalid proof, and at least one
/// valid one. A file with every anchor removed has nothing invalid in it and
/// must still not pass.
fn verdict(tally: &Tally) -> anyhow::Result<()> {
    anyhow::ensure!(
        tally.invalid == 0,
        "{} of {} anchor proofs do not verify",
        tally.invalid,
        tally.invalid + tally.valid
    );
    anyhow::ensure!(
        tally.valid > 0,
        "nothing was verified: no op in this history carries an anchor proof"
    );
    Ok(())
}

/// Check every entry and render one line each, then the totals.
fn verify(history: &History) -> (String, Tally) {
    let mut out = String::new();
    let mut tally = Tally::default();
    // Writing to a `String` cannot fail.
    let _ = writeln!(out, "{}: {} ops", history.note_id, history.entries.len());
    for entry in &history.entries {
        let verdict = match &entry.anchor {
            None => {
                tally.pending += 1;
                "pending: not anchored yet, nothing to verify".to_owned()
            }
            Some(anchor) if proof_holds(&entry.op_hash, anchor) => {
                tally.valid += 1;
                format!(
                    "included under root {}, {}",
                    anchor.root,
                    anchored_at(&anchor.reference)
                )
            }
            Some(anchor) => {
                tally.invalid += 1;
                format!("INVALID: the proof does not lead to root {}", anchor.root)
            }
        };
        let _ = writeln!(
            out,
            "  op hash {} (labelled {} {} by {}): {verdict}",
            entry.op_hash, entry.op_id, entry.kind, entry.author
        );
    }
    let _ = writeln!(
        out,
        "A proof covers the op hash only. The op id, kind and author are labels from the file."
    );
    let _ = writeln!(
        out,
        "{} proofs valid, {} ops pending, {} proofs invalid",
        tally.valid, tally.pending, tally.invalid
    );
    (out, tally)
}

/// Whether the proof leads from the op's hash to the root it names. A hash
/// that is not valid hex cannot verify.
fn proof_holds(op_hash: &str, anchor: &Anchor) -> bool {
    match (
        Blake3Hash::from_hex(op_hash),
        Blake3Hash::from_hex(&anchor.root),
    ) {
        (Ok(leaf), Ok(root)) => verify_proof(root, leaf, &anchor.proof),
        _ => false,
    }
}

/// Where the root was anchored, and what that is worth to a verifier.
fn anchored_at(reference: &AnchorRef) -> String {
    match reference {
        AnchorRef::Local { seq } => format!(
            "recorded locally (seq {seq}): consistent with this file, not checkable against a chain"
        ),
        AnchorRef::OnChain {
            block_hash,
            extrinsic_hash,
        } => format!(
            "anchored on-chain: compare the root with extrinsic {extrinsic_hash} in block {block_hash}"
        ),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use super::*;
    use hippius_mem_core::{inclusion_proof, merkle_root};

    fn leaf(byte: u8) -> Blake3Hash {
        Blake3Hash::new([byte; 32])
    }

    fn entry(op_hash: &Blake3Hash, anchor: Option<Anchor>) -> Entry {
        Entry {
            op_id: "01OP".to_owned(),
            kind: "Remember".to_owned(),
            author: "5Author".to_owned(),
            op_hash: op_hash.to_hex(),
            anchor,
        }
    }

    fn anchor_for(leaves: &[Blake3Hash], index: usize) -> anyhow::Result<Anchor> {
        Ok(Anchor {
            root: merkle_root(leaves).to_hex(),
            reference: AnchorRef::Local { seq: 1 },
            proof: inclusion_proof(leaves, index)?,
        })
    }

    /// A real proof verifies, an op hash that is not the proven leaf does not,
    /// and an op with no anchor is pending, not invalid. Catches a verifier
    /// that accepts any well-formed proof, which is the failure that matters:
    /// it would vouch for a forged history.
    #[test]
    fn a_proof_for_another_op_is_invalid() -> anyhow::Result<()> {
        let leaves = [leaf(1), leaf(2), leaf(3)];
        let history = History {
            note_id: "mem_X".to_owned(),
            entries: vec![
                entry(&leaves[1], Some(anchor_for(&leaves, 1)?)),
                entry(&leaf(9), Some(anchor_for(&leaves, 1)?)),
                entry(&leaves[2], None),
            ],
        };
        let (report, tally) = verify(&history);
        assert_eq!(
            tally,
            Tally {
                valid: 1,
                pending: 1,
                invalid: 1
            }
        );
        assert!(report.contains("INVALID"), "{report}");
        assert!(
            report.contains(&format!("op hash {}", leaves[1].to_hex())),
            "the hash the proof covers must be printed: {report}"
        );
        assert!(
            report.contains("not checkable against a chain"),
            "a local anchor must not read as a chain proof: {report}"
        );
        Ok(())
    }

    /// Pending ops alone are not a verified history, and one invalid proof
    /// fails it whatever else is valid.
    #[test]
    fn only_a_history_with_a_valid_proof_and_no_invalid_one_passes() {
        let tally = |valid, pending, invalid| Tally {
            valid,
            pending,
            invalid,
        };
        assert!(verdict(&tally(1, 3, 0)).is_ok());
        assert!(verdict(&tally(0, 2, 0)).is_err());
        assert!(verdict(&tally(0, 0, 0)).is_err());
        assert!(verdict(&tally(5, 0, 1)).is_err());
    }

    #[test]
    fn a_hash_that_is_not_hex_cannot_verify() -> anyhow::Result<()> {
        let leaves = [leaf(1)];
        let mut anchor = anchor_for(&leaves, 0)?;
        anchor.root = "zz".to_owned();
        assert!(!proof_holds(&leaves[0].to_hex(), &anchor));
        Ok(())
    }
}
