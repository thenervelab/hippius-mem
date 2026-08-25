//! BIP-39 mnemonic parsing (English), replacing the `bip39` crate.
//!
//! The only thing this crate ever asked of `bip39` was `Mnemonic::parse` then
//! `to_entropy_array`: turn a phrase back into the entropy bytes Substrate's
//! seed derivation consumes (see the parent module docs). That is a wordlist
//! lookup, an 11-bit unpack, and a SHA-256 checksum compare — for which the
//! crate brought six crates (`bitcoin_hashes`, `hex-conservative`,
//! `unicode-normalization`, `tinyvec`, `tinyvec_macros`, itself). The wordlist
//! in [`english`] is the canonical BIP-39 list, byte-identical to the one the
//! crate embedded.
//!
//! Semantics preserved from `bip39::Mnemonic::parse` for English: words are
//! split on Unicode whitespace (any amount, any kind), matched exactly against
//! the lowercase list (so an uppercase word is unknown), 12/15/18/21/24 words
//! are accepted, and the checksum must verify. The one divergence is NFKD
//! normalisation: the crate ran it before lookup, which only matters for
//! non-ASCII compatibility forms of ASCII letters (fullwidth `ａｂｏｕｔ`);
//! those are now rejected as unknown words rather than silently accepted.
//!
//! Zeroisation is stricter than the crate's: the word indices and the unpacked
//! bit array are wiped on drop alongside the entropy, whereas `bip39::Mnemonic`
//! held its indices in a plain array.

mod english;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use english::WORDS;

/// Entropy of a 24-word phrase, in bytes: the most any phrase carries.
pub(super) const MAX_ENTROPY_BYTES: usize = 32;
const MIN_WORDS: usize = 12;
const MAX_WORDS: usize = 24;
/// Each word indexes a 2048-entry list.
const BITS_PER_WORD: usize = 11;

/// Why a phrase is not a valid English BIP-39 mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MnemonicError {
    /// Not 12, 15, 18, 21, or 24 words.
    BadWordCount(usize),
    /// The word at this 0-based position is not in the English list.
    UnknownWord(usize),
    /// The trailing checksum bits do not match SHA-256 of the entropy.
    InvalidChecksum,
}

/// The entropy `phrase` encodes: `bytes[..len]` is the payload, the rest is
/// zero. Both buffers this touches are wiped on drop.
///
/// # Errors
///
/// See [`MnemonicError`]; checked in the order word count, unknown word (first
/// offender), checksum — the same order `bip39` reported them.
pub(super) fn to_entropy(
    phrase: &str,
) -> Result<(Zeroizing<[u8; MAX_ENTROPY_BYTES]>, usize), MnemonicError> {
    let word_count = phrase.split_whitespace().count();
    if !(MIN_WORDS..=MAX_WORDS).contains(&word_count) || !word_count.is_multiple_of(3) {
        return Err(MnemonicError::BadWordCount(word_count));
    }

    let mut indices = Zeroizing::new([0u16; MAX_WORDS]);
    for (position, word) in phrase.split_whitespace().enumerate() {
        indices[position] = find_word(word).ok_or(MnemonicError::UnknownWord(position))?;
    }

    // Unpack the 11-bit indices into one bit per byte: `ENT` entropy bits
    // followed by `ENT / 32` checksum bits.
    let mut bits = Zeroizing::new([0u8; MAX_WORDS * BITS_PER_WORD]);
    for (position, &index) in indices[..word_count].iter().enumerate() {
        for offset in 0..BITS_PER_WORD {
            let bit = (index >> (BITS_PER_WORD - 1 - offset)) & 1 == 1;
            bits[position * BITS_PER_WORD + offset] = u8::from(bit);
        }
    }

    let entropy_len = word_count / 3 * 4;
    let checksum_bits = word_count / 3;

    let mut entropy = Zeroizing::new([0u8; MAX_ENTROPY_BYTES]);
    for (i, byte) in entropy[..entropy_len].iter_mut().enumerate() {
        for bit in &bits[i * 8..(i + 1) * 8] {
            *byte = (*byte << 1) | bit;
        }
    }

    // `checksum_bits <= 8`, so the checksum always lives in the digest's first
    // byte, most significant bit first.
    let digest = Sha256::digest(&entropy[..entropy_len]);
    for i in 0..checksum_bits {
        let expected = (digest[0] >> (7 - i)) & 1;
        if bits[entropy_len * 8 + i] != expected {
            return Err(MnemonicError::InvalidChecksum);
        }
    }

    Ok((entropy, entropy_len))
}

/// The list index of `word`, matched exactly (the list is sorted, lowercase
/// ASCII, so this is a binary search).
fn find_word(word: &str) -> Option<u16> {
    WORDS
        .binary_search(&word)
        .ok()
        .and_then(|index| u16::try_from(index).ok())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::english::WORDS;
    use super::{MAX_ENTROPY_BYTES, MnemonicError, to_entropy};

    /// The inverse of `to_entropy`, test-only: it exists to prove the parser
    /// against the spec vectors in both directions and to drive the round-trip
    /// property below. Production never mints phrases.
    fn to_phrase(entropy: &[u8]) -> String {
        let digest = Sha256::digest(entropy);
        let checksum_bits = entropy.len() / 4;
        let mut bits: Vec<u8> = entropy
            .iter()
            .flat_map(|byte| (0..8).map(move |j| (byte >> (7 - j)) & 1))
            .collect();
        bits.extend((0..checksum_bits).map(|i| (digest[0] >> (7 - i)) & 1));
        bits.chunks(11)
            .map(|chunk| {
                let index = chunk
                    .iter()
                    .fold(0usize, |acc, &bit| (acc << 1) | usize::from(bit));
                WORDS[index]
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn entropy_of(phrase: &str) -> Result<Vec<u8>, MnemonicError> {
        to_entropy(phrase).map(|(bytes, len)| bytes[..len].to_vec())
    }

    /// BIP-39 English test vectors (trezor/python-mnemonic `vectors.json`).
    const VECTORS: &[(&str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        ),
        (
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        ),
    ];

    #[test]
    fn spec_vectors_parse_in_both_directions() {
        for &(entropy_hex, phrase) in VECTORS {
            let entropy = crate::hex::decode(entropy_hex).unwrap_or_default();
            assert_eq!(entropy_of(phrase), Ok(entropy.clone()), "parse {phrase:?}");
            assert_eq!(to_phrase(&entropy), phrase, "encode {entropy_hex}");
        }
    }

    /// Five hundred phrases minted by `bip39 2.2.2` itself, a hundred per
    /// entropy size (see `tests/fixtures/README.md`), parsed and re-encoded.
    #[test]
    fn matches_the_bip39_crate_on_five_hundred_generated_phrases() {
        const GOLDEN: &str = include_str!("../../tests/fixtures/bip39_golden.tsv");
        let mut per_size = BTreeMap::new();
        for line in GOLDEN
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let (hex, phrase) = line.split_once('\t').unwrap_or(("", ""));
            let entropy = crate::hex::decode(hex).unwrap_or_default();
            assert!(!entropy.is_empty(), "malformed fixture line {line:?}");
            assert_eq!(entropy_of(phrase), Ok(entropy.clone()), "parse {phrase:?}");
            assert_eq!(to_phrase(&entropy), phrase, "encode {hex}");
            *per_size
                .entry(phrase.split_whitespace().count())
                .or_insert(0) += 1;
        }
        assert_eq!(
            per_size,
            BTreeMap::from([(12, 100), (15, 100), (18, 100), (21, 100), (24, 100)]),
            "every phrase size, a hundred each; the fixture must be intact"
        );
    }

    #[test]
    fn wordlist_is_the_sorted_canonical_list() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(WORDS.first(), Some(&"abandon"));
        assert_eq!(WORDS.last(), Some(&"zoo"));
        assert!(
            WORDS.windows(2).all(|pair| pair[0] < pair[1]),
            "sorted and unique"
        );
        assert!(
            WORDS
                .iter()
                .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase())),
            "lowercase ASCII only"
        );
    }

    #[test]
    fn tolerates_any_whitespace_between_words() {
        let phrase = "  abandon\tabandon abandon\n abandon abandon abandon abandon abandon abandon abandon abandon   about \n";
        assert_eq!(entropy_of(phrase), Ok(vec![0; 16]));
    }

    #[test]
    fn rejects_bad_word_counts() {
        let eleven = ["abandon"; 11].join(" ");
        assert_eq!(entropy_of(&eleven), Err(MnemonicError::BadWordCount(11)));
        let thirteen = ["abandon"; 13].join(" ");
        assert_eq!(entropy_of(&thirteen), Err(MnemonicError::BadWordCount(13)));
        let twenty_five = ["abandon"; 25].join(" ");
        assert_eq!(
            entropy_of(&twenty_five),
            Err(MnemonicError::BadWordCount(25))
        );
        assert_eq!(entropy_of(""), Err(MnemonicError::BadWordCount(0)));
    }

    #[test]
    fn rejects_unknown_and_uppercase_words_naming_the_first_offender() {
        let phrase = "abandon abandon abandon Abandon abandon abandon abandon abandon abandon abandon xyzzy about";
        assert_eq!(entropy_of(phrase), Err(MnemonicError::UnknownWord(3)));
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyzzy about";
        assert_eq!(entropy_of(phrase), Err(MnemonicError::UnknownWord(10)));
    }

    #[test]
    fn rejects_a_checksum_mismatch() {
        // Twelve `abandon`s decode to all-zero entropy whose checksum word is
        // `about`, not `abandon`.
        let phrase = ["abandon"; 12].join(" ");
        assert_eq!(entropy_of(&phrase), Err(MnemonicError::InvalidChecksum));
        // One word swapped inside an otherwise valid phrase.
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank zoo";
        assert_eq!(entropy_of(phrase), Err(MnemonicError::InvalidChecksum));
    }

    #[test]
    fn unused_entropy_tail_is_zero() {
        let (bytes, len) = to_entropy(VECTORS[0].1).unwrap_or((Zeroizing::new([1; 32]), 0));
        assert_eq!(len, 16);
        assert!(bytes[len..MAX_ENTROPY_BYTES].iter().all(|&b| b == 0));
    }

    proptest! {
        #[test]
        fn every_entropy_size_round_trips(
            bytes in proptest::collection::vec(any::<u8>(), 32),
            words in prop_oneof![Just(12usize), Just(15), Just(18), Just(21), Just(24)],
        ) {
            let entropy = &bytes[..words / 3 * 4];
            let phrase = to_phrase(entropy);
            prop_assert_eq!(phrase.split_whitespace().count(), words);
            prop_assert_eq!(entropy_of(&phrase), Ok(entropy.to_vec()));
        }
    }
}
