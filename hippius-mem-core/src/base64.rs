//! Standard base64 (RFC 4648 §4, padded) for binary payloads inside JSON.
//!
//! First-party for the same reason as [`crate::hex`]: `encode` and `decode` are
//! the whole surface needed, and the one caller is the index checkpoint, whose
//! sealed records and embedding vectors used to be written as JSON arrays of
//! numbers (about 3.6 characters per byte). Base64 is 4 characters per 3 bytes.
//!
//! Decoding is strict — canonical padded input only: no whitespace, no URL-safe
//! alphabet, no missing or extra padding, and no non-zero bits in the final
//! padded group. Only this module's own output is ever decoded, so accepting
//! anything looser would only widen what a tampered checkpoint could smuggle
//! past the envelope's own authentication.

use core::fmt;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Render `bytes` as padded standard base64.
#[must_use]
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let group = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);

        out.push(sextet(group >> 18));
        out.push(sextet(group >> 12));
        out.push(if chunk.len() > 1 {
            sextet(group >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { sextet(group) } else { '=' });
    }
    out
}

fn sextet(bits: u32) -> char {
    // Masked to 0..64, so the index is always in bounds.
    char::from(ALPHABET[(bits & 0x3f) as usize])
}

/// Why a string failed to decode. No payload: the input is sealed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The length is not a multiple of four.
    Length,
    /// A character outside the standard alphabet, or `=` anywhere but the end.
    InvalidChar,
    /// Padding that is not canonical: more than two `=`, or non-zero bits
    /// in the final group that padding says are unused.
    NonCanonical,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length => f.write_str("base64 length is not a multiple of four"),
            Self::InvalidChar => f.write_str("base64 contains a character outside the alphabet"),
            Self::NonCanonical => f.write_str("base64 padding is not canonical"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode padded standard base64.
///
/// # Errors
///
/// A [`DecodeError`] for any input [`encode`] could not have produced.
pub fn decode(s: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    let raw = s.as_ref();
    if raw.len() % 4 != 0 {
        return Err(DecodeError::Length);
    }

    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    let last = raw.len() / 4;
    for (index, quad) in raw.chunks_exact(4).enumerate() {
        let padding = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 || (padding > 0 && index + 1 != last) {
            return Err(DecodeError::NonCanonical);
        }
        let mut group = 0_u32;
        for &c in &quad[..4 - padding] {
            group = (group << 6) | u32::from(value(c)?);
        }
        group <<= 6 * padding;

        let bytes = group.to_be_bytes();
        let kept = 3 - padding;
        // The bits padding marks unused must be zero, or two strings would
        // decode to the same bytes.
        if bytes[1 + kept..].iter().any(|&byte| byte != 0) {
            return Err(DecodeError::NonCanonical);
        }
        out.extend_from_slice(&bytes[1..=kept]);
    }
    Ok(out)
}

/// The 6-bit value of one alphabet character.
fn value(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(DecodeError::InvalidChar),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{DecodeError, decode, encode};

    /// RFC 4648 §10 test vectors.
    const VECTORS: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn matches_the_rfc_vectors() {
        for (plain, encoded) in VECTORS {
            assert_eq!(encode(plain), encoded);
            assert_eq!(decode(encoded), Ok(plain.as_bytes().to_vec()));
        }
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(decode("Zg="), Err(DecodeError::Length));
        assert_eq!(decode("Zg=\n"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("Zm-v"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("Z==="), Err(DecodeError::NonCanonical));
        assert_eq!(decode("Zg==Zm9v"), Err(DecodeError::NonCanonical));
        assert_eq!(decode("Zm=v"), Err(DecodeError::InvalidChar));
    }

    #[test]
    fn rejects_non_zero_padding_bits() {
        // "Zh==" and "Zg==" would otherwise both decode to "f".
        assert_eq!(decode("Zh=="), Err(DecodeError::NonCanonical));
        assert_eq!(decode("Zm9=",), Err(DecodeError::NonCanonical));
    }

    proptest! {
        #[test]
        fn round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..96)) {
            let text = encode(&bytes);
            prop_assert_eq!(text.len(), bytes.len().div_ceil(3) * 4);
            prop_assert_eq!(decode(&text), Ok(bytes));
        }
    }
}
