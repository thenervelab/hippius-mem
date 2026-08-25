//! Lowercase hex codec for byte strings.
//!
//! First-party replacement for the `hex` crate. `encode` and `decode` are the
//! whole surface this workspace ever used, so carrying a dependency for them
//! bought nothing; keeping the codec here also means the lean binary stops
//! linking a hex crate of its own the day the S3 SDK no longer pulls one in.
//!
//! Decoding accepts either case, as the `hex` crate did, so an operator-typed
//! uppercase seed still loads; encoding is always lowercase. The op-log's
//! stricter canonical-lowercase decoder ([`crate::oplog::HexError`]) is a
//! different contract and stays separate.
//!
//! [`DecodeError`] deliberately carries neither the offending character nor its
//! position: every caller in this workspace decodes SECRET material (author
//! seeds, team keys, recovery seeds), and the `hex` crate's error text named the
//! bad char and index, which is why each call site already had to discard it.

use core::fmt;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Render `bytes` as a `2 * len` character lowercase hex string.
#[must_use]
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Why a string failed to decode as hex. No payload on purpose (see the module
/// docs): the input is usually a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input had an odd number of characters.
    OddLength,
    /// A character outside `0-9`, `a-f`, `A-F`.
    InvalidChar,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => f.write_str("hex string has an odd length"),
            Self::InvalidChar => f.write_str("hex string contains a non-hex character"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode a hex string (either case) into bytes.
///
/// # Errors
///
/// [`DecodeError::OddLength`] for an odd character count, [`DecodeError::InvalidChar`]
/// for any character outside `0-9a-fA-F`.
pub fn decode(s: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    let raw = s.as_ref();
    if raw.len() % 2 != 0 {
        return Err(DecodeError::OddLength);
    }

    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

/// Decode one hex digit (either case) into its `0..=15` value.
fn nibble(c: u8) -> Result<u8, DecodeError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(DecodeError::InvalidChar),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{DecodeError, decode, encode};

    #[test]
    fn encodes_lowercase() {
        assert_eq!(encode([0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn decodes_either_case() {
        assert_eq!(decode("000ff0ff"), Ok(vec![0x00, 0x0f, 0xf0, 0xff]));
        assert_eq!(decode("000FF0FF"), Ok(vec![0x00, 0x0f, 0xf0, 0xff]));
        assert_eq!(decode("aBcD"), Ok(vec![0xab, 0xcd]));
        assert_eq!(decode(""), Ok(vec![]));
    }

    #[test]
    fn rejects_odd_length_and_non_hex() {
        assert_eq!(decode("abc"), Err(DecodeError::OddLength));
        assert_eq!(decode("zz"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("0g"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("0 "), Err(DecodeError::InvalidChar));
    }

    #[test]
    fn errors_name_no_input_bytes() {
        // Callers decode secrets; the message must stay generic.
        for err in [DecodeError::OddLength, DecodeError::InvalidChar] {
            let text = err.to_string();
            assert!(!text.contains("at"), "no position in {text:?}");
            assert!(!text.contains('\''), "no quoted char in {text:?}");
        }
    }

    proptest! {
        #[test]
        fn round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let text = encode(&bytes);
            prop_assert_eq!(text.len(), bytes.len() * 2);
            prop_assert_eq!(decode(&text), Ok(bytes.clone()));
            prop_assert_eq!(decode(text.to_uppercase()), Ok(bytes));
        }
    }
}
