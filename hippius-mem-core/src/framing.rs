//! Canonical length-prefix framing for signed byte strings.
//!
//! Every signature in the crate — over an [`crate::Op`], a
//! [`crate::TeamManifest`], a [`crate::MemberKey`], or a [`crate::HeadPointer`] —
//! is computed over bytes assembled field-by-field with [`push_framed`]. Keeping
//! ONE definition is a security property, not just tidiness: the framing contract
//! is the entire forgery-resistance argument, so a change to how fields are
//! delimited must land in exactly one place. Four byte-identical copies could
//! silently drift, and each would still verify within its own type — so no
//! single-type test would catch signatures minted by different types disagreeing.
//!
//! Keep that list in step when a signed type is added: a stale enumeration in the
//! module whose whole purpose is being the single definition is the first sign the
//! property has stopped being maintained.

/// Append a variable-length field to `buf`, length-prefixed with a fixed 8-byte
/// little-endian `u64`.
///
/// The fixed width is the load-bearing invariant: `usize::to_le_bytes` is 8
/// bytes on 64-bit hosts and 4 on 32-bit, so a `usize` prefix would make the
/// signed bytes — and the signature over them — disagree across platforms.
/// `u64::try_from` cannot realistically fail (no in-memory slice exceeds
/// `u64::MAX` bytes); the saturating fallback keeps the function total without
/// `unwrap`/`panic`, which crate lints deny.
pub(crate) fn push_framed(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::push_framed;
    use proptest::prelude::*;

    /// A test-only inverse that reads the 8-byte LE length prefixes back and
    /// recovers each field. Its existence IS the proof that `push_framed`'s
    /// framing is unambiguous: distinct field sequences cannot collide into the
    /// same byte string, which is exactly the property the signing-bytes
    /// forgery-resistance argument relies on. Written without `unwrap`/`panic`
    /// so it complies with the crate's `unwrap_used`/`panic` denials.
    fn parse_framed(mut buf: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while buf.len() >= 8 {
            let mut len_bytes = [0u8; 8];
            len_bytes.copy_from_slice(&buf[..8]);
            let len = usize::try_from(u64::from_le_bytes(len_bytes)).unwrap_or(usize::MAX);
            let rest = &buf[8..];
            if rest.len() < len {
                break;
            }
            out.push(rest[..len].to_vec());
            buf = &rest[len..];
        }
        out
    }

    proptest! {
        /// Framing round-trips: any sequence of fields (including empty fields
        /// and an empty sequence) frames and parses back identically — so no two
        /// distinct field sequences share a framing.
        #[test]
        fn framing_round_trips(
            fields in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..16)
        ) {
            let mut buf = Vec::new();
            for field in &fields {
                push_framed(&mut buf, field);
            }
            prop_assert_eq!(parse_framed(&buf), fields);
        }
    }

    /// Golden wire-format vectors that pin the exact 8-byte little-endian length
    /// prefix every signature in the crate is computed over. The round-trip
    /// proptest proves `push_framed` is injective against its OWN inverse, but a
    /// coordinated change to both `push_framed` and `parse_framed` (a `u32`
    /// prefix, or big-endian order) would still round-trip green while silently
    /// changing every minted signature. These fixed expectations fail on any
    /// width or endianness drift, so the wire contract cannot move unnoticed.
    #[test]
    fn push_framed_pins_the_wire_format() {
        // Empty field: an 8-byte zero length prefix and no payload.
        let mut empty = Vec::new();
        push_framed(&mut empty, &[]);
        assert_eq!(empty, [0u8; 8]);

        // Two-byte field "hi": length 2 as a little-endian u64, then raw bytes.
        let mut hi = Vec::new();
        push_framed(&mut hi, b"hi");
        assert_eq!(hi, [2, 0, 0, 0, 0, 0, 0, 0, b'h', b'i']);
    }
}
