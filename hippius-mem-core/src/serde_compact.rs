//! Compact JSON encodings for the binary fields of the index checkpoint.
//!
//! `serde_json` writes a `Vec<u8>` as an array of decimal numbers (about 3.6
//! characters per byte) and an `f32` as up to a dozen characters of decimal
//! text. The checkpoint carries one sealed record per note, each wrapping an
//! embedding of hundreds of floats, so those two encodings made a 4,600-note
//! team's checkpoint about 90 MiB. These adapters write base64 instead: the
//! bytes as-is, and a vector as the little-endian bytes of its floats, which is
//! also bit-exact where decimal text round-trips floats only approximately.
//!
//! # Reading both forms
//!
//! Checkpoints live in a shared bucket and are written by every teammate's
//! build, so a checkpoint written by an older release (JSON arrays) must keep
//! loading. Each adapter therefore READS both the base64 string and the legacy
//! array, and WRITES only base64. An older release cannot read the new form: it
//! skips such a checkpoint as unreadable (as it does any undecodable one) and
//! falls back to an older checkpoint or a full replay — correct, only slower.

use core::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

use crate::base64;

/// `#[serde(with = "crate::serde_compact::bytes")]` for a `Vec<u8>`.
pub(crate) mod bytes {
    use super::{BytesVisitor, Deserializer, Serializer, base64};

    pub(crate) fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::encode(value))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(BytesVisitor)
    }
}

/// `#[serde(default, skip_serializing_if = "Option::is_none", with =
/// "crate::serde_compact::floats")]` for an `Option<Vec<f32>>`.
pub(crate) mod floats {
    use super::{Deserializer, FloatsVisitor, Serializer, base64};

    #[expect(
        clippy::ref_option,
        reason = "serde's `with` passes the field by reference, so the signature is fixed"
    )]
    pub(crate) fn serialize<S: Serializer>(
        value: &Option<Vec<f32>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(floats) => {
                let bytes: Vec<u8> = floats.iter().flat_map(|f| f.to_le_bytes()).collect();
                serializer.serialize_str(&base64::encode(bytes))
            }
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<f32>>, D::Error> {
        deserializer.deserialize_any(FloatsVisitor)
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a base64 string or an array of bytes")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        base64::decode(value).map_err(E::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element::<u8>()? {
            out.push(byte);
        }
        Ok(out)
    }
}

struct FloatsVisitor;

impl<'de> Visitor<'de> for FloatsVisitor {
    type Value = Option<Vec<f32>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("null, a base64 string of little-endian f32s, or an array of numbers")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        let bytes = base64::decode(value).map_err(E::custom)?;
        let (chunks, rest) = bytes.as_chunks::<4>();
        if !rest.is_empty() {
            return Err(E::custom("embedding bytes are not a whole number of f32s"));
        }
        Ok(Some(
            chunks
                .iter()
                .map(|chunk| f32::from_le_bytes(*chunk))
                .collect(),
        ))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(value) = seq.next_element::<f32>()? {
            out.push(value);
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use proptest::prelude::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Holder {
        #[serde(with = "super::bytes")]
        sealed: Vec<u8>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "super::floats"
        )]
        embedding: Option<Vec<f32>>,
    }

    fn holder(sealed: Vec<u8>, embedding: Option<Vec<f32>>) -> Holder {
        Holder { sealed, embedding }
    }

    #[test]
    fn writes_base64_strings() -> serde_json::Result<()> {
        let json = serde_json::to_string(&holder(b"foo".to_vec(), Some(vec![1.0])))?;
        assert_eq!(json, r#"{"sealed":"Zm9v","embedding":"AACAPw=="}"#);
        Ok(())
    }

    #[test]
    fn reads_the_legacy_array_forms() -> serde_json::Result<()> {
        let legacy = r#"{"sealed":[102,111,111],"embedding":[1.0,-2.5]}"#;
        let parsed: Holder = serde_json::from_str(legacy)?;
        assert_eq!(parsed, holder(b"foo".to_vec(), Some(vec![1.0, -2.5])));
        Ok(())
    }

    #[test]
    fn a_missing_or_null_embedding_is_none() -> serde_json::Result<()> {
        let missing: Holder = serde_json::from_str(r#"{"sealed":""}"#)?;
        let null: Holder = serde_json::from_str(r#"{"sealed":"","embedding":null}"#)?;
        assert_eq!(missing.embedding, None);
        assert_eq!(null.embedding, None);
        Ok(())
    }

    #[test]
    fn rejects_a_partial_float() {
        // Five bytes: one whole f32 and a stray byte.
        let partial = format!(
            r#"{{"sealed":"","embedding":"{}"}}"#,
            crate::base64::encode([0; 5])
        );
        assert!(serde_json::from_str::<Holder>(&partial).is_err());
    }

    proptest! {
        #[test]
        fn round_trips_bit_exact(
            sealed in proptest::collection::vec(any::<u8>(), 0..64),
            bits in proptest::option::of(proptest::collection::vec(any::<u32>(), 0..16)),
        ) {
            // Build floats from raw bits so NaN payloads and signed zeros are
            // covered too: the round trip must preserve the exact bit patterns.
            let embedding = bits.map(|bits| bits.into_iter().map(f32::from_bits).collect::<Vec<_>>());
            let json = serde_json::to_string(&holder(sealed.clone(), embedding.clone()))
                .map_err(|err| TestCaseError::fail(err.to_string()))?;
            let parsed: Holder = serde_json::from_str(&json)
                .map_err(|err| TestCaseError::fail(err.to_string()))?;
            prop_assert_eq!(parsed.sealed, sealed);
            let as_bits = |floats: Option<Vec<f32>>| {
                floats.map(|floats| floats.into_iter().map(f32::to_bits).collect::<Vec<_>>())
            };
            prop_assert_eq!(as_bits(parsed.embedding), as_bits(embedding));
        }
    }
}
