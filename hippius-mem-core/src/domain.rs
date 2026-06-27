//! Core domain types for a single memory note.
//!
//! Every later layer (S3 blob store, hybrid index, op-log) consumes [`Note`].
//! The types here follow one rule: model state explicitly so invalid states are
//! unrepresentable (axiom `illu_design_02`). Enums replace stringly-typed state,
//! newtypes replace bare primitives, and each validated value funnels through a
//! single construction site so the invariant cannot be bypassed.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

/// Stable identifier for a memory note.
///
/// Wraps a [`ulid::Ulid`] (lexicographically sortable by creation time) and is
/// only constructible from a valid ULID, so an out-of-range value cannot exist.
/// The human/wire form is `mem_` + the ULID's Crockford base32 — see [`Display`]
/// and [`FromStr`], which are the round-trip pair the serde impls reuse.
///
/// [`Display`]: std::fmt::Display
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NoteId(ulid::Ulid);

/// The textual prefix that namespaces a [`NoteId`] in keys and logs.
const NOTE_ID_PREFIX: &str = "mem_";

impl NoteId {
    /// Generate a fresh identifier from the current time plus randomness.
    #[must_use]
    #[expect(
        clippy::new_without_default,
        reason = "a Default impl would mint a random, clock-reading id; a side-effecting identity created implicitly via derive(Default)/or_default() is a footgun, so callers must opt in explicitly via new()"
    )]
    pub fn new() -> Self {
        Self(ulid::Ulid::new())
    }

    /// Borrow the underlying ULID for callers that need the raw sortable value.
    #[must_use]
    pub const fn as_ulid(&self) -> ulid::Ulid {
        self.0
    }
}

impl From<ulid::Ulid> for NoteId {
    fn from(ulid: ulid::Ulid) -> Self {
        Self(ulid)
    }
}

impl fmt::Display for NoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NOTE_ID_PREFIX}{}", self.0)
    }
}

impl FromStr for NoteId {
    type Err = ParseNoteIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let crockford = s
            .strip_prefix(NOTE_ID_PREFIX)
            .ok_or(ParseNoteIdError::MissingPrefix)?;
        crockford
            .parse::<ulid::Ulid>()
            .map(Self)
            .map_err(ParseNoteIdError::InvalidUlid)
    }
}

impl Serialize for NoteId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `collect_str` routes through `Display`, keeping JSON as the `mem_…` form
        // without a separate allocation.
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NoteId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Why a string failed to parse into a [`NoteId`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ParseNoteIdError {
    /// The string did not begin with the required `mem_` prefix.
    MissingPrefix,
    /// The text after `mem_` was not a valid Crockford-base32 ULID.
    InvalidUlid(ulid::DecodeError),
}

impl fmt::Display for ParseNoteIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPrefix => f.write_str("note id is missing the `mem_` prefix"),
            Self::InvalidUlid(_) => f.write_str("note id has an invalid ULID body"),
        }
    }
}

impl std::error::Error for ParseNoteIdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingPrefix => None,
            Self::InvalidUlid(err) => Some(err),
        }
    }
}

/// The base58 alphabet used by SS58 account strings (Bitcoin/Substrate variant,
/// excluding the visually ambiguous `0`, `O`, `I`, and `l`).
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A Substrate SS58 account address, validated to a cheap structural sanity
/// check at construction.
///
/// The check accepts a byte length of 47..=48 (the range real SS58 v42 addresses
/// fall in) and an all-base58 character set. This is deliberately *not*
/// cryptographic validation: the SS58 checksum is verified where an address must
/// resolve to a key, by [`ss58_decode`](crate::identity::ss58_decode) (used in
/// [`crate::oplog::Op::verify_identity`]). The
/// field is private and every path — [`Ss58::new`], `TryFrom<String>`, and serde
/// deserialization via `#[serde(try_from = "String")]` — funnels through the same
/// check, so a value that skipped validation cannot be built.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Ss58(String);

impl Ss58 {
    /// Validate `value` and wrap it, or report why it cannot be an SS58 address.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSs58`] when the input is empty, has a length outside
    /// 47..=49 bytes, or contains a non-base58 character.
    ///
    /// The upper bound is 49, not 48: a two-byte network prefix (ident `>= 64`)
    /// encodes a 36-byte `prefix ++ pubkey ++ checksum` body, ~49 base58 chars.
    /// The old 47..=48 bound rejected exactly those on deserialize while
    /// [`Ss58::from_trusted`] (the encoder path) admitted them, so a note authored
    /// under a multi-byte prefix serialized but could not be re-read — an
    /// asymmetric round-trip. The bound now matches what the encoder can emit. (The
    /// Hippius default prefix 42 is one byte, ~47-48 chars, and is unaffected.)
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidSs58> {
        let value = value.into();
        if value.is_empty() {
            return Err(InvalidSs58::Empty);
        }
        let len = value.len();
        if !(47..=49).contains(&len) {
            return Err(InvalidSs58::BadLength { len });
        }
        if let Some(ch) = value.chars().find(|c| !is_base58(*c)) {
            return Err(InvalidSs58::IllegalChar { ch });
        }
        Ok(Self(value))
    }

    /// Borrow the validated address text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap a string already known to be a well-formed SS58 address, skipping
    /// the structural sanity check.
    ///
    /// The only caller is [`crate::identity::ss58_encode`], whose output is a
    /// base58-encoded `prefix ++ pubkey ++ blake2b checksum` and therefore
    /// valid by construction. [`Ss58::new`] remains the sole gate for every
    /// *untrusted* string; this trusted path exists so the encoder can return an
    /// [`Ss58`] infallibly without depending on the structural bound at all —
    /// `new` now accepts the ~49-char addresses two-byte prefixes produce, but a
    /// future longer-prefix or padding change must not be able to make the
    /// infallible encoder fail.
    pub(crate) fn from_trusted(value: String) -> Self {
        Self(value)
    }
}

/// Test a single character for base58 membership without casting `char` to a
/// narrower integer (the alphabet is ASCII, so comparing as `char` is exact).
fn is_base58(c: char) -> bool {
    BASE58_ALPHABET.iter().any(|&b| char::from(b) == c)
}

impl TryFrom<String> for Ss58 {
    type Error = InvalidSs58;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Why a string failed the [`Ss58`] sanity check.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum InvalidSs58 {
    /// The input was empty.
    Empty,
    /// The byte length was outside the accepted 47..=49 range.
    BadLength {
        /// The rejected length, in bytes.
        len: usize,
    },
    /// A character outside the base58 alphabet was present.
    IllegalChar {
        /// The first offending character.
        ch: char,
    },
}

impl fmt::Display for InvalidSs58 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("SS58 address is empty"),
            Self::BadLength { len } => write!(f, "SS58 address length {len} is outside 47..=49"),
            Self::IllegalChar { ch } => {
                write!(f, "SS58 address contains non-base58 character `{ch}`")
            }
        }
    }
}

impl std::error::Error for InvalidSs58 {}

/// BLAKE3 digest of a note's ciphertext, used later for integrity and as the
/// audit-anchor input.
///
/// Wraps a fixed `[u8; 32]`, so the "32 bytes" invariant holds by type. The wire
/// form is a 64-character lowercase hex string; uppercase is rejected so the
/// representation is canonical (see [`Blake3Hash::from_hex`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Blake3Hash([u8; 32]);

impl Blake3Hash {
    /// Wrap a raw 32-byte digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The all-zero digest, used as a sentinel rather than a real BLAKE3 output.
    ///
    /// BLAKE3 never produces the all-zero digest for any practical input, so
    /// the op-log uses this value as the `prev_op_hash` genesis marker for an
    /// author's first operation (see [`crate::oplog::GENESIS_PREV`]). `const fn`
    /// so it can seed that `const` at compile time.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Render the digest as a 64-character lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(self.0.len() * 2);
        for &byte in &self.0 {
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
        out
    }

    /// Parse a 64-character lowercase hex string back into a digest.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidBlake3Hex`] when the input is not exactly 64 characters
    /// or contains a character outside `0-9a-f` (uppercase is intentionally
    /// rejected to keep one canonical form).
    pub fn from_hex(s: &str) -> Result<Self, InvalidBlake3Hex> {
        let raw = s.as_bytes();
        if raw.len() != 64 {
            return Err(InvalidBlake3Hex::BadLength { len: raw.len() });
        }
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(raw.chunks_exact(2)) {
            *slot = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}

/// Decode one lowercase-hex byte into its 0..=15 nibble value.
fn hex_nibble(c: u8) -> Result<u8, InvalidBlake3Hex> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(InvalidBlake3Hex::IllegalHexDigit { ch: char::from(c) }),
    }
}

impl Serialize for Blake3Hash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Blake3Hash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Why a string failed to parse into a [`Blake3Hash`].
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum InvalidBlake3Hex {
    /// The input was not exactly 64 hex characters.
    BadLength {
        /// The rejected length, in bytes.
        len: usize,
    },
    /// A character outside `0-9a-f` was present.
    IllegalHexDigit {
        /// The first offending character.
        ch: char,
    },
}

impl fmt::Display for InvalidBlake3Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadLength { len } => write!(f, "hash hex length {len} is not 64"),
            Self::IllegalHexDigit { ch } => {
                write!(f, "hash hex contains non-lowercase-hex character `{ch}`")
            }
        }
    }
}

impl std::error::Error for InvalidBlake3Hex {}

/// The object-key segment standing in for [`RepoScope::Global`].
///
/// The single source of truth for the team-global sentinel: [`Scope::repo_segment`]
/// mints it and `objkey` parses it back, so the two never drift. Because the word
/// is reserved, a repository literally named `"global"` is rejected when deriving
/// an object key (otherwise `Repo("global")` and `Global` would both serialize to
/// `.../global/...` and the round trip would be lossy).
pub(crate) const GLOBAL_SEGMENT: &str = "global";

/// The repository dimension of a [`Scope`]: either team-wide or one named repo.
///
/// Serialized in serde's default externally-tagged form (`"Global"` or
/// `{"Repo": "name"}`); the variant is part of the wire contract for the
/// object-key layout, so it is modeled as an enum rather than an empty-string
/// sentinel (axiom `rust_quality_115_serde_attribute_correctness`).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum RepoScope {
    /// Visible to the whole team, not tied to one repository.
    Global,
    /// Tied to a single repository, named here.
    Repo(String),
}

/// Where a note lives: a team plus its repository dimension.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Scope {
    /// The owning team.
    pub team: String,
    /// Global or a specific repository.
    pub repo: RepoScope,
}

impl Scope {
    /// The path segment used in object keys: [`GLOBAL_SEGMENT`] for
    /// [`RepoScope::Global`], otherwise the repository name. This is the one place
    /// the global sentinel string is minted, so keys stay consistent across the
    /// codebase.
    ///
    /// `pub(crate)`: only the sibling `objkey` module mints object keys; this is
    /// an internal layout helper, not part of the crate's public surface.
    #[must_use]
    pub(crate) fn repo_segment(&self) -> &str {
        match &self.repo {
            RepoScope::Global => GLOBAL_SEGMENT,
            RepoScope::Repo(name) => name,
        }
    }
}

/// The kind of knowledge a note records.
///
/// The serde tags, [`Display`], and [`FromStr`] all use the same lowercase names
/// so the on-disk form, the parsed form, and the rendered form never drift apart.
///
/// [`Display`]: std::fmt::Display
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteType {
    /// A decision that was made and the reasoning behind it.
    Decision,
    /// A convention the team follows.
    Convention,
    /// A non-obvious pitfall worth remembering.
    Gotcha,
    /// A pointer to external material.
    Reference,
    /// Background context that frames other notes.
    Context,
}

impl NoteType {
    /// The lowercase tag for this type, shared by serde, [`Display`], and parsing.
    ///
    /// [`Display`]: std::fmt::Display
    const fn as_tag(self) -> &'static str {
        match self {
            Self::Decision => "decision",
            Self::Convention => "convention",
            Self::Gotcha => "gotcha",
            Self::Reference => "reference",
            Self::Context => "context",
        }
    }
}

impl fmt::Display for NoteType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_tag())
    }
}

impl FromStr for NoteType {
    type Err = ParseNoteTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "decision" => Ok(Self::Decision),
            "convention" => Ok(Self::Convention),
            "gotcha" => Ok(Self::Gotcha),
            "reference" => Ok(Self::Reference),
            "context" => Ok(Self::Context),
            _ => Err(ParseNoteTypeError {
                input: s.to_owned(),
            }),
        }
    }
}

/// Why a string failed to parse into a [`NoteType`].
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct ParseNoteTypeError {
    /// The unrecognized input, retained for an actionable message.
    input: String,
}

impl fmt::Display for ParseNoteTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown note type `{}`", self.input)
    }
}

impl std::error::Error for ParseNoteTypeError {}

/// A point in time as Unix milliseconds.
///
/// A plain `i64` newtype rather than a `time`/`chrono` type: it sidesteps
/// time-crate serde friction and serializes transparently as an integer.
/// Conversion to human-readable formats is a deliberate later concern.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Wrap a Unix-millisecond instant.
    #[must_use]
    pub const fn new(millis: i64) -> Self {
        Self(millis)
    }

    /// The wrapped Unix-millisecond value.
    #[must_use]
    pub const fn as_millis(self) -> i64 {
        self.0
    }
}

/// A single unit of team memory: identity, scope, attribution, and prose.
///
/// `tags` and `links` use [`BTreeSet`] so their order is deterministic; that
/// determinism is what makes the JSON round-trip stable regardless of insertion
/// order (axiom `rust_quality_162`). The serde derive defines the wire contract
/// for the stored blob, so adding a field later must keep old payloads readable.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Note {
    /// Stable identifier.
    pub id: NoteId,
    /// Where the note lives.
    pub scope: Scope,
    /// The kind of knowledge recorded.
    pub note_type: NoteType,
    /// The SS58 account that authored the note.
    pub author: Ss58,
    /// When the note was first created.
    pub created: Timestamp,
    /// When the note was last updated.
    pub updated: Timestamp,
    /// Free-form tags, kept sorted for deterministic output.
    pub tags: BTreeSet<String>,
    /// Related note ids, kept sorted for deterministic output.
    pub links: BTreeSet<NoteId>,
    /// One-sentence summary returned by `recall`.
    pub summary: String,
    /// Full note text returned by `get`.
    pub body: String,
}

impl Note {
    /// Serialize to compact JSON.
    ///
    /// The `Result` from `serde_json` is collapsed because a `Note` contains no
    /// non-string map keys and no `Serialize` impl that can fail, so the only way
    /// to reach the error arm would be an out-of-memory abort — not a recoverable
    /// condition. A richer error wrapper is introduced in the next task.
    ///
    /// # Panics
    ///
    /// Does not panic for any constructible `Note`: serialization of its fields
    /// is total. The internal `expect` guards only the theoretically-impossible
    /// `serde_json` failure described above.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "Note has no map keys and no fallible Serialize impl; serialization is total"
    )]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Note JSON serialization is infallible")
    }

    /// Parse a `Note` from JSON.
    ///
    /// # Errors
    ///
    /// Propagates the `serde_json` error for malformed JSON or a value that
    /// violates a field's invariant (e.g. an out-of-range [`Ss58`]). A typed
    /// crate-wide error wrapper is the next task's concern.
    pub fn from_json(s: &str) -> serde_json::Result<Self> {
        serde_json::from_str(s)
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
    use std::collections::BTreeSet;
    use std::str::FromStr;

    #[test]
    fn note_id_display_roundtrips() {
        let id = NoteId::new();
        let rendered = id.to_string();
        assert!(rendered.starts_with("mem_"));
        assert_eq!(NoteId::from_str(&rendered), Ok(id));
    }

    #[test]
    fn note_type_parses_and_rejects() {
        assert_eq!("decision".parse::<NoteType>().unwrap(), NoteType::Decision);
        assert_eq!("context".parse::<NoteType>().unwrap(), NoteType::Context);
        assert!("banana".parse::<NoteType>().is_err());
        for nt in [
            NoteType::Decision,
            NoteType::Convention,
            NoteType::Gotcha,
            NoteType::Reference,
            NoteType::Context,
        ] {
            assert_eq!(nt.to_string().parse::<NoteType>().unwrap(), nt);
        }
    }

    #[test]
    fn ss58_rejects_empty_and_bad_length() {
        assert!(matches!(Ss58::new(""), Err(InvalidSs58::Empty)));
        assert!(matches!(
            Ss58::new("toolong".repeat(20)),
            Err(InvalidSs58::BadLength { .. })
        ));
        assert!(matches!(
            Ss58::new("abc"),
            Err(InvalidSs58::BadLength { len: 3 })
        ));
        // A valid-length, all-base58 string is accepted (sanity check only).
        let ok = "5".to_owned() + &"1".repeat(47);
        assert!(Ss58::new(ok).is_ok());
        // Right length but a non-base58 character (`0`, `O`, `I`, `l`) is rejected.
        let bad = "0".to_owned() + &"1".repeat(47);
        assert!(matches!(
            Ss58::new(bad),
            Err(InvalidSs58::IllegalChar { ch: '0' })
        ));
    }

    #[test]
    fn scope_repo_segment_distinguishes_global() {
        let global = Scope {
            team: "team".to_owned(),
            repo: RepoScope::Global,
        };
        assert_eq!(global.repo_segment(), "global");
        let repo = Scope {
            team: "team".to_owned(),
            repo: RepoScope::Repo("hippius".to_owned()),
        };
        assert_eq!(repo.repo_segment(), "hippius");
    }

    proptest! {
        #[test]
        fn blake3_hex_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            let hash = Blake3Hash::new(bytes);
            prop_assert_eq!(Blake3Hash::from_hex(&hash.to_hex()).unwrap(), hash);
            let json = serde_json::to_string(&hash).unwrap();
            prop_assert_eq!(serde_json::from_str::<Blake3Hash>(&json).unwrap(), hash);
        }
    }

    prop_compose! {
        fn arb_note_id()(bytes in proptest::array::uniform16(any::<u8>())) -> NoteId {
            NoteId::from(ulid::Ulid::from_bytes(bytes))
        }
    }

    prop_compose! {
        fn arb_ss58()(s in "[1-9A-HJ-NP-Za-km-z]{48}") -> Ss58 {
            Ss58::new(s).unwrap()
        }
    }

    fn arb_note_type() -> impl Strategy<Value = NoteType> {
        prop_oneof![
            Just(NoteType::Decision),
            Just(NoteType::Convention),
            Just(NoteType::Gotcha),
            Just(NoteType::Reference),
            Just(NoteType::Context),
        ]
    }

    fn arb_repo_scope() -> impl Strategy<Value = RepoScope> {
        prop_oneof![
            Just(RepoScope::Global),
            "[a-z0-9-]{1,20}".prop_map(RepoScope::Repo),
        ]
    }

    prop_compose! {
        fn arb_note()(
            id in arb_note_id(),
            team in "[a-z0-9-]{1,20}",
            repo in arb_repo_scope(),
            note_type in arb_note_type(),
            author in arb_ss58(),
            created in any::<i64>(),
            updated in any::<i64>(),
            tags in prop::collection::btree_set("[a-z0-9-]{1,20}", 0..5),
            links in prop::collection::btree_set(arb_note_id(), 0..4),
            summary in "[^\n]{0,80}",
            body in "\\PC{0,500}",
        ) -> Note {
            Note {
                id,
                scope: Scope { team, repo },
                note_type,
                author,
                created: Timestamp::new(created),
                updated: Timestamp::new(updated),
                tags,
                links,
                summary,
                body,
            }
        }
    }

    proptest! {
        #[test]
        fn note_json_round_trips(note in arb_note()) {
            let json = note.to_json();
            prop_assert_eq!(Note::from_json(&json).unwrap(), note);
        }
    }

    #[test]
    fn note_id_rejects_missing_prefix() {
        assert_eq!(
            NoteId::from_str("01ARZ3NDEKTSV4RRFFQ69G5FAV"),
            Err(ParseNoteIdError::MissingPrefix)
        );
    }

    #[test]
    fn blake3_from_hex_rejects_bad_input() {
        assert!(matches!(
            Blake3Hash::from_hex("ab"),
            Err(InvalidBlake3Hex::BadLength { len: 2 })
        ));
        let with_uppercase = "A".to_owned() + &"0".repeat(63);
        assert!(matches!(
            Blake3Hash::from_hex(&with_uppercase),
            Err(InvalidBlake3Hex::IllegalHexDigit { ch: 'A' })
        ));
    }

    #[test]
    fn empty_btree_collections_round_trip() {
        let note = Note {
            id: NoteId::new(),
            scope: Scope {
                team: "t".to_owned(),
                repo: RepoScope::Global,
            },
            note_type: NoteType::Reference,
            author: Ss58::new("5".to_owned() + &"1".repeat(47)).unwrap(),
            created: Timestamp::new(0),
            updated: Timestamp::new(0),
            tags: BTreeSet::new(),
            links: BTreeSet::new(),
            summary: String::new(),
            body: String::new(),
        };
        assert_eq!(Note::from_json(&note.to_json()).unwrap(), note);
    }
}
