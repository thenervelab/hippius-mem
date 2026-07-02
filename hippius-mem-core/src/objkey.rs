//! Object-key derivation for the shared team S3 blob store.
//!
//! A memory note's object KEY encodes where the note lives, so retrieval is a
//! direct `GetObject` rather than a listing scan. The layout is
//! `"{team}/{repo_segment}/{mem_id}/ver_{version}"`, and [`parse_object_key`] is
//! a LEFT INVERSE of [`object_key`]: `parse_object_key(object_key(x)) == x` for
//! every `x` (the `key_round_trips` proptest proves exactly that). It is not a
//! full bijection — `parse_object_key` also accepts non-canonical encodings
//! `object_key` never emits (a lower-case / `I,L,O`-aliased ULID in either the
//! id or version segment), all of which decode to the same canonical components.
//! Production only ever parses keys it minted, so this is latent; a future path
//! parsing untrusted keys must not assume canonicality from a successful parse.
//!
//! # Why the version is the writing op's ULID, not a counter
//!
//! The version segment is the [`ulid::Ulid`] of the op that wrote that version,
//! not a per-note `+1` revision counter. A counter is derived from a reader's
//! view of the current revision, so two writers (two machines editing the same
//! note from the same synced state) independently pick the SAME next counter and
//! derive the SAME key — the later `put` then overwrites the earlier writer's
//! ciphertext, and whichever op later wins convergence may name a key holding the
//! OTHER op's bytes (the integrity gate in `get` then rejects the note: silent
//! data loss). A ULID is globally unique by construction, so every write lands at
//! a distinct key and no honest write can clobber another's blob.
//!
//! The keyspace is ours to mint, but it is still a *boundary*: a key may be
//! interpreted by downstream tooling that maps objects onto filesystem paths,
//! so every component is validated to be traversal-free before it reaches a
//! key. Validation lives in [`object_key`] (honest, panic-free `Result`)
//! rather than a documented precondition, because an unsafe component is a
//! storage-layer fault the caller can recover from, not a reason to abort.

use ulid::Ulid;

use crate::domain::{GLOBAL_SEGMENT, NoteId, RepoScope, Scope};
use crate::error::MemError;

/// The version-segment prefix. Shared by both directions so the literal lives
/// in exactly one place.
const VER_PREFIX: &str = "ver_";

/// Reject a single key component that could enable path traversal or ambiguity.
///
/// A component must be non-empty, at most 256 bytes, and drawn entirely from
/// `[A-Za-z0-9_-]`. That
/// single allowlist is what the rest of the module's traversal reasoning assumed
/// but did not previously enforce: it rejects `/` and `\` (either OS's path
/// separator), `.` (so `.`/`..` path elements are impossible), control bytes,
/// whitespace, and any non-ASCII byte in one check. A key is a boundary that
/// downstream tooling may map onto a filesystem path, so the enforced alphabet
/// must equal the documented one — not a weaker subset.
fn validate_component(value: &str) -> Result<(), MemError> {
    // The whole `{team}/{repo}/{id}/{version}` key must stay under S3's 1024-byte
    // key limit; bounding each caller-controlled component keeps it there and turns
    // a pathological `team`/`repo` name into a clear `Malformed` here rather than an
    // opaque `Storage` failure at `put`. The alphabet below is ASCII, so byte length
    // equals character count.
    const MAX_COMPONENT_LEN: usize = 256;
    if value.is_empty() {
        return Err(MemError::Malformed(
            "object-key component must not be empty".to_owned(),
        ));
    }
    if value.len() > MAX_COMPONENT_LEN {
        return Err(MemError::Malformed(format!(
            "object-key component of {} bytes exceeds the {MAX_COMPONENT_LEN}-byte limit",
            value.len()
        )));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(MemError::Malformed(format!(
            "object-key component {value:?} must match [A-Za-z0-9_-]"
        )));
    }
    Ok(())
}

/// Derive the S3 object key for the `version` of note `id` under `scope`.
///
/// `version` is the [`ulid::Ulid`] of the op that wrote this version (see the
/// module docs for why it is not a `+1` counter). The layout is
/// `"{team}/{repo_segment}/{mem_id}/ver_{version}"`, e.g.
/// `hippius-core/thebrain/mem_01J.../ver_01K...`.
///
/// # Errors
///
/// Returns [`MemError::Malformed`] when `scope.team` or the repo name is unsafe
/// as a key component (empty, or containing any byte outside `[A-Za-z0-9_-]` —
/// so `/`, `\`, `.`, whitespace, and control bytes are all rejected), when the
/// repo is literally named `"global"` — a name reserved for the team-global
/// scope — or when the repo name begins with `_`, reserved for the store's
/// internal namespaces. An unsafe component is an upstream programming error,
/// but it is reported, never panicked, so the storage layer stays panic-free.
pub fn object_key(scope: &Scope, id: NoteId, version: Ulid) -> Result<String, MemError> {
    validate_component(&scope.team)?;
    if let RepoScope::Repo(name) = &scope.repo {
        if name == GLOBAL_SEGMENT {
            return Err(MemError::Malformed(format!(
                "repo name {GLOBAL_SEGMENT:?} is reserved for the team-global scope"
            )));
        }
        // A leading underscore is reserved for the store's internal namespaces
        // (`_oplog`, `_snapshots`, `_anchors`, and any future one), which share
        // the `{team}/{segment}/...` keyspace with note blobs. Without this guard
        // a caller-controlled repo named `_snapshots` lands note blobs in the
        // snapshot namespace, where `prune_old_snapshots`' retention sweep would
        // delete them as stale snapshots — silent, permanent data loss. Reserving
        // the whole leading-`_` prefix closes the class, not just the one name.
        if name.starts_with('_') {
            return Err(MemError::Malformed(format!(
                "repo name {name:?} is reserved: a leading underscore names an internal store namespace"
            )));
        }
        validate_component(name)?;
    }
    // `repo_segment()` mints "global" for `Global` and the (already validated)
    // name otherwise; `id` Displays as `mem_<ulid>`, `version` as Crockford
    // base32 (all `[0-9A-Z]`, so the key component allowlist accepts it).
    Ok(format!(
        "{}/{}/{id}/{VER_PREFIX}{version}",
        scope.team,
        scope.repo_segment()
    ))
}

/// Parse an object key produced by [`object_key`] back into its components.
///
/// # Errors
///
/// Returns [`MemError::Malformed`] for any malformed key: not exactly four
/// `/`-separated segments, an unsafe team/repo component, an id that is not a
/// valid `mem_<ulid>`, or a version segment that is not `ver_<ulid>`. A
/// malformed key is a storage-layer fault, so this never panics.
pub fn parse_object_key(key: &str) -> Result<(Scope, NoteId, Ulid), MemError> {
    let parts: Vec<&str> = key.split('/').collect();
    // `&str: Copy`, so the slice pattern binds each segment by copy; a length
    // mismatch falls through to the typed error instead of panicking on index.
    let [team, repo_seg, id_seg, ver_seg] = parts[..] else {
        return Err(MemError::Malformed(format!(
            "object key must have 4 '/'-separated segments, got {}",
            parts.len()
        )));
    };

    validate_component(team)?;
    // "global" is the reserved sentinel: it always maps back to `Global`, and
    // `object_key` guarantees no `Repo("global")` was ever encoded, so the
    // mapping is bijective.
    let repo = if repo_seg == GLOBAL_SEGMENT {
        RepoScope::Global
    } else {
        validate_component(repo_seg)?;
        RepoScope::Repo(repo_seg.to_owned())
    };

    let id = id_seg
        .parse::<NoteId>()
        .map_err(|err| MemError::Malformed(format!("object key has an invalid note id: {err}")))?;

    let version = ver_seg
        .strip_prefix(VER_PREFIX)
        .ok_or_else(|| {
            MemError::Malformed(format!(
                "object key version segment {ver_seg:?} must start with {VER_PREFIX:?}"
            ))
        })?
        .parse::<Ulid>()
        .map_err(|err| MemError::Malformed(format!("object key has an invalid version: {err}")))?;

    Ok((
        Scope {
            team: team.to_owned(),
            repo,
        },
        id,
        version,
    ))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "tests assert on known-valid fixtures where construction cannot fail"
    )]

    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_note_id()(bytes in proptest::array::uniform16(any::<u8>())) -> NoteId {
            NoteId::from(ulid::Ulid::from_bytes(bytes))
        }
    }

    prop_compose! {
        fn arb_version()(bytes in proptest::array::uniform16(any::<u8>())) -> Ulid {
            Ulid::from_bytes(bytes)
        }
    }

    fn arb_repo_scope() -> impl Strategy<Value = RepoScope> {
        prop_oneof![
            Just(RepoScope::Global),
            // Exclude the reserved word so `object_key` never rejects a value
            // the round-trip property feeds it.
            "[a-z0-9-]{1,20}"
                .prop_filter("repo name \"global\" is reserved", |s| s != GLOBAL_SEGMENT)
                .prop_map(RepoScope::Repo),
        ]
    }

    prop_compose! {
        fn arb_scope()(team in "[a-z0-9-]{1,20}", repo in arb_repo_scope()) -> Scope {
            Scope { team, repo }
        }
    }

    proptest! {
        #[test]
        fn key_round_trips(scope in arb_scope(), id in arb_note_id(), version in arb_version()) {
            let key = object_key(&scope, id, version).unwrap();
            let (parsed_scope, parsed_id, parsed_version) = parse_object_key(&key).unwrap();
            prop_assert_eq!(parsed_scope, scope);
            prop_assert_eq!(parsed_id, id);
            prop_assert_eq!(parsed_version, version);
        }
    }

    #[test]
    fn global_scope_uses_global_segment() {
        let scope = Scope {
            team: "hippius-core".to_owned(),
            repo: RepoScope::Global,
        };
        let key = object_key(&scope, NoteId::new(), Ulid::new()).unwrap();
        assert!(key.contains("/global/"), "key was {key}");
        let (parsed, _, _) = parse_object_key(&key).unwrap();
        assert_eq!(parsed.repo, RepoScope::Global);
    }

    #[test]
    fn rejects_team_with_slash() {
        let scope = Scope {
            team: "a/b".to_owned(),
            repo: RepoScope::Global,
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), Ulid::new()),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_over_long_component() {
        // A caller-controlled component longer than the 256-byte cap is rejected as
        // Malformed here, not left to fail opaquely at `put` once the assembled key
        // exceeds S3's 1024-byte key limit. 257 valid-alphabet bytes isolates the
        // length check from the alphabet check.
        let long = "a".repeat(257);
        assert!(
            matches!(
                object_key(
                    &Scope {
                        team: long.clone(),
                        repo: RepoScope::Global,
                    },
                    NoteId::new(),
                    Ulid::new()
                ),
                Err(MemError::Malformed(_))
            ),
            "an over-long team is rejected"
        );
        assert!(
            matches!(
                object_key(
                    &Scope {
                        team: "team".to_owned(),
                        repo: RepoScope::Repo(long),
                    },
                    NoteId::new(),
                    Ulid::new()
                ),
                Err(MemError::Malformed(_))
            ),
            "an over-long repo name is rejected"
        );
        // A 256-byte component is at the boundary and accepted.
        assert!(
            object_key(
                &Scope {
                    team: "a".repeat(256),
                    repo: RepoScope::Global,
                },
                NoteId::new(),
                Ulid::new()
            )
            .is_ok(),
            "a 256-byte component is within the limit"
        );
    }

    #[test]
    fn rejects_dotdot_component() {
        let scope = Scope {
            team: "team".to_owned(),
            repo: RepoScope::Repo("..".to_owned()),
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), Ulid::new()),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_empty_component() {
        let scope = Scope {
            team: String::new(),
            repo: RepoScope::Global,
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), Ulid::new()),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_whitespace_component() {
        let scope = Scope {
            team: " team".to_owned(),
            repo: RepoScope::Global,
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), Ulid::new()),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_backslash_and_control_bytes() {
        // crypto-2: the alphabet allowlist rejects bytes the old substring checks
        // let through — a backslash forges a path element on a Windows consumer,
        // and a control byte is a non-canonical path component.
        for bad in ["a\\b", "x\ny", "v.1", "."] {
            let scope = Scope {
                team: bad.to_owned(),
                repo: RepoScope::Global,
            };
            assert!(
                matches!(
                    object_key(&scope, NoteId::new(), Ulid::new()),
                    Err(MemError::Malformed(_))
                ),
                "component {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_repo_named_global() {
        let scope = Scope {
            team: "team".to_owned(),
            repo: RepoScope::Repo("global".to_owned()),
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), Ulid::new()),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_repo_with_reserved_underscore_prefix() {
        // The store-takeover vector: a caller-named repo that collides with an
        // internal namespace must be refused at the key boundary, so a note can
        // never be minted into `_snapshots`/`_oplog` and swept by retention.
        for reserved in ["_snapshots", "_oplog", "_anchors", "_"] {
            let scope = Scope {
                team: "team".to_owned(),
                repo: RepoScope::Repo(reserved.to_owned()),
            };
            assert!(
                matches!(
                    object_key(&scope, NoteId::new(), Ulid::new()),
                    Err(MemError::Malformed(_))
                ),
                "reserved repo name {reserved:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_rejects_wrong_segment_count() {
        assert!(matches!(
            parse_object_key("team/global/mem_x"),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_rev() {
        let key = format!("team/global/{}/ver_notanumber", NoteId::new());
        assert!(matches!(
            parse_object_key(&key),
            Err(MemError::Malformed(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_id() {
        assert!(matches!(
            parse_object_key("team/global/not-an-id/ver_1"),
            Err(MemError::Malformed(_))
        ));
    }
}
