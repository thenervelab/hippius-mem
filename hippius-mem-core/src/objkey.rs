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
//! The version segment is the [`crate::ulid::Ulid`] of the op that wrote that version,
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

use crate::ulid::Ulid;

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
/// `version` is the [`crate::ulid::Ulid`] of the op that wrote this version (see the
/// module docs for why it is not a `+1` counter). The layout is
/// `"{team}/{repo_segment}/{mem_id}/ver_{version}"`, e.g.
/// `hippius-core/thebrain/mem_01J.../ver_01K...`.
///
/// # Errors
///
/// Returns [`MemError::Malformed`] when `scope.team` is unsafe as a key
/// component (empty, over 256 bytes, or containing any byte outside
/// `[A-Za-z0-9_-]`, so `/`, `\`, `.`, whitespace, and control bytes are all
/// rejected), when the repo name is empty, literally `"global"` (reserved for
/// the team-global scope), or over 256 bytes once escaped. A repo name outside
/// the alphabet is escaped, not refused (`next.js` becomes `_repo-next_2Ejs`). An unsafe
/// component is reported, never panicked, so the storage layer stays
/// panic-free.
pub fn object_key(scope: &Scope, id: NoteId, version: Ulid) -> Result<String, MemError> {
    validate_component(&scope.team)?;
    let repo = repo_segment(&scope.repo)?;

    // `id` Displays as `mem_<ulid>`, `version` as Crockford base32 (all
    // `[0-9A-Z]`, so the key component allowlist accepts it).
    Ok(format!("{}/{repo}/{id}/{VER_PREFIX}{version}", scope.team))
}

/// The prefix of a repo segment that holds an escaped repo name.
///
/// A leading `_` is otherwise reserved for the store's internal namespaces
/// (`_oplog`, `_snapshots`, `_anchors`, `_heads`, `_keys`, `_keycheck`, `_keyshares`), so no
/// plain repo segment and no namespace starts with this prefix, and an escaped
/// name can never land a note blob inside a namespace.
pub(crate) const ESCAPED_REPO_PREFIX: &str = "_repo-";

/// The key segment for `repo`: [`GLOBAL_SEGMENT`] for the team-global scope, the
/// name itself when it is a plain key component, and the escaped form
/// otherwise.
///
/// A plain component is drawn from `[A-Za-z0-9_-]`, does not start with `_`,
/// and is not `"global"`. Every other name (a dotted `next.js`, a leading
/// underscore, `..`) is written as [`ESCAPED_REPO_PREFIX`] followed by the name
/// with each byte outside `[A-Za-z0-9-]` as `_` and two upper-case hex digits,
/// so `next.js` is `_repo-next_2Ejs`. The mapping is injective: a plain segment
/// never starts with `_`, and inside an escaped one `_` only starts an escape.
/// The key alphabet stays `[A-Za-z0-9_-]`, and plain names keep the keys they
/// always had.
///
/// `"global"` stays refused rather than escaped: the server maps a `repo` of
/// `"global"` to the team-global scope, so a repo of that name is not one a
/// caller can mean.
fn repo_segment(repo: &RepoScope) -> Result<String, MemError> {
    let name = match repo {
        RepoScope::Global => return Ok(GLOBAL_SEGMENT.to_owned()),
        RepoScope::Repo(name) => name,
    };
    if name == GLOBAL_SEGMENT {
        return Err(MemError::Malformed(format!(
            "repo name {GLOBAL_SEGMENT:?} is reserved for the team-global scope"
        )));
    }
    if name.is_empty() {
        return Err(MemError::Malformed(
            "object-key component must not be empty".to_owned(),
        ));
    }

    let segment = if is_plain_repo_name(name) {
        name.clone()
    } else {
        let mut escaped = String::from(ESCAPED_REPO_PREFIX);
        for byte in name.bytes() {
            if byte.is_ascii_alphanumeric() || byte == b'-' {
                escaped.push(char::from(byte));
            } else {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                escaped.push('_');
                escaped.push(char::from(HEX[usize::from(byte >> 4)]));
                escaped.push(char::from(HEX[usize::from(byte & 0x0F)]));
            }
        }
        escaped
    };
    validate_component(&segment)?;
    Ok(segment)
}

/// Whether `name` is stored in a key as is (see [`repo_segment`]).
fn is_plain_repo_name(name: &str) -> bool {
    !name.starts_with('_')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The repo scope a key segment names: the inverse of [`repo_segment`].
///
/// Accepts only segments [`repo_segment`] emits, so one repo has one segment:
/// an escape that is not `_` plus two upper-case hex digits, a decoded name
/// that is not UTF-8, and an escaped form of a name that would be stored plain
/// are all refused.
fn parse_repo_segment(segment: &str) -> Result<RepoScope, MemError> {
    if segment == GLOBAL_SEGMENT {
        return Ok(RepoScope::Global);
    }
    validate_component(segment)?;
    let Some(escaped) = segment.strip_prefix(ESCAPED_REPO_PREFIX) else {
        if segment.starts_with('_') {
            return Err(MemError::Malformed(format!(
                "repo segment {segment:?} names an internal store namespace"
            )));
        }
        return Ok(RepoScope::Repo(segment.to_owned()));
    };

    let malformed =
        || MemError::Malformed(format!("repo segment {segment:?} is not a valid escape"));
    let mut bytes = Vec::with_capacity(escaped.len());
    let mut rest = escaped.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'_' {
            let [hi, lo, tail @ ..] = tail else {
                return Err(malformed());
            };
            let hex = [*hi, *lo];
            // Lower-case hex parses here; the round trip below refuses it.
            let digits = std::str::from_utf8(&hex).map_err(|_| malformed())?;
            bytes.push(u8::from_str_radix(digits, 16).map_err(|_| malformed())?);
            rest = tail;
        } else {
            bytes.push(byte);
            rest = tail;
        }
    }
    let name = String::from_utf8(bytes).map_err(|_| malformed())?;
    if repo_segment(&RepoScope::Repo(name.clone())).ok().as_deref() != Some(segment) {
        return Err(malformed());
    }
    Ok(RepoScope::Repo(name))
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
    let repo = parse_repo_segment(repo_seg)?;

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

/// The object-key prefix under which EVERY ciphertext version of a note lives,
/// derived from one of that note's version keys.
///
/// [`object_key`] lays a note's versions out as
/// `{team}/{repo_segment}/{mem_id}/ver_{version}`, and a note's repo is fixed at
/// `remember` (an edit preserves it), so every version shares the prefix
/// `{team}/{repo_segment}/{mem_id}/`. A single
/// [`BlobStore::list`](crate::BlobStore) on that prefix therefore enumerates
/// every version at once — which is how `redact` scrubs a note by listing its
/// bytes straight from the store instead of reading the whole op-log to recover
/// their keys. Listing the bytes is also strictly more complete for a redaction:
/// it catches a straggler version whose op has not reached this machine's log
/// yet, and an orphan blob whose op never verified — both invisible to an
/// op-log-derived key set.
///
/// The prefix is rebuilt from the PARSED components, not by trimming the string,
/// so a malformed key is rejected rather than yielding a bogus prefix that could
/// list — and scrub — the wrong keyspace. The trailing `/` is load-bearing: it
/// stops one note's prefix from matching another whose id shares a leading run
/// (mem-ids are fixed-length ULIDs, so with the slash no prefix contains
/// another), and it excludes the sibling `_oplog`/`_snapshots`/`_anchors`/`_heads`
/// namespaces because a repo segment that begins with `_` is always an escaped
/// one, under the `_repo-` prefix no namespace uses.
///
/// # Errors
///
/// Returns [`MemError::Malformed`] if `object_key` is not a valid note key —
/// the same conditions as [`parse_object_key`].
pub fn note_blob_prefix(object_key: &str) -> Result<String, MemError> {
    let (scope, id, _version) = parse_object_key(object_key)?;
    Ok(format!(
        "{}/{}/{id}/",
        scope.team,
        repo_segment(&scope.repo)?
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
            NoteId::from(crate::ulid::Ulid::from_bytes(bytes))
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
            // Names outside the key alphabet take the escaped form.
            "[a-zA-Z0-9_.\\-]{1,12}|\\PC{1,8}"
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

        // The property `redact` relies on: the prefix derived from ONE version key
        // covers EVERY version of that note, and nothing else. `v1 != v2` gives two
        // distinct version keys; both must start with the one prefix, and the prefix
        // must end in `/` so it cannot spill into a sibling note or namespace.
        #[test]
        fn prefix_covers_all_versions_of_a_note(
            scope in arb_scope(),
            id in arb_note_id(),
            v1 in arb_version(),
            v2 in arb_version(),
        ) {
            let key1 = object_key(&scope, id, v1).unwrap();
            let prefix = note_blob_prefix(&key1).unwrap();
            prop_assert!(prefix.ends_with('/'), "prefix {prefix:?} must end in a slash");
            prop_assert!(key1.starts_with(&prefix), "{key1:?} must start with {prefix:?}");
            let key2 = object_key(&scope, id, v2).unwrap();
            prop_assert!(
                key2.starts_with(&prefix),
                "a second version {key2:?} must share the prefix {prefix:?}"
            );
        }
    }

    #[test]
    fn note_blob_prefix_strips_the_version_segment() {
        let scope = Scope {
            team: "hippius-core".to_owned(),
            repo: RepoScope::Repo("thebrain".to_owned()),
        };
        let id = NoteId::new();
        let key = object_key(&scope, id, Ulid::new()).unwrap();
        let prefix = note_blob_prefix(&key).unwrap();
        assert_eq!(prefix, format!("hippius-core/thebrain/{id}/"));
        // A global-scope note lands under the `/global/` segment, not a repo name.
        let global = object_key(
            &Scope {
                team: "hippius-core".to_owned(),
                repo: RepoScope::Global,
            },
            id,
            Ulid::new(),
        )
        .unwrap();
        assert_eq!(
            note_blob_prefix(&global).unwrap(),
            format!("hippius-core/global/{id}/")
        );
    }

    #[test]
    fn note_blob_prefix_rejects_a_malformed_key() {
        // A bogus key must error, never yield a prefix that would list the wrong
        // keyspace and scrub unrelated notes.
        assert!(matches!(
            note_blob_prefix("team/global/not-an-id/ver_1"),
            Err(MemError::Malformed(_))
        ));
        assert!(matches!(
            note_blob_prefix("team/global/mem_x"),
            Err(MemError::Malformed(_))
        ));
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
    fn a_dotted_repo_name_is_escaped_into_one_safe_segment() {
        for (name, segment) in [
            ("next.js", "_repo-next_2Ejs"),
            ("..", "_repo-_2E_2E"),
            ("a_b.c", "_repo-a_5Fb_2Ec"),
        ] {
            let scope = Scope {
                team: "team".to_owned(),
                repo: RepoScope::Repo(name.to_owned()),
            };
            let key = object_key(&scope, NoteId::new(), Ulid::new()).unwrap();
            assert_eq!(key.split('/').nth(1), Some(segment), "{name:?}");
            assert_eq!(parse_object_key(&key).unwrap().0, scope);
        }
    }

    #[test]
    fn plain_and_escaped_names_never_share_a_segment() {
        // `a_2Eb` is plain, `a.b` is escaped; were `_` not escaped too, `a.b` and
        // `a_2Eb` would both be `..._2E...` under one prefix.
        let segments: Vec<String> = ["a.b", "a_2Eb", "_repo-a_2Eb", "a_b"]
            .into_iter()
            .map(|name| repo_segment(&RepoScope::Repo(name.to_owned())).unwrap())
            .collect();
        let distinct: std::collections::BTreeSet<&String> = segments.iter().collect();
        assert_eq!(distinct.len(), segments.len(), "{segments:?}");
    }

    #[test]
    fn parse_refuses_a_segment_object_key_never_emits() {
        for segment in [
            "_repo-abc",  // a plain name, escaped
            "_repo-a_2e", // lower-case hex
            "_repo-a_2",  // a cut-off escape
            "_repo-_FF",  // not UTF-8
            "_snapshots", // an internal namespace
        ] {
            let key = format!("team/{segment}/{}/ver_{}", NoteId::new(), Ulid::new());
            assert!(
                matches!(parse_object_key(&key), Err(MemError::Malformed(_))),
                "{segment:?} must be refused"
            );
        }
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
    fn a_repo_named_like_a_namespace_never_lands_in_it() {
        // A caller-named repo that matches an internal namespace must not put
        // note blobs under it, where `prune_old_snapshots`' retention sweep would
        // delete them as stale snapshots.
        for reserved in ["_snapshots", "_oplog", "_anchors", "_"] {
            let scope = Scope {
                team: "team".to_owned(),
                repo: RepoScope::Repo(reserved.to_owned()),
            };
            let key = object_key(&scope, NoteId::new(), Ulid::new()).unwrap();
            assert!(
                key.starts_with("team/_repo-_5F"),
                "{reserved:?} must be escaped out of the namespace, got {key}"
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
