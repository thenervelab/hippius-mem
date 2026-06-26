//! Object-key derivation for the shared team S3 blob store.
//!
//! A memory note's object KEY encodes where the note lives, so retrieval is a
//! direct `GetObject` rather than a listing scan. The layout is
//! `"{team}/{repo_segment}/{mem_id}/rev_{rev}"`, and [`object_key`] /
//! [`parse_object_key`] are an exact inverse pair (the `key_round_trips`
//! proptest is the executable proof of that bijection).
//!
//! The keyspace is ours to mint, but it is still a *boundary*: a key may be
//! interpreted by downstream tooling that maps objects onto filesystem paths,
//! so every component is validated to be traversal-free before it reaches a
//! key. Validation lives in [`object_key`] (honest, panic-free `Result`)
//! rather than a documented precondition, because an unsafe component is a
//! storage-layer fault the caller can recover from, not a reason to abort.

use crate::domain::{GLOBAL_SEGMENT, NoteId, RepoScope, Scope};
use crate::error::MemError;

/// The revision-segment prefix. Shared by both directions so the literal lives
/// in exactly one place.
const REV_PREFIX: &str = "rev_";

/// Reject a single key component that could enable path traversal or ambiguity.
///
/// A component is rejected when it is empty, contains `/` (would forge an extra
/// segment), contains `..` anywhere, or has leading/trailing whitespace.
///
/// The `..` rule is a *substring* check, deliberately stricter than the
/// component-level traversal check used for general filesystem paths: team and
/// repo identifiers are drawn from a controlled `[a-z0-9-]` alphabet where `..`
/// has no legitimate use, so rejecting any `..` is the safe superset with zero
/// false-negatives against the traversal invariant.
fn validate_component(value: &str) -> Result<(), MemError> {
    if value.is_empty() {
        return Err(MemError::Storage(
            "object-key component must not be empty".to_owned(),
        ));
    }
    if value.contains('/') {
        return Err(MemError::Storage(format!(
            "object-key component {value:?} must not contain '/'"
        )));
    }
    if value.contains("..") {
        return Err(MemError::Storage(format!(
            "object-key component {value:?} must not contain '..'"
        )));
    }
    if value.starts_with(char::is_whitespace) || value.ends_with(char::is_whitespace) {
        return Err(MemError::Storage(format!(
            "object-key component {value:?} must not start or end with whitespace"
        )));
    }
    Ok(())
}

/// Derive the S3 object key for revision `rev` of note `id` under `scope`.
///
/// The layout is `"{team}/{repo_segment}/{mem_id}/rev_{rev}"`, e.g.
/// `hippius-core/thebrain/mem_01J.../rev_3`.
///
/// # Errors
///
/// Returns [`MemError::Storage`] when `scope.team` or the repo name is unsafe
/// as a key component (empty, contains `/` or `..`, or has surrounding
/// whitespace), or when the repo is literally named `"global"` — a name
/// reserved for the team-global scope. An unsafe component is an upstream
/// programming error, but it is reported, never panicked, so the storage layer
/// stays panic-free.
pub fn object_key(scope: &Scope, id: NoteId, rev: u32) -> Result<String, MemError> {
    validate_component(&scope.team)?;
    if let RepoScope::Repo(name) = &scope.repo {
        if name == GLOBAL_SEGMENT {
            return Err(MemError::Storage(format!(
                "repo name {GLOBAL_SEGMENT:?} is reserved for the team-global scope"
            )));
        }
        validate_component(name)?;
    }
    // `repo_segment()` mints "global" for `Global` and the (already validated)
    // name otherwise; `id` Displays as `mem_<ulid>`.
    Ok(format!(
        "{}/{}/{id}/{REV_PREFIX}{rev}",
        scope.team,
        scope.repo_segment()
    ))
}

/// Parse an object key produced by [`object_key`] back into its components.
///
/// # Errors
///
/// Returns [`MemError::Storage`] for any malformed key: not exactly four
/// `/`-separated segments, an unsafe team/repo component, an id that is not a
/// valid `mem_<ulid>`, or a revision segment that is not `rev_<u32>`. A
/// malformed key is a storage-layer fault, so this never panics.
pub fn parse_object_key(key: &str) -> Result<(Scope, NoteId, u32), MemError> {
    let parts: Vec<&str> = key.split('/').collect();
    // `&str: Copy`, so the slice pattern binds each segment by copy; a length
    // mismatch falls through to the typed error instead of panicking on index.
    let [team, repo_seg, id_seg, rev_seg] = parts[..] else {
        return Err(MemError::Storage(format!(
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
        .map_err(|err| MemError::Storage(format!("object key has an invalid note id: {err}")))?;

    let rev = rev_seg
        .strip_prefix(REV_PREFIX)
        .ok_or_else(|| {
            MemError::Storage(format!(
                "object key revision segment {rev_seg:?} must start with {REV_PREFIX:?}"
            ))
        })?
        .parse::<u32>()
        .map_err(|err| MemError::Storage(format!("object key has an invalid revision: {err}")))?;

    Ok((
        Scope {
            team: team.to_owned(),
            repo,
        },
        id,
        rev,
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
        fn key_round_trips(scope in arb_scope(), id in arb_note_id(), rev in any::<u32>()) {
            let key = object_key(&scope, id, rev).unwrap();
            let (parsed_scope, parsed_id, parsed_rev) = parse_object_key(&key).unwrap();
            prop_assert_eq!(parsed_scope, scope);
            prop_assert_eq!(parsed_id, id);
            prop_assert_eq!(parsed_rev, rev);
        }
    }

    #[test]
    fn global_scope_uses_global_segment() {
        let scope = Scope {
            team: "hippius-core".to_owned(),
            repo: RepoScope::Global,
        };
        let key = object_key(&scope, NoteId::new(), 3).unwrap();
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
            object_key(&scope, NoteId::new(), 0),
            Err(MemError::Storage(_))
        ));
    }

    #[test]
    fn rejects_dotdot_component() {
        let scope = Scope {
            team: "team".to_owned(),
            repo: RepoScope::Repo("..".to_owned()),
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), 0),
            Err(MemError::Storage(_))
        ));
    }

    #[test]
    fn rejects_empty_component() {
        let scope = Scope {
            team: String::new(),
            repo: RepoScope::Global,
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), 0),
            Err(MemError::Storage(_))
        ));
    }

    #[test]
    fn rejects_whitespace_component() {
        let scope = Scope {
            team: " team".to_owned(),
            repo: RepoScope::Global,
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), 0),
            Err(MemError::Storage(_))
        ));
    }

    #[test]
    fn rejects_repo_named_global() {
        let scope = Scope {
            team: "team".to_owned(),
            repo: RepoScope::Repo("global".to_owned()),
        };
        assert!(matches!(
            object_key(&scope, NoteId::new(), 0),
            Err(MemError::Storage(_))
        ));
    }

    #[test]
    fn parse_rejects_wrong_segment_count() {
        assert!(matches!(
            parse_object_key("team/global/mem_x"),
            Err(MemError::Storage(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_rev() {
        let key = format!("team/global/{}/rev_notanumber", NoteId::new());
        assert!(matches!(parse_object_key(&key), Err(MemError::Storage(_))));
    }

    #[test]
    fn parse_rejects_bad_id() {
        assert!(matches!(
            parse_object_key("team/global/not-an-id/rev_1"),
            Err(MemError::Storage(_))
        ));
    }
}
