//! Route the launch repository to the team profile whose memory it belongs to.
//!
//! One server process binds exactly one profile (design:
//! `docs/plans/2026-07-03-multi-team-org-routing-design.md`). This module owns
//! that decision: given the launch repo's `origin` remote and the configured
//! profiles, pick which profile's store to bind — or report that memory is
//! disabled for this repo. Reading the remote sits behind [`RemoteReader`] so the
//! routing logic is unit-tested with injected strings, never a live `git`
//! subprocess (the seam pattern for isolating a live dependency).

use std::path::Path;
use std::process::Command;

/// Canonical coordinates of a repository's remote, `host/org/repo`.
///
/// The host is lowercased because DNS is case-insensitive; `org`/`repo` keep
/// their original case (a forge may treat the path as case-sensitive). Used both
/// to match a profile's `orgs` and, later, to derive a note's repo scope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct RepoCoord {
    /// Remote host, e.g. `github.com`, lowercased.
    pub(crate) host: String,
    /// Owning org or user: the first path segment.
    pub(crate) org: String,
    /// Repository name: the last path segment, with any `.git` suffix removed.
    pub(crate) repo: String,
}

/// The org-routing view of one configured team profile.
///
/// Only the fields the router reads live here; the credential fields (`bucket`,
/// `secret`, key, seed) join when `Config` is split into profiles, so routing
/// never has the credentials in hand while it decides.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct TeamProfile {
    /// Human-facing profile name, logged when a profile binds.
    pub(crate) name: String,
    /// Remote patterns this profile owns: `host/org` (a whole org) or
    /// `host/org/repo` (one repo). Empty for a pure catch-all.
    pub(crate) orgs: Vec<String>,
    /// Whether this profile absorbs repos that match no `orgs` (and repos with no
    /// remote). At most one profile may set this — enforced at config load.
    pub(crate) catch_all: bool,
}

/// The outcome of routing the launch repo against the configured profiles.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Resolution<'a> {
    /// Bind this profile's memory store for the process lifetime.
    Bound(&'a TeamProfile),
    /// Bind no store: memory is off for this repo, for the given reason.
    Disabled(DisabledReason),
}

/// Why memory is disabled for the launch repo — surfaced to the user by the
/// memory tools so a silent no-op is never mistaken for "nothing to recall".
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DisabledReason {
    /// The remote resolved but matched no profile, and no catch-all is defined.
    Unmatched(RepoCoord),
    /// No usable `origin` remote (not a git repo, or origin unset), and no
    /// catch-all is defined.
    NoRemote,
}

impl std::fmt::Display for DisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmatched(coord) => write!(
                f,
                "no team profile maps {}/{}/{}; add its org to a [[team]] profile \
                 or define a catch_all profile",
                coord.host, coord.org, coord.repo
            ),
            Self::NoRemote => f.write_str(
                "this repository has no git 'origin' remote and no catch_all profile \
                 is configured, so team memory is disabled here",
            ),
        }
    }
}

/// Choose the profile to bind for the repo whose remote is `remote`.
///
/// Order: the first profile whose `orgs` matches the remote wins; else the sole
/// `catch_all` profile; else [`Resolution::Disabled`]. A `None` remote (no
/// `origin`, or not a git repo) can only land on the catch-all — a local-only
/// project is de facto personal.
#[must_use]
pub(crate) fn resolve<'a>(profiles: &'a [TeamProfile], remote: Option<&str>) -> Resolution<'a> {
    let coord = remote.and_then(normalize_remote);
    if let Some(coord) = &coord
        && let Some(profile) = profiles
            .iter()
            .find(|profile| matches(coord, &profile.orgs))
    {
        return Resolution::Bound(profile);
    }
    if let Some(profile) = profiles.iter().find(|profile| profile.catch_all) {
        return Resolution::Bound(profile);
    }
    match coord {
        Some(coord) => Resolution::Disabled(DisabledReason::Unmatched(coord)),
        None => Resolution::Disabled(DisabledReason::NoRemote),
    }
}

/// Parse a git remote URL into canonical `host/org/repo`, or `None` if it is not
/// a recognizable remote carrying at least an org and a repo.
///
/// Accepts the three shapes `git` emits: scp-like SSH (`git@github.com:org/repo.git`),
/// `https://github.com/org/repo(.git)`, and `ssh://git@github.com/org/repo`. One
/// trailing `.git` and any trailing slashes are stripped, and the host is
/// lowercased. For a nested path (`host/group/sub/repo`) the org is the first
/// segment and the repo the last, so routing keys on the top-level org. A
/// single-segment path (`host/org`, no repo), a local filesystem path, or junk
/// yields `None`.
fn normalize_remote(url: &str) -> Option<RepoCoord> {
    let url = url.trim();
    // Split the host from the `org/.../repo` path across the three forms. `://`
    // is checked first so an `https`/`ssh` URL never reaches the scp branch,
    // whose `:` split would otherwise misread the scheme colon.
    let (host, path) = if let Some((_scheme, after)) = url.split_once("://") {
        let (authority, path) = after.split_once('/')?;
        // Drop any `user@` userinfo; keep the bare host.
        (authority.rsplit('@').next().unwrap_or(authority), path)
    } else if let Some((authority, path)) = url.split_once(':') {
        (authority.rsplit('@').next().unwrap_or(authority), path)
    } else {
        return None;
    };
    if host.is_empty() {
        return None;
    }
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let org = path.split('/').find(|segment| !segment.is_empty())?;
    let repo = path.rsplit('/').find(|segment| !segment.is_empty())?;
    // A single non-empty segment is an org, not a repo: `org` and `repo` would be
    // the same lone segment and the path holds no separator.
    if !path.contains('/') {
        return None;
    }
    Some(RepoCoord {
        host: host.to_ascii_lowercase(),
        org: org.to_owned(),
        repo: repo.to_owned(),
    })
}

/// Whether `coord` falls under any of `patterns` — each a `host/org` (whole org)
/// or `host/org/repo` (one repo) — compared case-insensitively.
fn matches(coord: &RepoCoord, patterns: &[String]) -> bool {
    let host_org = format!("{}/{}", coord.host, coord.org);
    let host_org_repo = format!("{host_org}/{}", coord.repo);
    patterns.iter().any(|pattern| {
        let pattern = pattern.trim().trim_end_matches('/');
        pattern.eq_ignore_ascii_case(&host_org) || pattern.eq_ignore_ascii_case(&host_org_repo)
    })
}

/// Read a repository's `origin` remote URL.
///
/// Behind a trait so [`resolve`] is exercised with injected strings in tests
/// while production reads the real remote, keeping the routing logic free of a
/// live `git` dependency.
pub(crate) trait RemoteReader {
    /// The `origin` remote URL for the repo containing `dir`, or `None` when
    /// there is no git repo, no `origin`, or `git` is unavailable.
    fn origin_url(&self, dir: &Path) -> Option<String>;
}

/// Reads the remote by shelling out to `git` — always present in a dev
/// environment, and the same tool the installer already relies on.
pub(crate) struct GitRemoteReader;

impl RemoteReader for GitRemoteReader {
    fn origin_url(&self, dir: &Path) -> Option<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["remote", "get-url", "origin"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let url = String::from_utf8(output.stdout).ok()?;
        let url = url.trim();
        if url.is_empty() {
            None
        } else {
            Some(url.to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "tests assert on hand-built fixtures where construction cannot fail"
    )]

    use super::{
        DisabledReason, GitRemoteReader, RemoteReader, RepoCoord, Resolution, TeamProfile,
        normalize_remote, resolve,
    };
    use proptest::prelude::*;

    fn coord(host: &str, org: &str, repo: &str) -> RepoCoord {
        RepoCoord {
            host: host.to_owned(),
            org: org.to_owned(),
            repo: repo.to_owned(),
        }
    }

    fn profile(name: &str, orgs: &[&str], catch_all: bool) -> TeamProfile {
        TeamProfile {
            name: name.to_owned(),
            orgs: orgs.iter().map(|o| (*o).to_owned()).collect(),
            catch_all,
        }
    }

    #[test]
    fn normalize_https_strips_git_and_lowercases_host() {
        assert_eq!(
            normalize_remote("https://GitHub.com/thenervelab/hippius-mem.git"),
            Some(coord("github.com", "thenervelab", "hippius-mem"))
        );
    }

    #[test]
    fn normalize_https_without_git_suffix() {
        assert_eq!(
            normalize_remote("https://github.com/thenervelab/hippius-mem"),
            Some(coord("github.com", "thenervelab", "hippius-mem"))
        );
    }

    #[test]
    fn normalize_scp_form() {
        assert_eq!(
            normalize_remote("git@github.com:thenervelab/hippius-mem.git"),
            Some(coord("github.com", "thenervelab", "hippius-mem"))
        );
    }

    #[test]
    fn normalize_ssh_scheme_form() {
        assert_eq!(
            normalize_remote("ssh://git@github.com/thenervelab/hippius-mem"),
            Some(coord("github.com", "thenervelab", "hippius-mem"))
        );
    }

    #[test]
    fn normalize_nested_path_keeps_top_org_and_last_repo() {
        // A GitLab-style subgroup path: routing must key on the top-level org, and
        // the repo is the final segment.
        assert_eq!(
            normalize_remote("https://gitlab.com/group/sub/repo.git"),
            Some(coord("gitlab.com", "group", "repo"))
        );
    }

    #[test]
    fn normalize_rejects_non_remotes() {
        // Single-segment (org only), local path, bare host, and junk are not
        // routable repo remotes.
        for bad in [
            "https://github.com/onlyorg",
            "git@github.com:onlyorg",
            "/local/path/to/repo",
            "github.com",
            "not a url",
            "",
        ] {
            assert_eq!(normalize_remote(bad), None, "expected None for {bad:?}");
        }
    }

    #[test]
    fn resolve_matched_org_binds_that_profile() {
        let profiles = [
            profile("ourovoros", &["github.com/thenervelab"], false),
            profile("personal", &[], true),
        ];
        let got = resolve(
            &profiles,
            Some("git@github.com:thenervelab/hippius-mem.git"),
        );
        assert_eq!(got, Resolution::Bound(&profiles[0]));
    }

    #[test]
    fn resolve_matches_a_single_repo_pattern() {
        let profiles = [profile(
            "one-repo",
            &["github.com/thenervelab/hippius-mem"],
            false,
        )];
        let hit = resolve(
            &profiles,
            Some("https://github.com/thenervelab/hippius-mem"),
        );
        assert_eq!(hit, Resolution::Bound(&profiles[0]));
        // A different repo in the same org is NOT covered by a repo-level pattern,
        // and with no catch-all it resolves to Unmatched.
        let miss = resolve(&profiles, Some("https://github.com/thenervelab/other"));
        assert_eq!(
            miss,
            Resolution::Disabled(DisabledReason::Unmatched(coord(
                "github.com",
                "thenervelab",
                "other"
            )))
        );
    }

    #[test]
    fn resolve_unmatched_falls_back_to_catch_all() {
        let profiles = [
            profile("ourovoros", &["github.com/thenervelab"], false),
            profile("personal", &[], true),
        ];
        let got = resolve(
            &profiles,
            Some("https://github.com/someoneelse/side-project"),
        );
        assert_eq!(got, Resolution::Bound(&profiles[1]));
    }

    #[test]
    fn resolve_unmatched_without_catch_all_is_disabled() {
        let profiles = [profile("ourovoros", &["github.com/thenervelab"], false)];
        let got = resolve(
            &profiles,
            Some("https://github.com/someoneelse/side-project"),
        );
        assert_eq!(
            got,
            Resolution::Disabled(DisabledReason::Unmatched(coord(
                "github.com",
                "someoneelse",
                "side-project"
            )))
        );
    }

    #[test]
    fn resolve_no_remote_binds_catch_all_when_present() {
        let profiles = [
            profile("ourovoros", &["github.com/thenervelab"], false),
            profile("personal", &[], true),
        ];
        assert_eq!(resolve(&profiles, None), Resolution::Bound(&profiles[1]));
    }

    #[test]
    fn resolve_no_remote_without_catch_all_is_disabled_no_remote() {
        let profiles = [profile("ourovoros", &["github.com/thenervelab"], false)];
        assert_eq!(
            resolve(&profiles, None),
            Resolution::Disabled(DisabledReason::NoRemote)
        );
    }

    #[test]
    fn resolve_first_matching_profile_wins() {
        // Two profiles claim the same org; the earlier one binds, so ordering in
        // the config is the tie-break.
        let profiles = [
            profile("first", &["github.com/thenervelab"], false),
            profile("second", &["github.com/thenervelab"], false),
        ];
        assert_eq!(
            resolve(&profiles, Some("https://github.com/thenervelab/x")),
            Resolution::Bound(&profiles[0])
        );
    }

    #[test]
    fn disabled_reason_messages_name_the_repo() {
        let unmatched =
            DisabledReason::Unmatched(coord("github.com", "someoneelse", "side")).to_string();
        assert!(
            unmatched.contains("github.com/someoneelse/side"),
            "message should name the repo: {unmatched}"
        );
        assert!(DisabledReason::NoRemote.to_string().contains("origin"));
    }

    #[test]
    fn git_remote_reader_reads_configured_origin() {
        let dir = tempfile::tempdir().expect("temp dir");
        run_git(dir.path(), &["init", "-q"]);
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/thenervelab/hippius-mem.git",
            ],
        );
        assert_eq!(
            GitRemoteReader.origin_url(dir.path()).as_deref(),
            Some("https://github.com/thenervelab/hippius-mem.git")
        );
    }

    #[test]
    fn git_remote_reader_none_without_origin() {
        let dir = tempfile::tempdir().expect("temp dir");
        run_git(dir.path(), &["init", "-q"]);
        assert_eq!(GitRemoteReader.origin_url(dir.path()), None);
    }

    fn run_git(dir: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?} failed");
    }

    proptest! {
        /// The three URL shapes for the same repo normalize to the same coord —
        /// the parser-agreement invariant. Charset is restricted so the tokens
        /// hold no `.git`/scheme/`:` that would fold into the parse.
        #[test]
        fn normalize_agrees_across_url_shapes(
            host in "[a-z0-9]{1,8}",
            org in "[a-z0-9]{1,8}",
            repo in "[a-z0-9]{1,8}",
        ) {
            let want = RepoCoord { host: host.clone(), org: org.clone(), repo: repo.clone() };
            let forms = [
                format!("https://{host}/{org}/{repo}.git"),
                format!("git@{host}:{org}/{repo}.git"),
                format!("ssh://git@{host}/{org}/{repo}"),
            ];
            for form in forms {
                let got = normalize_remote(&form);
                prop_assert_eq!(got.as_ref(), Some(&want));
            }
        }
    }
}
