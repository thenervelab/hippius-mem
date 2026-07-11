//! The `SessionStart` brief: a deterministic, tiered, token-bounded digest of the
//! team's live memory.
//!
//! Recall is pull-only — an agent must already suspect a fact exists to query for
//! it, so the highest-value memories (a gotcha you do not know to look for) are
//! exactly the ones recall misses. The brief closes that gap by compiling the
//! live set into a short digest injected at session start.
//!
//! Selection is **pure and LLM-free**: a fixed tiering by [`NoteType`] plus a
//! recency sort, so the same converged set always renders the same brief (two
//! machines agree, and it is testable). It reads only the `summary` the index
//! already holds — never a note body.

use crate::domain::{NoteType, RepoScope, Scope};
use crate::index::IndexRecord;

/// Estimated tokens for `text` (~4 chars/token), matching the index's own budget
/// accounting ([`crate::index`]'s `estimate_tokens`) so the brief's cap means the
/// same thing recall's `token_budget` does.
fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

/// The repo a record lives in, as a compact label for the brief.
fn repo_label(scope: &Scope) -> &str {
    match &scope.repo {
        RepoScope::Global => "global",
        RepoScope::Repo(name) => name.as_str(),
    }
}

/// Order a tier newest-first, then by note id — a total, reproducible order so the
/// brief is deterministic for a given converged set.
fn by_recency(records: &mut [&IndexRecord]) {
    records.sort_by(|a, b| {
        b.updated
            .as_millis()
            .cmp(&a.updated.as_millis())
            .then(a.note_id.cmp(&b.note_id))
    });
}

/// Render the live `records` into a tiered markdown brief within `token_budget`.
///
/// Tiers, in order of durability: **Conventions + Decisions** (the rules a session
/// should not relearn), then **Gotchas** (pitfalls) newest-first, then a compact
/// one-line index of everything else. Lines are appended until the running token
/// estimate would exceed `token_budget`; because tiers are filled in order, a
/// tight budget drops the compressible tail (the index tier) first and always
/// keeps the rules. Returns an empty string for an empty live set, so a caller
/// (the `SessionStart` hook) injects nothing rather than a bare header.
#[must_use]
pub fn render_brief(records: &[IndexRecord], token_budget: usize) -> String {
    if records.is_empty() {
        return String::new();
    }

    let mut rules: Vec<&IndexRecord> = Vec::new();
    let mut gotchas: Vec<&IndexRecord> = Vec::new();
    let mut rest: Vec<&IndexRecord> = Vec::new();
    for record in records {
        match record.note_type {
            NoteType::Convention | NoteType::Decision => rules.push(record),
            NoteType::Gotcha => gotchas.push(record),
            NoteType::Reference | NoteType::Context => rest.push(record),
        }
    }
    by_recency(&mut rules);
    by_recency(&mut gotchas);
    by_recency(&mut rest);

    let header = "# Team memory brief\n\nThe team's live conventions, decisions, and gotchas — prefer these over re-deciding.\n";
    let mut out = String::new();
    let mut used = estimate_tokens(header);
    if used > token_budget {
        return String::new();
    }
    out.push_str(header);

    push_section(
        &mut out,
        &mut used,
        token_budget,
        "Conventions & decisions",
        &rules,
        false,
    );
    push_section(
        &mut out,
        &mut used,
        token_budget,
        "Gotchas",
        &gotchas,
        false,
    );
    push_section(&mut out, &mut used, token_budget, "More", &rest, true);
    out
}

/// Append a titled section of `items`, respecting `token_budget` against the
/// running `used` count. A `compact` section drops the type/repo prefix to fit
/// more one-liners. Skips the whole section (title included) if even the title
/// would overflow, and stops mid-section at the first line that would — a greedy
/// prefix, so higher-priority tiers appended earlier keep their claim on budget.
fn push_section(
    out: &mut String,
    used: &mut usize,
    token_budget: usize,
    title: &str,
    items: &[&IndexRecord],
    compact: bool,
) {
    if items.is_empty() {
        return;
    }
    let title_line = format!("\n## {title}\n");
    if *used + estimate_tokens(&title_line) > token_budget {
        return;
    }
    *used += estimate_tokens(&title_line);
    out.push_str(&title_line);

    for record in items {
        let line = if compact {
            format!("- {}\n", record.summary)
        } else {
            format!(
                "- [{}] ({}) {}\n",
                record.note_type,
                repo_label(&record.scope),
                record.summary
            )
        };
        let cost = estimate_tokens(&line);
        if *used + cost > token_budget {
            break;
        }
        *used += cost;
        out.push_str(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Blake3Hash, NoteId, Ss58, Timestamp};
    use std::collections::BTreeSet;

    // The crate denies `panic_in_result_fn`, so `Result`-returning fixtures report
    // failures by returning `Err`, not via `assert!`.
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ensure(cond: bool, msg: &str) -> TestResult {
        if cond { Ok(()) } else { Err(msg.into()) }
    }

    fn rec(
        note_type: NoteType,
        repo: RepoScope,
        summary: &str,
        updated: i64,
    ) -> Result<IndexRecord, Box<dyn std::error::Error>> {
        Ok(IndexRecord {
            note_id: NoteId::new(),
            object_key: "team/repo/mem/ver_0".to_string(),
            cid: Blake3Hash::new([0_u8; 32]),
            scope: Scope {
                team: "team".to_string(),
                repo,
            },
            note_type,
            author: Ss58::new("5".repeat(48))?,
            updated: Timestamp::new(updated),
            lamport: 0,
            key_epoch: 0,
            tags: BTreeSet::new(),
            summary: summary.to_string(),
        })
    }

    #[test]
    fn empty_live_set_renders_nothing() {
        assert!(render_brief(&[], 1500).is_empty());
    }

    #[test]
    fn conventions_and_decisions_precede_gotchas_precede_the_rest() -> TestResult {
        let records = vec![
            rec(
                NoteType::Reference,
                RepoScope::Global,
                "a reference link",
                1,
            )?,
            rec(NoteType::Gotcha, RepoScope::Global, "a nasty pitfall", 2)?,
            rec(
                NoteType::Convention,
                RepoScope::Repo("thebrain".to_string()),
                "always use uv",
                3,
            )?,
        ];
        let brief = render_brief(&records, 1500);
        let conv = brief
            .find("Conventions & decisions")
            .ok_or("rules section")?;
        let got = brief.find("Gotchas").ok_or("gotchas section")?;
        let more = brief.find("More").ok_or("more section")?;
        ensure(conv < got && got < more, "tiers are ordered by durability")?;
        // The convention carries its type + repo tag; the reference is compact.
        ensure(
            brief.contains("- [convention] (thebrain) always use uv"),
            "a rule keeps its type + repo tag",
        )?;
        ensure(
            brief.contains("- a reference link"),
            "a low-priority note is a compact one-liner",
        )
    }

    #[test]
    fn gotchas_are_ordered_newest_first() -> TestResult {
        let records = vec![
            rec(NoteType::Gotcha, RepoScope::Global, "older gotcha", 10)?,
            rec(NoteType::Gotcha, RepoScope::Global, "newer gotcha", 20)?,
        ];
        let brief = render_brief(&records, 1500);
        let newer = brief.find("newer gotcha").ok_or("newer present")?;
        let older = brief.find("older gotcha").ok_or("older present")?;
        ensure(newer < older, "the newest gotcha comes first")
    }

    #[test]
    fn a_tight_budget_keeps_rules_and_drops_the_index_tier() -> TestResult {
        let records = vec![
            rec(NoteType::Convention, RepoScope::Global, "keep this rule", 5)?,
            rec(
                NoteType::Reference,
                RepoScope::Global,
                "a droppable low-priority reference note with a long summary",
                6,
            )?,
        ];
        // Budget large enough for the header + the rule, too small for the long
        // low-priority reference that follows it.
        let brief = render_brief(&records, 60);
        ensure(
            brief.contains("keep this rule"),
            "the rule survives the budget",
        )?;
        ensure(
            !brief.contains("droppable"),
            "the low-priority index tier is dropped first under a tight budget",
        )
    }

    #[test]
    fn render_is_deterministic_and_bounded() -> TestResult {
        let records = vec![
            rec(NoteType::Decision, RepoScope::Global, "decide x", 3)?,
            rec(NoteType::Gotcha, RepoScope::Global, "gotcha y", 2)?,
            rec(NoteType::Context, RepoScope::Global, "context z", 1)?,
        ];
        let a = render_brief(&records, 1500);
        let b = render_brief(&records, 1500);
        ensure(a == b, "same converged set renders an identical brief")?;
        ensure(
            estimate_tokens(&a) <= 1500,
            "the brief respects its token budget",
        )
    }
}
