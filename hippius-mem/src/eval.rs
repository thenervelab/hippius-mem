//! The `eval` subcommand: measure recall quality against the bound team's REAL
//! vault, so a ranking change is judged by numbers from the corpus agents query.
//!
//! The labelled corpus in `hippius-mem-core/tests/shared/calibration_corpus.rs`
//! is a few dozen hand-written summaries. A live vault holds thousands of notes
//! written by agents, and ranking behaves differently there: an unrelated query
//! finds some note sharing a word with it. This command needs no labels and no
//! model beyond the one recall already uses. It measures two things.
//!
//! **Known-item.** Recall indexes a note's summary and tags, never its body. So
//! a sentence taken from a note's body, one that does not restate the summary,
//! is a query written in different words whose right answer is known: the note
//! it came from. The rank of that note is the measurement.
//!
//! **Off-topic.** A fixed list of queries about subjects a software team's vault
//! does not hold, asked as an agent in the launch repository would ask them.
//! Every pointer returned for one is noise. A strong match among them means the
//! strong-match threshold sits too low for this vault, and the relevance of the
//! best one next to the relevance of a found note shows how far apart they are.
//!
//! # What the numbers do not show
//!
//! A body sentence is a stand-in for an agent's query, not a sample of real
//! queries: it shares its author's vocabulary with the summary, so known-item
//! results flatter the ranker. Compare two runs on the same vault; do not read
//! one run as an absolute quality score. A vault that does hold notes on an
//! off-topic subject makes those probes report false noise.
//!
//! # Read-only
//!
//! The gateway is wrapped in [`InstrumentedBlobStore::read_only`], as `profile`
//! does. Every body is fetched BEFORE the first recall, because a `get` that
//! follows a `recall` of the same note appends a signed `Reinforce` op: the
//! measurement must not record itself as reuse.

use std::fmt::Write as _;
use std::sync::Arc;

use anyhow::Context;
use hippius_mem_core::{
    InstrumentedBlobStore, MemoryStore, NoteId, RecallInput, RepoScope, SearchResult,
};

use crate::config::Config;

/// Notes sampled when `--sample` is omitted. Arbitrary: enough that one note
/// moves a percentage by half a point, few enough that the body fetches finish
/// in about a minute against the gateway.
const DEFAULT_SAMPLE: usize = 200;

/// Pointers requested per recall: the MCP `recall` tool's default
/// (`DEFAULT_RECALL_K` in `server.rs`), the window an agent reads.
const RECALL_K: usize = 12;

/// Fewest words a body sentence needs to serve as a query. Arbitrary: shorter
/// sentences are headings and fragments ("Fix:", "See below").
const MIN_QUERY_WORDS: usize = 6;

/// Most words of a body sentence used as the query. Arbitrary: about the length
/// of a question an agent asks.
const MAX_QUERY_WORDS: usize = 24;

/// Queries about subjects a software team's vault does not hold.
const OFF_TOPIC_QUERIES: &[&str] = &[
    "sourdough starter hydration ratio for rye bread",
    "how long to rest a brisket after smoking it",
    "best pruning time for apple trees in a cold climate",
    "fingering for a two octave melodic minor scale on the cello",
    "offside rule when the goalkeeper leaves the penalty area",
    "wax temperature for cross country skis on fresh snow",
    "how to repot an orchid without damaging the roots",
    "knitting gauge for a fisherman rib scarf in merino wool",
    "tide tables and moon phases for surf fishing",
    "glaze firing schedule for stoneware in an electric kiln",
    "how to trim a horse's hooves between farrier visits",
    "sonnet rhyme scheme petrarchan versus shakespearean",
];

/// A query whose right answer is known: `query` came from the body of `id`.
#[derive(Debug)]
struct KnownItem {
    id: NoteId,
    repo: RepoScope,
    query: String,
}

/// What one off-topic query returned.
#[derive(Debug, Clone, Copy)]
struct OffTopic {
    returned: usize,
    /// Pointers the index marked strong.
    strong: usize,
    top_relevance: Option<f32>,
}

/// The measurement, before rendering.
#[derive(Debug)]
struct Report {
    /// Live notes in the converged index.
    live: usize,
    /// Sampled notes whose body was fetched.
    read: usize,
    /// Sampled notes this machine could not open.
    unreadable: usize,
    /// For each sampled note with a usable body sentence: the 1-based rank of
    /// the note in its own query's results, or `None` when it was not returned.
    ranks: Vec<Option<usize>>,
    /// Relevance of the note itself for each known-item query that returned
    /// it: what the strong-match threshold should sit below.
    found_relevance: Vec<f32>,
    off_topic: Vec<OffTopic>,
}

/// Build the bound profile's store read-only, measure it, and print the report.
///
/// # Errors
///
/// Returns an error for bad arguments, a missing or invalid config, a repository
/// that routes to no team, a store that cannot be built or synced, a vault none
/// of whose sampled notes can be read, or a recall that fails.
pub(crate) async fn run(args: &[String]) -> anyhow::Result<()> {
    let sample = parse_sample(args)?;

    let cfg = Config::from_env_and_file().context("failed to load the hippius-mem config")?;
    let (profile, launch_repo) = crate::resolve_profile(&cfg)?;
    let (store, _blob) = profile
        .build_store_layered(&cfg, |backend| {
            Arc::new(InstrumentedBlobStore::read_only(backend))
        })
        .await
        .context("failed to build the store for this profile")?;
    crate::profile::bootstrap_key_ring(&store, cfg.max_epoch).await;
    store
        .sync()
        .await
        .context("failed to sync the index from the op-log")?;

    let repo = hippius_mem::server::parse_repo(launch_repo.as_deref());
    let report = evaluate(&store, sample, &repo).await?;
    let title = format!(
        "hippius-mem eval: team {:?}, {}, read-only",
        profile.name,
        crate::profile::retrieval_mode(&store)
    );
    crate::profile::write_stdout(&render(&title, &report));
    Ok(())
}

/// Parse `[--sample N]`.
fn parse_sample(args: &[String]) -> anyhow::Result<usize> {
    match args {
        [] => Ok(DEFAULT_SAMPLE),
        [flag, value] if flag == "--sample" => {
            let sample: usize = value
                .parse()
                .with_context(|| format!("--sample takes a whole number (got {value:?})"))?;
            anyhow::ensure!(sample > 0, "--sample must be at least 1");
            Ok(sample)
        }
        _ => anyhow::bail!("usage: hippius-mem eval [--sample N]"),
    }
}

/// Measure `store`'s recall over up to `sample` of its notes, and the off-topic
/// probes as an agent in `repo` would ask them. Reads the index as it is: the
/// caller syncs first.
async fn evaluate(store: &MemoryStore, sample: usize, repo: &RepoScope) -> anyhow::Result<Report> {
    let mut records = store.list_records()?;
    // `list_records` is unordered. Sorting by id, then taking evenly spaced
    // notes, makes two runs on the same vault sample the same notes.
    records.sort_by_key(|record| record.note_id);
    let live = records.len();
    let stride = live.div_ceil(sample).max(1);

    let mut read = 0_usize;
    let mut unreadable = 0_usize;
    let mut items = Vec::new();
    for record in records.iter().step_by(stride) {
        // A note this machine cannot open (an epoch key it was never given, a
        // blob the bucket lost) is not a recall failure, so it is counted apart.
        let Ok(note) = store.get(record.note_id).await else {
            unreadable += 1;
            continue;
        };
        read += 1;
        if let Some(query) = known_item_query(&note.summary, &note.body) {
            items.push(KnownItem {
                id: record.note_id,
                repo: record.scope.repo.clone(),
                query,
            });
        }
    }
    // Every fetch failing is an outage or a missing key, and a report of zeros
    // would read as a ranking collapse.
    anyhow::ensure!(
        read > 0 || unreadable == 0,
        "none of the {unreadable} sampled notes could be read; check the gateway and this \
         machine's keys with `hippius-mem doctor`"
    );

    let mut ranks = Vec::with_capacity(items.len());
    let mut found_relevance = Vec::new();
    for item in &items {
        let result = recall(store, &item.query, item.repo.clone())?;
        let found = result
            .pointers
            .iter()
            .enumerate()
            .find(|(_, pointer)| pointer.note_id == item.id);
        if let Some((_, pointer)) = found {
            found_relevance.push(pointer.relevance);
        }
        ranks.push(found.map(|(index, _)| index + 1));
    }

    let mut off_topic = Vec::with_capacity(OFF_TOPIC_QUERIES.len());
    for query in OFF_TOPIC_QUERIES {
        let result = recall(store, query, repo.clone())?;
        off_topic.push(OffTopic {
            returned: result.pointers.len(),
            strong: result
                .pointers
                .iter()
                .filter(|pointer| pointer.strong)
                .count(),
            top_relevance: result
                .pointers
                .iter()
                .map(|pointer| pointer.relevance)
                .max_by(f32::total_cmp),
        });
    }

    Ok(Report {
        live,
        read,
        unreadable,
        ranks,
        found_relevance,
        off_topic,
    })
}

/// An agent's recall: the same call, window and weak-match cap the MCP tool
/// uses. Nothing here follows it with a `get`, so it records no reuse.
fn recall(store: &MemoryStore, text: &str, repo: RepoScope) -> anyhow::Result<SearchResult> {
    store
        .recall(RecallInput {
            text: text.to_owned(),
            repo,
            k: RECALL_K,
            token_budget: None,
        })
        .context("recall failed")
}

/// The first sentence of `body` usable as a query for its own note, or `None`.
///
/// A sentence is usable when it has at least [`MIN_QUERY_WORDS`] words and fewer
/// than half of them appear in `summary`. The second condition is the point: a
/// body that opens by repeating the summary would make the query a keyword copy
/// of the indexed text, which any ranker finds.
fn known_item_query(summary: &str, body: &str) -> Option<String> {
    let summary_words: Vec<String> = words(summary).collect();
    body.split(['\n', '.', '!', '?', ';'])
        .map(str::trim)
        .find_map(|sentence| {
            let sentence_words: Vec<String> = words(sentence).collect();
            if sentence_words.len() < MIN_QUERY_WORDS {
                return None;
            }
            let shared = sentence_words
                .iter()
                .filter(|word| summary_words.contains(word))
                .count();
            if shared * 2 >= sentence_words.len() {
                return None;
            }
            let query: Vec<&str> = sentence.split_whitespace().take(MAX_QUERY_WORDS).collect();
            Some(query.join(" "))
        })
}

/// Lowercased alphanumeric runs of `text`.
fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|piece| !piece.is_empty())
        .map(str::to_lowercase)
}

/// The value `percent` of the way through `values` in ascending order (`50` is
/// the median, `100` the largest), or `None` when empty.
fn percentile(values: &[f32], percent: usize) -> Option<f32> {
    let mut sorted = values.to_vec();
    sorted.sort_by(f32::total_cmp);
    let last = sorted.len().checked_sub(1)?;
    sorted.get(last * percent.min(100) / 100).copied()
}

/// `part` of `whole` as a whole percentage; `0` when `whole` is `0`.
fn percent(part: usize, whole: usize) -> usize {
    (part * 100).checked_div(whole).unwrap_or(0)
}

/// Mean of `1 / rank` over `ranks`, counting a note that was not returned as 0.
#[expect(
    clippy::cast_precision_loss,
    reason = "ranks are at most the recall window and counts at most the sample; f64 represents both exactly"
)]
fn mean_reciprocal_rank(ranks: &[Option<usize>]) -> f64 {
    if ranks.is_empty() {
        return 0.0;
    }
    let sum: f64 = ranks.iter().flatten().map(|&rank| 1.0 / rank as f64).sum();
    sum / ranks.len() as f64
}

fn render(title: &str, report: &Report) -> String {
    let usable = report.ranks.len();
    let within = |limit: usize| {
        report
            .ranks
            .iter()
            .flatten()
            .filter(|&&rank| rank <= limit)
            .count()
    };
    let missed = report.ranks.iter().filter(|rank| rank.is_none()).count();

    let mut out = String::new();
    // Writing to a `String` cannot fail.
    let _ = writeln!(out, "{title}");
    let _ = writeln!(
        out,
        "{} live notes; {} bodies read, {} unreadable; {usable} had a usable sentence\n",
        report.live, report.read, report.unreadable
    );

    let _ = writeln!(out, "known-item: a body sentence must recall its own note");
    for (label, count) in [
        ("rank 1".to_owned(), within(1)),
        ("top 5".to_owned(), within(5)),
        (format!("top {RECALL_K}"), within(RECALL_K)),
        ("not returned".to_owned(), missed),
    ] {
        let _ = writeln!(
            out,
            "  {label:<22} {count:>5}  {:>3}%",
            percent(count, usable)
        );
    }
    let _ = writeln!(
        out,
        "  {:<22} {:>9.3}\n",
        "mean reciprocal rank",
        mean_reciprocal_rank(&report.ranks)
    );

    let probes = report.off_topic.len();
    let answered = report
        .off_topic
        .iter()
        .filter(|probe| probe.returned > 0)
        .count();
    let pointers: usize = report.off_topic.iter().map(|probe| probe.returned).sum();
    let strong: usize = report.off_topic.iter().map(|probe| probe.strong).sum();
    let _ = writeln!(
        out,
        "off-topic: {probes} queries about subjects a team vault does not hold"
    );
    let _ = writeln!(
        out,
        "  {:<38} {answered:>3} of {probes}",
        "queries that returned any pointer"
    );
    let _ = writeln!(out, "  {:<38} {pointers:>3}", "pointers returned in total");
    let _ = writeln!(out, "  {:<38} {strong:>3}\n", "of those, strong matches");

    // The two distributions the strong-match threshold has to separate.
    let off_topic_tops: Vec<f32> = report
        .off_topic
        .iter()
        .filter_map(|probe| probe.top_relevance)
        .collect();
    let _ = writeln!(out, "relevance, before recency and reuse");
    for (label, values) in [
        ("found note", &report.found_relevance),
        ("best off-topic pointer", &off_topic_tops),
    ] {
        if let (Some(low), Some(mid), Some(high)) = (
            percentile(values, 10),
            percentile(values, 50),
            percentile(values, 100),
        ) {
            let _ = writeln!(
                out,
                "  {label:<22} 10th percentile {low:.2}  median {mid:.2}  highest {high:.2}"
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Result-returning tests use `?` for setup but still assert on outcomes"
    )]

    use std::collections::{BTreeMap, BTreeSet};

    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, NetworkPrefix, NoopAnchor,
        NoteType, OpLogStore, RememberInput, SecretKey, Signer, Sr25519Signer,
    };

    use super::*;

    const AUTHOR: [u8; 32] = [3_u8; 32];
    const READER: [u8; 32] = [5_u8; 32];

    fn store_over(blob: Arc<dyn BlobStore>, seed: &[u8; 32]) -> anyhow::Result<MemoryStore> {
        let signer: Arc<dyn Signer> = Arc::new(Sr25519Signer::from_seed_with_prefix(
            seed,
            NetworkPrefix::HIPPIUS,
        )?);
        Ok(MemoryStore::new(
            Arc::clone(&blob),
            Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
            OpLogStore::new(blob),
            Arc::new(NoopAnchor),
            signer,
            BTreeMap::from([(0_u64, SecretKey::from_bytes([7_u8; 32]))]),
            0,
            "eval-team".to_owned(),
            usize::MAX,
        ))
    }

    async fn remember(store: &MemoryStore, summary: &str, body: &str) -> anyhow::Result<NoteId> {
        Ok(store
            .remember(RememberInput {
                force: true,
                note_type: NoteType::Gotcha,
                repo: RepoScope::Repo("svc".to_owned()),
                tags: BTreeSet::new(),
                summary: summary.to_owned(),
                body: body.to_owned(),
            })
            .await?)
    }

    fn svc() -> RepoScope {
        RepoScope::Repo("svc".to_owned())
    }

    /// The whole measurement over a real store, as a reader that never wrote.
    ///
    /// Catches three bugs: a note in a repository being queried in the wrong
    /// scope (it would never be found), a body that restates its summary being
    /// counted as a query, and the evaluation fetching a body after recalling
    /// its note, which appends a reuse op and so raises every sampled note's
    /// rank for the whole team. The meter counts refused puts too, so a single
    /// attempted reuse op fails the last assertion.
    #[tokio::test]
    async fn measures_a_vault_without_attempting_a_write() -> anyhow::Result<()> {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(Arc::clone(&bucket), &AUTHOR)?;
        remember(
            &writer,
            "uploader retry budget capped at three attempts",
            "Raising the retry budget past three made the uploader hammer a gateway that was already shedding load.",
        )
        .await?;
        remember(
            &writer,
            "listing index is rebuilt by a nightly trigger",
            "listing index is rebuilt by a nightly trigger on the primary.",
        )
        .await?;
        // A checkpoint already in the bucket, so the reader's sync has none of
        // its own to attempt and every put the meter sees is the evaluation's.
        writer.sync().await?;

        let meter = Arc::new(InstrumentedBlobStore::read_only(Arc::clone(&bucket)));
        let reader = store_over(Arc::<InstrumentedBlobStore>::clone(&meter), &READER)?;
        reader.sync().await?;
        let synced = meter.stats();
        let report = evaluate(&reader, 10, &svc()).await?;

        assert_eq!((report.live, report.read, report.unreadable), (2, 2, 0));
        assert_eq!(
            report.ranks,
            vec![Some(1)],
            "only the first note's body says something its summary does not, and its \
             sentence shares `retry`, `budget`, `three` and `uploader` with that summary"
        );
        assert_eq!(report.found_relevance.len(), 1);
        assert!(
            report.off_topic.iter().all(|probe| probe.returned == 0),
            "no probe shares a content word with either note: {:?}",
            report.off_topic
        );
        assert_eq!(
            meter.stats().since(&synced).put.calls,
            0,
            "the evaluation attempted a write"
        );
        Ok(())
    }

    /// Catches an outage being reported as a table of zeros.
    #[tokio::test]
    async fn refuses_to_report_when_no_sampled_note_can_be_read() -> anyhow::Result<()> {
        let bucket: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let writer = store_over(Arc::clone(&bucket), &AUTHOR)?;
        remember(&writer, "a note", "whose body the reader cannot open").await?;

        let reader = store_over(Arc::clone(&bucket), &READER)?;
        reader.sync().await?;
        for key in bucket.list("eval-team/svc/").await? {
            bucket.delete(&key).await?;
        }

        let error = evaluate(&reader, 10, &svc())
            .await
            .err()
            .context("every body is gone, so the evaluation must refuse")?;
        assert!(
            error.to_string().contains("none of the 1 sampled notes"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn known_item_query_skips_fragments_and_restatements() {
        let summary = "uploader retry budget capped at three attempts";
        assert_eq!(
            known_item_query(
                summary,
                "Fix: see below.\nThe uploader retry budget is capped at three attempts."
            ),
            None,
            "a fragment is too short and the second sentence restates the summary"
        );
        assert_eq!(
            known_item_query(
                summary,
                "Fix: see below. The gateway was already shedding load when this happened; more text"
            )
            .as_deref(),
            Some("The gateway was already shedding load when this happened"),
        );
    }

    #[test]
    fn known_item_query_is_capped_at_the_word_limit() {
        let body = (0..MAX_QUERY_WORDS + 10)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let query = known_item_query("unrelated summary", &body);
        assert_eq!(
            query.map(|query| query.split_whitespace().count()),
            Some(MAX_QUERY_WORDS)
        );
    }

    /// Catches a report that divides by the sampled count, not the usable one,
    /// and a missed note being dropped from the mean instead of counted as 0.
    #[test]
    fn render_reports_ranks_against_usable_queries() {
        let report = Report {
            live: 50,
            read: 10,
            unreadable: 2,
            ranks: vec![Some(1), Some(4), Some(9), None],
            found_relevance: vec![0.5, 0.3, 0.2],
            off_topic: vec![
                OffTopic {
                    returned: 4,
                    strong: 1,
                    top_relevance: Some(0.6),
                },
                OffTopic {
                    returned: 0,
                    strong: 0,
                    top_relevance: None,
                },
            ],
        };
        let text = render("title", &report);

        assert!(
            text.contains("50 live notes; 10 bodies read, 2 unreadable; 4 had a usable sentence"),
            "{text}"
        );
        assert!(
            text.contains("rank 1                     1   25%"),
            "{text}"
        );
        assert!(
            text.contains("top 5                      2   50%"),
            "{text}"
        );
        assert!(
            text.contains("not returned               1   25%"),
            "{text}"
        );
        // (1 + 1/4 + 1/9 + 0) / 4
        assert!(text.contains("0.340"), "{text}");
        assert!(text.contains("  1 of 2"), "{text}");
        assert!(
            text.contains("of those, strong matches                 1"),
            "{text}"
        );
        assert!(
            text.contains("best off-topic pointer 10th percentile 0.60"),
            "{text}"
        );
    }

    #[test]
    fn parse_sample_accepts_only_a_positive_count() -> anyhow::Result<()> {
        let args = |list: &[&str]| list.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
        assert_eq!(parse_sample(&[])?, DEFAULT_SAMPLE);
        assert_eq!(parse_sample(&args(&["--sample", "40"]))?, 40);
        assert!(parse_sample(&args(&["--sample", "0"])).is_err());
        assert!(parse_sample(&args(&["--sample", "many"])).is_err());
        assert!(parse_sample(&args(&["--verbose"])).is_err());
        Ok(())
    }
}
