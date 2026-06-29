//! rmcp MCP server exposing the nine Hippius Memory tools over stdio.
//!
//! The transport-facing `#[tool]` methods are deliberately thin: each parses
//! its parameters, delegates to a transport-free `logic_*` method, then funnels
//! the `Result` through [`into_call_result`]. Keeping the param -> core -> DTO
//! mapping in the `logic_*` methods (rather than inside the macro-generated
//! handlers) is what lets the unit tests exercise the full behavior without
//! standing up a client<->server round-trip.

use std::collections::BTreeSet;
use std::sync::Arc;

use hippius_mem_core::{
    AnchorProof, AnchorRef, Blake3Hash, HistoryEntry, MemError, MemoryStore, MerkleProof, Note,
    NoteHistory, NoteId, NoteType, ParseNoteIdError, ParseNoteTypeError, Pointer, RecallInput,
    ReconcileReport, RememberInput, RepoScope,
};
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Pointers returned by `recall` when the caller omits `k`.
///
/// Sized for the default dense model (`bge-small-en-v1.5`), which trades a
/// higher recall@floor for a compressed cosine band: the true match clears the
/// floor but is not always rank 1, so `recall` hands the LLM caller a slightly
/// wider window to re-rank rather than betting on a single top hit. Pointers are
/// body-free, so the extra width is cheap; `token_budget` still bounds the total.
const DEFAULT_RECALL_K: usize = 12;

/// Parameters for the `remember` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct RememberParams {
    /// Note kind: `decision`, `convention`, `gotcha`, `reference`, or `context`.
    note_type: String,
    /// Repository scope: `null` or `"global"` for team-global, else a repo name.
    #[serde(default)]
    repo: Option<String>,
    /// Free-form tags indexed alongside the summary.
    #[serde(default)]
    tags: Vec<String>,
    /// One-line summary surfaced by `recall`.
    summary: String,
    /// Full note body, returned only by `get`.
    body: String,
}

/// Parameters for the `recall` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct RecallParams {
    /// Natural-language query text.
    text: String,
    /// Repository scope: `null` or `"global"` for team-global, else a repo name.
    #[serde(default)]
    repo: Option<String>,
    /// Maximum number of pointers to return (default 8).
    #[serde(default)]
    k: Option<usize>,
    /// Optional cap on the summed estimated token cost of returned summaries.
    #[serde(default)]
    token_budget: Option<usize>,
}

/// Parameters for the `get` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct GetParams {
    /// The `mem_...` id of the note to fetch.
    id: String,
}

/// Parameters for the `refresh` tool: none. An empty object `{}` is accepted.
#[derive(Debug, Default, Deserialize, JsonSchema)]
struct RefreshParams {}

/// Parameters for the `forget` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct ForgetParams {
    /// The `mem_...` id of the note to tombstone.
    id: String,
}

/// Parameters for the `link` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct LinkParams {
    /// The `mem_...` id of the note the link points *from*.
    from: String,
    /// The `mem_...` id of the note the link points *to*.
    to: String,
}

/// Parameters for the `history` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct HistoryParams {
    /// The `mem_...` id of the note whose op history to return.
    id: String,
}

/// Parameters for the `reconcile` tool: none. An empty object `{}` is accepted.
#[derive(Debug, Default, Deserialize, JsonSchema)]
struct ReconcileParams {}

/// Parameters for the `edit` tool.
///
/// Only the fields the caller supplies are changed; omitted fields keep their
/// current value (the handler reads the note first and re-stores the merge).
#[derive(Debug, Deserialize, JsonSchema)]
struct EditParams {
    /// The `mem_...` id of the note to update.
    id: String,
    /// New one-line summary; omit to keep the current summary.
    #[serde(default)]
    summary: Option<String>,
    /// New full body; omit to keep the current body.
    #[serde(default)]
    body: Option<String>,
    /// New tag set (replaces the current tags); omit to keep the current tags.
    #[serde(default)]
    tags: Option<Vec<String>>,
    /// Optional compare-and-swap guard: the `version` you received from `get`. If
    /// set, the edit is refused (the note is left unchanged) when the note has
    /// changed since you read it — re-`get` to obtain the new version and retry.
    /// Omit for a plain last-writer-wins edit.
    #[serde(default)]
    expected_version: Option<String>,
}

/// Parameters for the `redact` tool.
#[derive(Debug, Deserialize, JsonSchema)]
struct RedactParams {
    /// The `mem_...` id of the note to permanently scrub.
    id: String,
}

/// Result of a successful `remember` call.
#[derive(Debug, Serialize)]
struct RememberOutput {
    /// The new note's `mem_...` id.
    id: String,
}

/// Result of a `recall` call.
///
/// `total_matched` is how many in-scope, relevant notes matched in total;
/// `returned` is how many pointers are in `pointers` after the `k`/token-budget
/// cap. When `returned < total_matched`, the caller saw only the head of a larger
/// result and can raise `k` (or relax the budget) to see more.
#[derive(Debug, Serialize)]
struct RecallOutput {
    /// The ranked pointers, summaries only — never bodies.
    pointers: Vec<PointerDto>,
    /// Total in-scope relevant matches before the `k`/budget cap.
    total_matched: usize,
    /// Number of pointers actually returned (`pointers.len()`).
    returned: usize,
}

/// Result of a successful `refresh` call.
#[derive(Debug, Serialize)]
struct RefreshOutput {
    /// Number of live notes indexed from the shared op-log during the sync.
    indexed: usize,
}

/// A search result surfaced by `recall`.
///
/// This DTO intentionally has no `body` field: `recall` returns pointers to
/// notes, never their contents — that is the whole point of the recall/get
/// split. Bodies are fetched separately via `get`. The absence is enforced at
/// compile time, mirroring the core [`Pointer`] type.
#[derive(Debug, Serialize)]
struct PointerDto {
    id: String,
    summary: String,
    score: f32,
    repo: String,
    author: String,
    updated: i64,
}

/// The full note returned by `get`, including its body.
#[derive(Debug, Serialize)]
struct NoteDto {
    id: String,
    note_type: String,
    repo: String,
    author: String,
    created: i64,
    updated: i64,
    tags: Vec<String>,
    summary: String,
    body: String,
    /// The current content version (hex content hash). Pass it back as
    /// `expected_version` on `edit` for a compare-and-swap that fails if the note
    /// changed since you read it.
    version: String,
}

/// Result of a successful `forget` call.
#[derive(Debug, Serialize)]
struct ForgetOutput {
    /// Always `true`: the note was tombstoned in the shared op-log.
    forgotten: bool,
}

/// Result of a successful `link` call.
#[derive(Debug, Serialize)]
struct LinkOutput {
    /// Always `true`: the directed link was appended to the shared op-log.
    linked: bool,
}

/// Result of a successful `edit` call.
#[derive(Debug, Serialize)]
struct EditOutput {
    /// Always `true`: a new note version was written and an Edit op appended.
    edited: bool,
}

/// Result of a successful `redact` call.
#[derive(Debug, Serialize)]
struct RedactOutput {
    /// Always `true`: a signed Redact op was appended and every ciphertext
    /// version of the note was scrubbed. Irreversible.
    redacted: bool,
}

/// The op history of a note, returned by `history`.
#[derive(Debug, Serialize)]
struct HistoryDto {
    /// The note this history describes.
    note_id: String,
    /// Whether the note's latest lifecycle op is a `Forget`.
    tombstoned: bool,
    /// Whether the note's content was permanently scrubbed by a `Redact` op. The
    /// op trail in `entries` survives and stays provable, but `get` returns no body.
    redacted: bool,
    /// The `mem_...` ids this note links to (converged `Link` targets).
    links: Vec<String>,
    /// Every op naming the note, in convergence order.
    entries: Vec<HistoryEntryDto>,
}

/// One op in a note's history, carrying its anchor proof once committed.
#[derive(Debug, Serialize)]
struct HistoryEntryDto {
    /// The op's unique id (a ULID).
    op_id: String,
    /// The author's SS58 address — the human-readable "who".
    ///
    /// Cryptographically bound to `author_key`: `read_all` rejects any op whose
    /// `author` does not decode to its `author_key`, so this is a verified
    /// identity (the readable form of `author_key`), not a self-asserted claim.
    author: String,
    /// Hex sr25519 public key the op's signature verifies against — the
    /// cryptographic "who". This is the identity `read_all` actually checked.
    author_key: String,
    /// The op's Lamport clock value.
    lamport: u64,
    /// The kind of mutation: `Remember`, `Edit`, `Forget`, or `Link`.
    kind: String,
    /// Hex content hash of the note's ciphertext at this op.
    cid: String,
    /// Hex hash of the op itself — the Merkle leaf to verify against.
    op_hash: String,
    /// The inclusion proof, or `null` while the op is pending anchoring.
    anchor: Option<AnchorProofDto>,
}

/// A Merkle inclusion proof binding an op to an anchored root.
///
/// A caller recomputes the Merkle path from `op_hash` (on the entry) and `proof`
/// and compares it to `root`. What that establishes depends on `reference`: with
/// an on-chain reference (`chain` anchoring) the verifier fetches the root from
/// the chain and compares it, so the result holds *without* trusting this server;
/// with a local reference (the default) both root and proof come from this
/// server's bucket, so the check is internal-consistency only — not a
/// trust-minimized proof. See the core `AnchorProof` docs for the distinction.
/// `reference` and `proof` reuse the core serde types verbatim: they are
/// already public, serde-shaped data records, so re-projecting them would add
/// drift risk without changing the wire shape.
#[derive(Debug, Serialize)]
struct AnchorProofDto {
    /// Hex Merkle root the op's batch was anchored under.
    root: String,
    /// Where `root` was anchored.
    reference: AnchorRef,
    /// The sibling path from the op's leaf up to `root`.
    proof: MerkleProof,
}

/// A failure surfaced to the MCP caller by one of the memory tools.
///
/// Both variants render as a user-visible `CallToolResult::error`, never a
/// JSON-RPC protocol error: per the MCP spec a tool that ran and produced a
/// fixable failure should return its message in the result so the caller reads
/// it (rmcp `ServerHandler::call_tool` docs). `BadInput` is a stable contract
/// callers may match on; `Mem` wraps the core error and exposes it via
/// `source()` through `#[error(transparent)]`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
enum HandlerError {
    /// A parameter could not be parsed into its typed core representation.
    #[error("invalid {field}: {detail}")]
    BadInput {
        /// Which parameter was rejected.
        field: &'static str,
        /// Why it was rejected.
        detail: String,
    },
    /// The core store rejected or failed the operation.
    #[error(transparent)]
    Mem(#[from] MemError),
}

/// The MCP server: nine memory tools backed by one shared [`MemoryStore`].
#[derive(Clone)]
pub(crate) struct MemoryServer {
    store: Arc<MemoryStore>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl MemoryServer {
    /// Build a server over `store`.
    pub(crate) fn new(store: Arc<MemoryStore>) -> Self {
        Self {
            store,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Store a durable team memory note the team will need later — a decision, convention, gotcha, reference, or context. Call this whenever you learn such a fact (not transient chatter); write one self-contained fact per note. Returns the new note id."
    )]
    async fn remember(&self, Parameters(params): Parameters<RememberParams>) -> CallToolResult {
        into_call_result(self.logic_remember(params).await)
    }

    #[tool(
        description = "Search team memory. Call this BEFORE starting a task or answering a question that may depend on a team decision, convention, or past gotcha — check memory rather than assuming. Returns ranked pointers (id, summary, score) — summaries only, never note bodies; open one with `get`."
    )]
    fn recall(&self, Parameters(params): Parameters<RecallParams>) -> CallToolResult {
        into_call_result(self.logic_recall(params))
    }

    #[tool(
        description = "Fetch the full note for an id, including its body and its current `version` (pass that back as `expected_version` on `edit` to avoid clobbering a concurrent change)."
    )]
    async fn get(&self, Parameters(params): Parameters<GetParams>) -> CallToolResult {
        into_call_result(self.logic_get(params).await)
    }

    #[tool(
        description = "Sync this machine's searchable index from the shared team op-log, pulling in teammates' latest notes and applying their tombstones. Returns the number of live notes indexed."
    )]
    async fn refresh(&self, Parameters(_params): Parameters<RefreshParams>) -> CallToolResult {
        into_call_result(self.logic_refresh().await)
    }

    #[tool(
        description = "Tombstone a note by id (logical delete). Appends a signed Forget op to the shared op-log and hides the note from recall. Returns { forgotten: true }."
    )]
    async fn forget(&self, Parameters(params): Parameters<ForgetParams>) -> CallToolResult {
        into_call_result(self.logic_forget(params).await)
    }

    #[tool(
        description = "Assert a directed link from one note to another by id. Appends a signed Link op to the shared op-log. Returns { linked: true }."
    )]
    async fn link(&self, Parameters(params): Parameters<LinkParams>) -> CallToolResult {
        into_call_result(self.logic_link(params).await)
    }

    #[tool(
        description = "Return the full op history of a note (who did what, in order). Each entry's author_key is the sr25519 key its signature was verified against (the cryptographic who); author is a self-asserted label. Once anchored, an op carries a Merkle inclusion proof: with on-chain (`chain`) anchoring a verifier compares the root against the chain to check the chain of custody without trusting this server; in the default local mode the proof shows only internal consistency against a root this server stored."
    )]
    async fn history(&self, Parameters(params): Parameters<HistoryParams>) -> CallToolResult {
        into_call_result(self.logic_history(params).await)
    }

    #[tool(
        description = "Audit the team memory: reconcile the visible op-log against the anchored Merkle roots. Reports any op anchored but now missing from the bucket and any anchor record whose root disagrees with its leaves. Returns { ok, checked_batches, total_anchored_ops, missing_ops, root_mismatches }. SCOPE: in the default local mode both the op-log AND the anchor records live in the same untrusted bucket, so this detects accidental or partial op-log loss but NOT adversarial suppression — a bucket that drops an op together with its anchor record leaves nothing to reconcile against and still reports ok. Trust-minimized suppression detection requires the `chain` feature plus chain readback (the root is read back from the chain, which the bucket cannot forge). Only ops that were actually anchored are covered; ops dropped before their batch anchored leave no commitment to check."
    )]
    async fn reconcile(&self, Parameters(_params): Parameters<ReconcileParams>) -> CallToolResult {
        into_call_result(self.logic_reconcile().await)
    }

    #[tool(
        description = "Update an existing note by id, keeping its identity and history. Provide any of summary, body, or tags to change them; omitted fields keep their current value. Optionally pass expected_version (the `version` from `get`) for a compare-and-swap that refuses the edit — returning a conflict, note unchanged — if it changed since you read it. Writes a new signed Edit op to the shared op-log, so teammates see the change after refresh. Returns { edited: true }."
    )]
    async fn edit(&self, Parameters(params): Parameters<EditParams>) -> CallToolResult {
        into_call_result(self.logic_edit(params).await)
    }

    #[tool(
        description = "Permanently scrub a note's content by id (leaked secret, PII, deletion request). Deletes every stored ciphertext version; the signed audit record of the redaction is kept and stays provable in `history`. IRREVERSIBLE and stronger than `forget` (which only hides the note but keeps the content for the audit trail) — use `forget` for ordinary deletion. Returns { redacted: true }."
    )]
    async fn redact(&self, Parameters(params): Parameters<RedactParams>) -> CallToolResult {
        into_call_result(self.logic_redact(params).await)
    }
}

impl MemoryServer {
    /// Parse, store, and report the new id. Transport-free for testability.
    async fn logic_remember(&self, params: RememberParams) -> Result<RememberOutput, HandlerError> {
        let note_type = parse_note_type(&params.note_type)?;
        let input = RememberInput {
            note_type,
            repo: parse_repo(params.repo.as_deref()),
            tags: params.tags.into_iter().collect::<BTreeSet<String>>(),
            summary: params.summary,
            body: params.body,
        };
        let id = self.store.remember(input).await?;
        Ok(RememberOutput { id: id.to_string() })
    }

    /// Search and map results to body-free pointer DTOs. Transport-free.
    fn logic_recall(&self, params: RecallParams) -> Result<RecallOutput, HandlerError> {
        let input = RecallInput {
            text: params.text,
            repo: parse_repo(params.repo.as_deref()),
            k: params.k.unwrap_or(DEFAULT_RECALL_K),
            token_budget: params.token_budget,
        };
        let result = self.store.recall(input)?;
        let pointers: Vec<PointerDto> = result.pointers.iter().map(pointer_to_dto).collect();
        Ok(RecallOutput {
            returned: pointers.len(),
            total_matched: result.total_matched,
            pointers,
        })
    }

    /// Sync the local index from the shared op-log and report the count.
    /// Transport-free.
    async fn logic_refresh(&self) -> Result<RefreshOutput, HandlerError> {
        let indexed = self.store.sync().await?;
        Ok(RefreshOutput { indexed })
    }

    /// Parse the id, hydrate the note, and map to a DTO. Transport-free.
    async fn logic_get(&self, params: GetParams) -> Result<NoteDto, HandlerError> {
        let id = parse_note_id(&params.id, "id")?;
        let note = self.store.get(id).await?;
        // The version token the agent round-trips into `edit`'s precondition: the
        // current ciphertext content hash, from the same converged index `get`
        // resolved the note through.
        let version = self.store.current_version(id)?.to_hex();
        Ok(note_to_dto(&note, version))
    }

    /// Parse the id and tombstone the note. Transport-free.
    async fn logic_forget(&self, params: ForgetParams) -> Result<ForgetOutput, HandlerError> {
        let id = parse_note_id(&params.id, "id")?;
        self.store.forget(id).await?;
        Ok(ForgetOutput { forgotten: true })
    }

    /// Parse both ids and assert the directed link. Transport-free.
    async fn logic_link(&self, params: LinkParams) -> Result<LinkOutput, HandlerError> {
        let from = parse_note_id(&params.from, "from")?;
        let to = parse_note_id(&params.to, "to")?;
        self.store.link(from, to).await?;
        Ok(LinkOutput { linked: true })
    }

    /// Parse the id, reconstruct the note's history, and map to a DTO.
    /// Transport-free.
    async fn logic_history(&self, params: HistoryParams) -> Result<HistoryDto, HandlerError> {
        let id = parse_note_id(&params.id, "id")?;
        let history = self.store.history(id).await?;
        Ok(history_to_dto(&history))
    }

    /// Reconcile the op-log against the anchored roots and return the report.
    /// Transport-free.
    ///
    /// The core [`ReconcileReport`] is already serde-shaped wire data (hashes
    /// render as hex, `AnchorRef` carries its own representation), so it is
    /// returned verbatim rather than re-projected onto a DTO — the same
    /// reuse-the-core-type rationale as [`AnchorProofDto`]'s `reference`/`proof`.
    async fn logic_reconcile(&self) -> Result<ReconcileReport, HandlerError> {
        Ok(self.store.reconcile().await?)
    }

    /// Parse the id, read the current note, merge the supplied fields, and
    /// re-store it as a new version. Transport-free.
    ///
    /// Reads the current note so an omitted parameter keeps its existing value;
    /// the core [`MemoryStore::edit`] then preserves `created` and the link set.
    async fn logic_edit(&self, params: EditParams) -> Result<EditOutput, HandlerError> {
        let id = parse_note_id(&params.id, "id")?;
        let current = self.store.get(id).await?;
        let input = RememberInput {
            note_type: current.note_type,
            repo: current.scope.repo,
            tags: match params.tags {
                Some(tags) => tags.into_iter().collect::<BTreeSet<String>>(),
                None => current.tags,
            },
            summary: params.summary.unwrap_or(current.summary),
            body: params.body.unwrap_or(current.body),
        };
        // Parse the optional CAS token at the boundary: a malformed hex version is
        // bad input, surfaced before the store is touched.
        let precondition = match params.expected_version.as_deref() {
            None => None,
            Some(hex) => Some(Blake3Hash::from_hex(hex).map_err(|err| HandlerError::BadInput {
                field: "expected_version",
                detail: err.to_string(),
            })?),
        };
        self.store.edit_with_precondition(id, input, precondition).await?;
        Ok(EditOutput { edited: true })
    }

    /// Parse the id and permanently scrub the note's content. Transport-free.
    async fn logic_redact(&self, params: RedactParams) -> Result<RedactOutput, HandlerError> {
        let id = parse_note_id(&params.id, "id")?;
        self.store.redact(id).await?;
        Ok(RedactOutput { redacted: true })
    }
}

// `router = self.tool_router` makes the generated `call_tool`/`list_tools` use
// the prebuilt field instead of the default `Self::tool_router()`, which would
// rebuild the router (and re-derive every tool's JSON schema) on each call.
#[tool_handler(router = self.tool_router)]
impl ServerHandler for MemoryServer {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` is `#[non_exhaustive]`, so it cannot be built with a
        // struct literal from this crate; start from the default and override
        // only the two fields we care about.
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Shared, verifiable team memory. RECALL BEFORE YOU ACT on anything that \
             might depend on a team decision, convention, or past gotcha — check \
             memory rather than assuming. REMEMBER durable facts the team will need \
             later (one self-contained fact per note). `recall` returns pointers \
             (summaries); `get` hydrates a full body — and its `version` — only when \
             you decide to open one. Tools: `remember` store a note; `recall` search; \
             `get` fetch a body by id; `refresh` pull teammates' latest notes into \
             this machine's searchable index; `forget` tombstone a note (hides it, \
             keeps the audit trail); `redact` permanently scrub a note's content \
             (irreversible — for secrets/PII); `link` relate two notes; `edit` update \
             a note in place (optionally compare-and-swap on `version`); `history` \
             audit a note's op history (links + independently verifiable anchor \
             proofs, and whether it was redacted); `reconcile` cross-check the \
             op-log against the anchored Merkle roots."
                .to_owned(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

/// Map the optional `repo` parameter to a [`RepoScope`].
///
/// `None` and the literal `"global"` both denote the team-global scope (the
/// segment the core uses for [`RepoScope::Global`]); any other string names a
/// repository. Inverse of [`repo_to_dto`] for every name except the reserved
/// `"global"` sentinel.
fn parse_repo(repo: Option<&str>) -> RepoScope {
    match repo {
        None | Some("global") => RepoScope::Global,
        Some(name) => RepoScope::Repo(name.to_owned()),
    }
}

/// Render a [`RepoScope`] as the string the DTOs and `parse_repo` agree on.
fn repo_to_dto(repo: &RepoScope) -> String {
    match repo {
        RepoScope::Global => "global".to_owned(),
        RepoScope::Repo(name) => name.clone(),
    }
}

/// Parse a `note_type` string into the core enum, reporting bad input.
fn parse_note_type(raw: &str) -> Result<NoteType, HandlerError> {
    raw.parse()
        .map_err(|e: ParseNoteTypeError| HandlerError::BadInput {
            field: "note_type",
            detail: e.to_string(),
        })
}

/// Parse a `mem_...` id, reporting a bad value against `field`.
///
/// Shared by every id-taking tool (`get`/`forget`/`history`, and each id of
/// `link`) so the `field` in a [`HandlerError::BadInput`] always names the
/// exact parameter the caller got wrong.
fn parse_note_id(raw: &str, field: &'static str) -> Result<NoteId, HandlerError> {
    raw.parse()
        .map_err(|e: ParseNoteIdError| HandlerError::BadInput {
            field,
            detail: e.to_string(),
        })
}

/// Project a core [`NoteHistory`] onto its wire DTO.
fn history_to_dto(history: &NoteHistory) -> HistoryDto {
    HistoryDto {
        note_id: history.note_id.to_string(),
        tombstoned: history.tombstoned,
        redacted: history.redacted,
        links: history.links.iter().map(NoteId::to_string).collect(),
        entries: history.entries.iter().map(history_entry_to_dto).collect(),
    }
}

/// Project one core [`HistoryEntry`] onto its wire DTO, rendering hashes as hex.
fn history_entry_to_dto(entry: &HistoryEntry) -> HistoryEntryDto {
    HistoryEntryDto {
        op_id: entry.op_id.clone(),
        author: entry.author.as_str().to_owned(),
        author_key: entry.author_key.to_hex(),
        lamport: entry.lamport,
        kind: entry.kind.as_str().to_owned(),
        cid: entry.cid.to_hex(),
        op_hash: entry.op_hash.to_hex(),
        anchor: entry.anchor.as_ref().map(anchor_to_dto),
    }
}

/// Project a core [`AnchorProof`] onto its wire DTO.
fn anchor_to_dto(anchor: &AnchorProof) -> AnchorProofDto {
    AnchorProofDto {
        root: anchor.root.to_hex(),
        reference: anchor.reference.clone(),
        proof: anchor.proof.clone(),
    }
}

/// Project a core [`Pointer`] onto the body-free wire DTO.
fn pointer_to_dto(pointer: &Pointer) -> PointerDto {
    PointerDto {
        id: pointer.note_id.to_string(),
        summary: pointer.summary.clone(),
        score: pointer.score,
        repo: repo_to_dto(&pointer.scope.repo),
        author: pointer.author.as_str().to_owned(),
        updated: pointer.updated.as_millis(),
    }
}

/// Project a core [`Note`] onto the full-note wire DTO. `version` is the note's
/// current content hash (hex), resolved by the caller from the same converged
/// index, and is the token an agent round-trips into `edit`'s precondition.
fn note_to_dto(note: &Note, version: String) -> NoteDto {
    NoteDto {
        id: note.id.to_string(),
        note_type: note.note_type.to_string(),
        repo: repo_to_dto(&note.scope.repo),
        author: note.author.as_str().to_owned(),
        created: note.created.as_millis(),
        updated: note.updated.as_millis(),
        tags: note.tags.iter().cloned().collect(),
        summary: note.summary.clone(),
        body: note.body.clone(),
        version,
    }
}

/// Render a handler result as a [`CallToolResult`].
///
/// `Ok` serializes to a single JSON text block; `Err` becomes a user-visible
/// `CallToolResult::error` carrying the failure message (the MCP-correct way to
/// surface a fixable failure, vs. an opaque protocol error). A serialization
/// failure is itself surfaced as a tool error rather than panicking, so no
/// handler path can abort the process.
fn into_call_result<T: Serialize>(result: Result<T, HandlerError>) -> CallToolResult {
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => CallToolResult::success(vec![Content::text(json)]),
            Err(err) => CallToolResult::error(vec![Content::text(format!(
                "failed to serialize tool result: {err}"
            ))]),
        },
        Err(err) => CallToolResult::error(vec![Content::text(err.to_string())]),
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on in-memory fixtures where construction cannot fail"
    )]

    use std::sync::Arc;

    use hippius_mem_core::RepoScope;
    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NetworkPrefix,
        NoopAnchor, OpLogStore, RecordingAnchor, SecretKey, Signer, Sr25519Signer,
    };

    /// Production anchor threshold; the server tests write below it, so anchoring
    /// stays inert and does not perturb the recall/get assertions.
    const ANCHOR_THRESHOLD: usize = 16;
    use proptest::prelude::*;

    use super::{
        HandlerError, MemoryServer, RecallParams, RememberParams, parse_repo, repo_to_dto,
    };

    /// A signer whose author SS58 is derived from its seed, so every op it mints
    /// passes the op-log identity binding.
    fn test_signer() -> Arc<dyn Signer> {
        Arc::new(
            Sr25519Signer::from_seed_with_prefix(&[5u8; 32], NetworkPrefix::HIPPIUS)
                .expect("valid test seed"),
        )
    }

    fn test_server() -> MemoryServer {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let key = SecretKey::from_bytes([7u8; 32]);
        let oplog = OpLogStore::new(blob.clone());
        let signer = test_signer();
        let store = MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            std::collections::BTreeMap::from([(0_u64, key)]),
            0,
            "test-team".to_owned(),
            ANCHOR_THRESHOLD,
        );
        MemoryServer::new(Arc::new(store))
    }

    /// A server whose anchor threshold is 1 and whose sink records every batch,
    /// so every op anchors immediately and its history entry carries a proof.
    fn anchoring_server() -> MemoryServer {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let key = SecretKey::from_bytes([7u8; 32]);
        let oplog = OpLogStore::new(blob.clone());
        let signer = test_signer();
        let store = MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(RecordingAnchor::new()),
            signer,
            std::collections::BTreeMap::from([(0_u64, key)]),
            0,
            "test-team".to_owned(),
            1,
        );
        MemoryServer::new(Arc::new(store))
    }

    fn sample_remember() -> RememberParams {
        RememberParams {
            note_type: "decision".to_owned(),
            repo: Some("widgets".to_owned()),
            tags: vec!["db".to_owned(), "schema".to_owned()],
            summary: "use ULID primary keys for the widgets table".to_owned(),
            body: "We chose ULID over auto-increment for global sortability.".to_owned(),
        }
    }

    #[tokio::test]
    async fn remember_returns_mem_id() {
        let server = test_server();
        let out = server.logic_remember(sample_remember()).await.unwrap();
        assert!(out.id.starts_with("mem_"), "id was {}", out.id);
    }

    #[tokio::test]
    async fn recall_returns_pointers_without_body() {
        let server = test_server();
        server.logic_remember(sample_remember()).await.unwrap();

        let out = server
            .logic_recall(RecallParams {
                text: "ULID primary keys widgets".to_owned(),
                repo: Some("widgets".to_owned()),
                k: None,
                token_budget: None,
            })
            .unwrap();

        assert!(out.returned >= 1, "expected at least one pointer");
        assert_eq!(out.returned, out.pointers.len());
        assert!(out.total_matched >= out.returned);
        // Assert on the serialized JSON: that is the exact wire shape the caller
        // sees, and the contract is "summaries yes, bodies never".
        let json = serde_json::to_value(&out).unwrap();
        assert!(json.get("total_matched").is_some());
        assert!(json.get("returned").is_some());
        let first = &json.get("pointers").unwrap().as_array().unwrap()[0];
        assert!(
            first.get("summary").is_some(),
            "pointer must carry a summary"
        );
        assert!(first.get("body").is_none(), "pointer must NOT carry a body");
        assert!(first.get("id").is_some());
        assert!(first.get("score").is_some());
    }

    #[tokio::test]
    async fn get_returns_full_note_with_body() {
        let server = test_server();
        let id = server.logic_remember(sample_remember()).await.unwrap().id;

        let note = server
            .logic_get(super::GetParams { id: id.clone() })
            .await
            .unwrap();

        assert_eq!(note.id, id);
        assert_eq!(note.note_type, "decision");
        assert_eq!(note.repo, "widgets");
        assert!(note.body.contains("ULID"), "body should round-trip");
        let json = serde_json::to_value(&note).unwrap();
        assert!(json.get("body").is_some(), "get must carry the body");
        assert!(json.get("tags").is_some());
    }

    #[tokio::test]
    async fn bad_note_type_is_a_handler_error_not_a_panic() {
        let server = test_server();
        let mut params = sample_remember();
        params.note_type = "not-a-real-type".to_owned();
        let err = server.logic_remember(params).await.unwrap_err();
        assert!(matches!(
            err,
            HandlerError::BadInput {
                field: "note_type",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn bad_id_is_a_handler_error_not_a_panic() {
        let server = test_server();
        let err = server
            .logic_get(super::GetParams {
                id: "not-a-mem-id".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::BadInput { field: "id", .. }));
    }

    #[tokio::test]
    async fn missing_note_id_maps_to_mem_error() {
        let server = test_server();
        // A well-formed but absent id parses fine, then fails in the core as NotFound.
        let absent = hippius_mem_core::NoteId::new().to_string();
        let err = server
            .logic_get(super::GetParams { id: absent })
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::Mem(_)));
    }

    #[test]
    fn none_and_global_map_to_global_scope() {
        assert_eq!(parse_repo(None), RepoScope::Global);
        assert_eq!(parse_repo(Some("global")), RepoScope::Global);
        assert_eq!(
            parse_repo(Some("widgets")),
            RepoScope::Repo("widgets".to_owned())
        );
    }

    #[test]
    fn server_advertises_ten_tools() {
        let router = MemoryServer::tool_router();
        let names: Vec<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert_eq!(names.len(), 10, "names were {names:?}");
        for expected in [
            "remember",
            "recall",
            "get",
            "refresh",
            "forget",
            "link",
            "history",
            "reconcile",
            "edit",
            "redact",
        ] {
            assert!(names.contains(&expected.to_owned()), "missing {expected}");
        }
    }

    #[tokio::test]
    async fn forget_marks_note_forgotten() {
        let server = test_server();
        let id = server.logic_remember(sample_remember()).await.unwrap().id;

        let out = server
            .logic_forget(super::ForgetParams { id: id.clone() })
            .await
            .unwrap();
        assert!(out.forgotten);

        // A forgotten note is no longer recallable.
        let recalled = server
            .logic_recall(RecallParams {
                text: "ULID primary keys widgets".to_owned(),
                repo: Some("widgets".to_owned()),
                k: None,
                token_budget: None,
            })
            .unwrap();
        assert_eq!(recalled.returned, 0, "forgotten note must not recall");
    }

    #[tokio::test]
    async fn forget_bad_id_is_a_handler_error() {
        let server = test_server();
        let err = server
            .logic_forget(super::ForgetParams {
                id: "not-a-mem-id".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::BadInput { field: "id", .. }));
    }

    #[tokio::test]
    async fn link_links_two_notes() {
        let server = test_server();
        let from = server.logic_remember(sample_remember()).await.unwrap().id;
        let mut second = sample_remember();
        second.repo = None;
        let to = server.logic_remember(second).await.unwrap().id;

        let out = server
            .logic_link(super::LinkParams { from, to })
            .await
            .unwrap();
        assert!(out.linked);
    }

    #[tokio::test]
    async fn link_bad_id_is_a_handler_error() {
        let server = test_server();
        let from = server.logic_remember(sample_remember()).await.unwrap().id;
        // `from` parses, `to` does not: the error must name `to`.
        let err = server
            .logic_link(super::LinkParams {
                from,
                to: "not-a-mem-id".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::BadInput { field: "to", .. }));
    }

    #[tokio::test]
    async fn edit_updates_via_handler() {
        let server = test_server();
        let id = server.logic_remember(sample_remember()).await.unwrap().id;

        let out = server
            .logic_edit(super::EditParams {
                id: id.clone(),
                summary: Some("new summary".to_owned()),
                body: Some("new body text".to_owned()),
                tags: None,
                expected_version: None,
            })
            .await
            .unwrap();
        assert!(out.edited);

        let note = server
            .logic_get(super::GetParams { id: id.clone() })
            .await
            .unwrap();
        assert_eq!(note.summary, "new summary");
        assert_eq!(note.body, "new body text");
        // Omitted `tags` keep the original note's tags.
        assert!(
            note.tags.contains(&"db".to_owned()),
            "omitted tags are preserved: {:?}",
            note.tags
        );
    }

    #[tokio::test]
    async fn edit_bad_id_is_a_handler_error() {
        let server = test_server();
        let err = server
            .logic_edit(super::EditParams {
                id: "not-a-mem-id".to_owned(),
                summary: None,
                body: None,
                tags: None,
                expected_version: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::BadInput { field: "id", .. }));
    }

    #[tokio::test]
    async fn history_returns_ordered_entries() {
        let server = test_server();
        let id = server.logic_remember(sample_remember()).await.unwrap().id;
        server
            .logic_forget(super::ForgetParams { id: id.clone() })
            .await
            .unwrap();

        let dto = server
            .logic_history(super::HistoryParams { id: id.clone() })
            .await
            .unwrap();
        assert_eq!(dto.note_id, id);
        assert!(dto.tombstoned);
        assert_eq!(dto.entries.len(), 2);
        assert_eq!(dto.entries[0].kind, "Remember");
        assert_eq!(dto.entries[1].kind, "Forget");
        // Below the test server's anchor threshold, nothing is anchored yet.
        assert!(dto.entries[0].anchor.is_none());

        // I3: every entry surfaces author_key (the verified crypto "who") as 64
        // hex chars, distinct from the self-asserted SS58 `author` label.
        assert_eq!(
            dto.entries[0].author_key.len(),
            64,
            "author_key is a 32-byte key rendered as 64 hex chars"
        );

        // The wire shape carries the op hash a caller needs to verify inclusion,
        // plus author_key for the cryptographic identity.
        let json = serde_json::to_value(&dto).unwrap();
        let first = &json.get("entries").unwrap().as_array().unwrap()[0];
        assert!(first.get("op_hash").is_some());
        assert!(
            first.get("author_key").is_some(),
            "the wire entry carries author_key (the verified identity)"
        );
        assert!(
            first.get("anchor").is_some(),
            "anchor key is always present"
        );
    }

    #[tokio::test]
    async fn history_dto_includes_links() {
        let server = test_server();
        let from = server.logic_remember(sample_remember()).await.unwrap().id;
        let mut second = sample_remember();
        second.repo = None;
        let to = server.logic_remember(second).await.unwrap().id;
        server
            .logic_link(super::LinkParams {
                from: from.clone(),
                to: to.clone(),
            })
            .await
            .unwrap();

        let dto = server
            .logic_history(super::HistoryParams { id: from })
            .await
            .unwrap();
        assert!(dto.links.contains(&to), "history links surface the target");
        // The wire shape carries `links`.
        let json = serde_json::to_value(&dto).unwrap();
        assert!(
            json.get("links").is_some(),
            "history wire shape carries links"
        );
    }

    #[tokio::test]
    async fn history_bad_id_is_a_handler_error() {
        let server = test_server();
        let err = server
            .logic_history(super::HistoryParams {
                id: "not-a-mem-id".to_owned(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, HandlerError::BadInput { field: "id", .. }));
    }

    #[tokio::test]
    async fn history_dto_carries_verifiable_anchor() {
        // Threshold-1 server: the op anchors immediately, so its DTO entry
        // carries a full proof object the caller can verify independently.
        let server = anchoring_server();
        let id = server.logic_remember(sample_remember()).await.unwrap().id;

        let dto = server
            .logic_history(super::HistoryParams { id })
            .await
            .unwrap();
        assert_eq!(dto.entries.len(), 1);
        let anchor = dto.entries[0]
            .anchor
            .as_ref()
            .expect("a threshold-1 op is anchored");
        let json = serde_json::to_value(anchor).unwrap();
        assert!(json.get("root").is_some(), "proof carries the root");
        assert!(
            json.get("reference").is_some(),
            "proof carries the anchor ref"
        );
        assert!(
            json.get("proof").is_some(),
            "proof carries the sibling path"
        );
    }

    #[tokio::test]
    async fn reconcile_reports_clean_anchored_log() {
        // Threshold-1 server: every remembered op is anchored, so reconcile sees a
        // fully-covered, clean log and reports ok with the anchored-op count.
        let server = anchoring_server();
        server.logic_remember(sample_remember()).await.unwrap();
        server.logic_remember(sample_remember()).await.unwrap();

        let report = server.logic_reconcile().await.unwrap();
        assert!(report.ok, "a clean anchored log reconciles ok: {report:?}");
        assert!(report.missing_ops.is_empty());
        assert!(report.root_mismatches.is_empty());
        assert_eq!(report.total_anchored_ops, 2);

        // The wire shape an MCP caller reads.
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(
            json.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(json.get("checked_batches").is_some());
        assert!(json.get("missing_ops").is_some());
        assert!(json.get("root_mismatches").is_some());
    }

    #[tokio::test]
    async fn refresh_pulls_in_notes_from_a_shared_blob_layer() {
        // Two servers (two machines) share ONE blob layer and team key but keep
        // independent indexes — the real cross-machine topology. Machine A writes
        // a note; machine B cannot recall it until it `refresh`es its index from
        // the shared bucket.
        let blob = Arc::new(MemoryBlobStore::default());
        let key_bytes = [7_u8; 32];
        let team = "test-team".to_owned();

        let machine = |b: Arc<dyn BlobStore>| {
            let oplog = OpLogStore::new(b.clone());
            MemoryServer::new(Arc::new(MemoryStore::new(
                b,
                Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default()))),
                oplog,
                Arc::new(NoopAnchor),
                test_signer(),
                std::collections::BTreeMap::from([(0_u64, SecretKey::from_bytes(key_bytes))]),
                0,
                team.clone(),
                ANCHOR_THRESHOLD,
            )))
        };
        let server_b = machine(blob.clone() as Arc<dyn BlobStore>);
        let server_a = machine(blob as Arc<dyn BlobStore>);

        server_a.logic_remember(sample_remember()).await.unwrap();

        let recall = || {
            server_b.logic_recall(RecallParams {
                text: "ULID primary keys widgets".to_owned(),
                repo: Some("widgets".to_owned()),
                k: None,
                token_budget: None,
            })
        };

        // Before refresh, B's index is empty: nothing to recall.
        assert_eq!(recall().unwrap().returned, 0);

        // refresh rebuilds B's index from the shared bucket.
        let refreshed = server_b.logic_refresh().await.unwrap();
        assert_eq!(
            refreshed.indexed, 1,
            "exactly A's one note lives in the bucket"
        );

        // Now B can recall A's note.
        assert!(
            recall().unwrap().returned >= 1,
            "B should see A's note after refresh"
        );
    }

    proptest! {
        // Every repo name except the reserved "global" sentinel round-trips
        // through the DTO projection: parse_repo is the inverse of repo_to_dto.
        #[test]
        fn repo_dto_round_trips(name in ".*") {
            prop_assume!(name != "global");
            let scope = RepoScope::Repo(name);
            let dto = repo_to_dto(&scope);
            prop_assert_eq!(parse_repo(Some(&dto)), scope);
        }
    }
}
