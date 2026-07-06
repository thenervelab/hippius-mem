# Dashboard Phase 1 (read-only) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** A read-only `hippius-mem dashboard` command that serves a local
browse / search / health view over the team's shared memory in a browser.

**Architecture:** A new opt-in `dashboard` cargo feature pulls `axum`. A
`dashboard` module builds an `axum::Router` over the same `Arc<MemoryStore>` the
MCP server uses, bound to `127.0.0.1` only and guarded by a per-launch random
token. Reads reuse the existing store paths; browse needs one new core read
method (`list_records`). `main.rs` dispatches the `dashboard` subcommand like the
existing `console`-gated ones. No write path in Phase 1.

**Tech Stack:** axum 0.8, tower 0.5 (test `oneshot`), tokio (`net`), the existing
`hippius-mem-core` `MemoryStore` + `IndexRecord`.

**Design source:** `docs/plans/2026-07-06-hippius-mem-dashboard-design.md`
(Sections 1, 2, 5, 6 — Phase 1 slice). Style reference: illu-rs
`src/server/dashboard.rs` + `dashboard.html`.

---

## Conventions

- Every Rust task follows the repo's Rust gates: before the first edit in a
  session run `mcp__illu__rust_preflight`, consult `mcp__illu__project_style` +
  `mcp__illu__decisions`, and before final answer run `mcp__illu__quality_gate`.
  Also call `mcp__hippius-mem__recall` before the first edit and
  `mcp__hippius-mem__remember` any durable gotcha.
- Commit after each task. Feature branch only (already in a worktree).
- All new `dashboard`-feature code sits behind `#[cfg(feature = "dashboard")]`;
  the default build must not compile axum.
- Test store-dependent routes over an in-memory `MemoryStore` (`MemoryBlobStore`
  + `HashEmbedder`) — the existing test seam — so no live S3 is needed.

---

## Task 1: Core read path — `MemoryStore::list_records`

Browse needs to enumerate every in-scope note without a query; `recall` only
ranks against a query, so add an enumeration path. `IndexRecord` is body-free
(summary only), so exposing records is safe for a local dashboard.

**Files:**
- Modify: `hippius-mem-core/src/index/mod.rs` (add `all_records` to `MemoryIndex`
  + `InMemoryIndex`)
- Modify: `hippius-mem-core/src/store/mod.rs` (add `MemoryStore::list_records`)
- Test: same files' `#[cfg(test)]` modules

**Step 1 — failing test (index):** in `index/mod.rs` tests, assert `all_records`
returns exactly the upserted records (body-free), order-independent:

```rust
#[test]
fn all_records_returns_every_upserted_record() -> TestResult {
    let index = InMemoryIndex::with_hash_embedder();
    let a = record("team", RepoScope::Global, NoteType::Decision, "alpha", 1)?;
    let b = record("team", RepoScope::Global, NoteType::Gotcha, "beta", 2)?;
    index.upsert(a.clone())?;
    index.upsert(b.clone())?;
    let got: BTreeSet<NoteId> = index.all_records()?.into_iter().map(|r| r.note_id).collect();
    assert_eq!(got, BTreeSet::from([a.note_id, b.note_id]));
    Ok(())
}
```

**Step 2 — run, expect fail:** `cargo test -p hippius-mem-core --lib all_records_returns` → FAIL (no `all_records`).

**Step 3 — implement.** Add to the `MemoryIndex` trait:

```rust
/// Return a clone of every indexed record (body-free — records carry only the
/// summary). This is the enumeration primitive the local dashboard's browse
/// view needs; it is NOT a retrieval path (no ranking, no scope filter) — the
/// caller filters. Order is unspecified.
fn all_records(&self) -> Result<Vec<IndexRecord>, MemError>;
```

Impl on `InMemoryIndex`:

```rust
fn all_records(&self) -> Result<Vec<IndexRecord>, MemError> {
    let guard = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
    Ok(guard.values().map(|entry| entry.record.clone()).collect())
}
```

(No default impl — a required capability; any future `MemoryIndex` impl must
provide it.)

**Step 4 — store delegate** in `store/mod.rs`:

```rust
/// Every note currently in this machine's index, body-free, for local
/// enumeration (the dashboard browse view). Reads the converged index as-is —
/// call `sync`/`refresh_if_stale` first for freshness.
pub fn list_records(&self) -> Result<Vec<IndexRecord>, MemError> {
    self.index.all_records()
}
```

**Step 5 — store test** through the public ingestion path (`remember` + `sync`,
per axiom 111): remember two notes, `list_records()`, assert both summaries present.

**Step 6 — run:** `cargo test -p hippius-mem-core` → PASS; `cargo clippy -p hippius-mem-core --all-targets -- -D warnings` → clean.

**Step 7 — commit:** `git commit -am "core: add list_records enumeration for the dashboard browse view"`

---

## Task 2: Binary — `dashboard` feature + axum deps

**Files:** Modify `hippius-mem/Cargo.toml`

**Step 1 — add deps/feature.** Under `[dependencies]`:

```toml
# Local dashboard HTTP server — pulled in ONLY by the `dashboard` feature.
# `dep:` keeps the optional crate from leaking an implicit feature; the default
# stdio MCP binary never compiles axum. It binds loopback and speaks plain HTTP.
axum = { version = "0.8", optional = true }
```

Add `"net"` to the existing tokio features (axum needs `TcpListener`):
`tokio = { version = "1.52.3", features = ["rt-multi-thread", "macros", "net"] }`

Under `[features]`:

```toml
# The local `hippius-mem dashboard` command (axum browse/search/health UI). Off
# by default so the stdio MCP binary stays lean; enable with
# `--features dashboard`.
dashboard = ["dep:axum"]
```

Under `[dev-dependencies]`: `tower = "0.5"` (for `ServiceExt::oneshot` route tests).

**Step 2 — verify both build shapes compile:**
- `cargo build -p hippius-mem` (default — axum absent) → OK
- `cargo build -p hippius-mem --features dashboard` → OK

**Step 3 — commit:** `git commit -am "binary: add opt-in dashboard feature + axum dep"`

---

## Task 3: Dashboard module — state, token guard, router skeleton

**Files:**
- Create: `hippius-mem/src/dashboard/mod.rs`
- Modify: `hippius-mem/src/main.rs` (add `#[cfg(feature = "dashboard")] mod dashboard;`)

**Step 1 — failing test (token guard rejects a bad/absent token):**

```rust
#[tokio::test]
async fn missing_token_is_unauthorized() {
    let app = router(test_state("secret-token"));
    let res = app
        .oneshot(Request::builder().uri("/api/overview").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn correct_token_is_authorized() {
    let app = router(test_state("secret-token"));
    let res = app
        .oneshot(Request::builder().uri("/api/overview?t=secret-token").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}
```

`test_state(token)` builds a `DashboardState` over an in-memory `MemoryStore`
(reuse the `test_store()` pattern from `server.rs` tests — extract it to a shared
test helper or duplicate minimally).

**Step 2 — run, expect fail** (module/router absent).

**Step 3 — implement `dashboard/mod.rs`:**

```rust
//! The local read-only dashboard: an axum server over the shared `MemoryStore`,
//! bound to loopback and guarded by a per-launch token. It serves DECRYPTED
//! summaries, so it must never leave `127.0.0.1` and never run without the token.
use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{Next, from_fn_with_state},
    response::{Html, IntoResponse, Json, Response},
    routing::get,
};
use hippius_mem_core::MemoryStore;
use serde::Serialize;

/// Shared state: the store the routes read, plus the launch token every request
/// must present. `Clone` is cheap (an `Arc` + an `Arc<str>`), as axum requires.
#[derive(Clone)]
pub(crate) struct DashboardState {
    pub store: Arc<MemoryStore>,
    /// Per-launch random token; every route is gated on it (query `?t=` or the
    /// `X-Dashboard-Token` header). Not a secret at rest — a session capability.
    pub token: Arc<str>,
}

/// Build the router. Split from `run` so tests drive it via `oneshot` without a
/// live socket.
pub(crate) fn router(state: DashboardState) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/api/overview", get(overview))
        .route("/api/notes", get(list_notes))
        .route("/api/notes/{id}", get(get_note))
        .route("/api/health", get(health))
        .layer(from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

/// Reject any request that does not present the launch token. The plaintext this
/// server returns is why this gate is mandatory, not optional.
async fn require_token(State(state): State<DashboardState>, req: Request, next: Next) -> Response {
    let presented = req
        .uri()
        .query()
        .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("t=").map(str::to_owned)))
        .or_else(|| {
            req.headers()
                .get("x-dashboard-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });
    if presented.as_deref() == Some(state.token.as_ref()) {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "missing or invalid dashboard token").into_response()
    }
}
```

**Step 4 — run, expect pass.**

**Step 5 — commit:** `git commit -am "dashboard: state, loopback token guard, router skeleton"`

---

## Task 4: Routes + DTOs

**Files:** Modify `hippius-mem/src/dashboard/mod.rs`

Implement the four handlers. DTOs are dashboard-local `Serialize` structs (browse
needs `note_type`/`tags` that the recall `PointerDto` lacks).

**Step 1 — failing tests:** for each of `overview`, `list_notes`, `get_note`,
`health`, assert the JSON shape over a store seeded with one `remember`. Example
for browse:

```rust
#[tokio::test]
async fn list_notes_returns_seeded_note() {
    let state = test_state("t");
    state.store.remember(sample_remember_input()).await.unwrap();
    let app = router(state);
    let res = app.oneshot(get_req("/api/notes?t=t")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(res).await;
    assert_eq!(body["notes"].as_array().unwrap().len(), 1);
    assert_eq!(body["notes"][0]["note_type"], "decision");
}
```

**Step 2 — run, expect fail.**

**Step 3 — implement handlers:**

```rust
/// One browse row — body-free. `note_type`/`tags` power the browse filters the
/// recall `PointerDto` does not carry.
#[derive(Serialize)]
struct NoteRow {
    id: String,
    summary: String,
    note_type: String,
    repo: String,
    author: String,
    updated: i64,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct OverviewDto {
    team: String,
    note_count: usize,
    semantic: bool, // cfg!(feature = "embeddings") && semantic_embeddings
    notes: Vec<NoteRow>,
}

async fn index_html() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

/// The one-shot browse payload: refresh first (best-effort), then enumerate.
async fn overview(State(state): State<DashboardState>) -> Result<Json<OverviewDto>, ApiError> {
    let _ = state.store.refresh_if_stale().await; // best-effort freshness
    let rows = rows_from(&state)?;
    Ok(Json(OverviewDto {
        team: state.store.team().to_owned(),
        note_count: rows.len(),
        semantic: state.store.is_semantic(),
        notes: rows,
    }))
}
```

`list_notes` applies optional `type`/`repo`/`tag`/`q` filters to the enumeration;
`q` delegates to `store.recall` (ranked) when present, else returns the filtered
enumeration. `get_note` calls `store.get(id)` + `store.history(id)` and maps to a
detail DTO. `health` returns sync/semantic/reconcile status. Add a small
`ApiError` (`impl IntoResponse`) mapping `MemError` → 404 (`NotFound`) / 500
(else) with a JSON body — typed per `decision_2026_04_27_error_categories`, not
a stringly `format!`.

> NOTE (Task 4a): `MemoryStore` may need trivial read accessors (`team()`,
> `is_semantic()`). Add them as getters in `store/mod.rs` if absent, TDD.

**Step 4 — run, expect pass; clippy clean.**

**Step 5 — commit:** `git commit -am "dashboard: overview/list/get/health routes + DTOs"`

---

## Task 5: `dashboard.html`

**Files:** Create `hippius-mem/src/dashboard/dashboard.html`

A single self-contained page (inline CSS + vanilla JS — no build, no CDN),
modeled on illu-rs `src/server/dashboard.html`. It:
- reads the token from its own `?t=` URL and sends it on every `fetch`;
- `GET /api/overview` on load → renders the note table + a semantic/lexical badge
  + the team name;
- client-side filter inputs (type, repo, tag, search) that re-query `/api/notes`;
- row click → `GET /api/notes/:id` → detail drawer (body, tags, history, links);
- a Health panel from `/api/health`.

UI, not logic — no unit test; verified with the `/verify` skill (load the page,
drive the flow). Keep the data contract EXACTLY as the Task 4 DTOs.
Commit: `git commit -am "dashboard: self-contained browse/health HTML"`

---

## Task 6: Wire the `dashboard` subcommand in `main.rs`

**Files:** Modify `hippius-mem/src/main.rs`

**Step 1 — dispatch (mirror the `console`/`mint-token` gating):** after the other
subcommand checks, before the server boot:

```rust
#[cfg(feature = "dashboard")]
if subcommand == Some("dashboard") {
    return dashboard::run(&args[2..]).await;
}
#[cfg(not(feature = "dashboard"))]
if subcommand == Some("dashboard") {
    anyhow::bail!("the `dashboard` subcommand requires building with `--features dashboard`");
}
```

**Step 2 — implement `dashboard::run`** (in `dashboard/mod.rs`): load config,
resolve the profile (reuse `resolver::resolve` + `TeamProfile::build_store` exactly
as the server boot does), `store.sync().await` (best-effort — the dashboard is not
latency-critical), generate a 16-byte token via a CSPRNG → hex, bind
`tokio::net::TcpListener` on `127.0.0.1:0` (or `--port`), print
`http://127.0.0.1:<port>/?t=<token>` to stderr, and
`axum::serve(listener, router(state)).await`.

> Token RNG: use the SAME CSPRNG path the installer uses for `author_seed_hex`
> (or `getrandom`). Never a non-crypto RNG.

**Step 3 — manual verify (`/verify` skill):** `cargo run -p hippius-mem --features dashboard,embeddings -- dashboard`, open the printed URL, confirm the table renders and a wrong `?t=` is rejected (401).

**Step 4 — commit:** `git commit -am "main: wire the dashboard subcommand (feature-gated)"`

---

## Task 7: Feature-matrix guard + final gate

**Step 1 — verify all build/lint shapes:**
```bash
cargo clippy -p hippius-mem --all-targets -- -D warnings                       # default (no axum)
cargo clippy -p hippius-mem --features dashboard --all-targets -- -D warnings   # +axum
cargo clippy -p hippius-mem --features dashboard,embeddings --all-targets -- -D warnings
cargo test -p hippius-mem --features dashboard
cargo test -p hippius-mem-core
```
**Step 2 — run `mcp__illu__quality_gate`** with the plan/impact/tests evidence.

**Step 3 — remember any durable gotcha** (`mcp__hippius-mem__remember`), e.g. an
axum-0.8 path-param syntax surprise (`{id}`, not `:id`).

**Step 4 — open the PR** to `main` (`gh pr create`), review, merge.

---

## Out of scope (Phase 1)

- Curation writes (edit/forget/redact/link) — Phase 2.
- Recall telemetry lane — Phase 3 (needs `serve`-side plumbing).
- Activity op-log team feed — Phase 1.5 or with Phase 2.
- Team switcher across `[[teams]]` — Phase 1 binds the resolved profile; add the
  switcher when curation lands.
