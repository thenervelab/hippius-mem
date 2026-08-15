# Dashboard inspect console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `hippius-mem dashboard` into a hardened, read-only inspect/audit console: integrity first, paginated notes, MCP-parity search, no token in the address bar.

**Architecture:** Keep axum + one embedded HTML document. Add a bootstrap/session token pair (cookie + Host/Origin/CSP), per-vault store lock, inspect APIs (reconcile, doctor, refresh, report `?since=`), then split the page and land `#/vault/<name>` on inspect home.

**Tech Stack:** axum 0.8, tower 0.5 (`oneshot`), existing `MemoryStore` / `ReconcileReport` / `build_report`. No new crates. Cookie and CSP are raw headers.

**Spec:** `docs/plans/2026-08-15-dashboard-inspect-console-design.md`

## Global Constraints

- Feature `dashboard` only; default stdio binary must not link axum.
- Installer / dist stay `--features embeddings,dashboard`.
- `store_for` still calls `admin::bootstrap_epochs` (mnemonic-gated).
- Reconcile/report numbers are the core types, not dashboard copies.
- `#![forbid(unsafe_code)]`, `cargo fmt`, `clippy --all-targets --all-features -- -D warnings`.
- Tests: `tower` `oneshot`, in-memory `MemoryStore` + `HashEmbedder`. No live S3, no browser.
- No remember/edit/forget/redact/link routes.
- Recall before the first edit; remember durable gotchas.
- Commits: user's git identity only, no `Co-Authored-By`. Why, not only what.
- Branch: `feat/dashboard-inspect-console` off `main`. Never commit these PRs on `main` directly.
- TDD: failing test first for every behavior change.

## File map

| File | Responsibility |
|---|---|
| `hippius-mem/src/dashboard/mod.rs` | Router, auth, handlers, tests (grows, then HTML extract in Task 12) |
| `hippius-mem/src/dashboard/dashboard.html` | Served UI (split in Task 12, still one document) |
| `hippius-mem/src/dashboard/page.html` | HTML shell with `__CSP_NONCE__` placeholders (Task 12) |
| `hippius-mem/src/dashboard/styles.css` | Extracted CSS (Task 12) |
| `hippius-mem/src/dashboard/app.js` | Extracted JS (Task 12) |
| `hippius-mem/src/doctor.rs` | Structured offline/live doctor report (Task 8) |
| `hippius-mem-core/src/index/mod.rs` | `MemoryIndex::len` + `get` (Task 5) |
| `hippius-mem-core/src/store/mod.rs` | `MemoryStore::index_len` + `index_get` (Task 5) |
| `docs/REFERENCE.md` | Operator-facing dashboard section (Task 14) |
| `docs/INVARIANTS.md` | `I-DASH-*` rows (Task 14) |

---

## PR 1 — Security foundation

### Task 1: Session vs bootstrap tokens + Host gate

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`DashboardState`, `require_token`, `router`, `run`, tests)

**Interfaces:**
- Consumes: existing `generate_token()`, `router(state)`, `test_state(token)`
- Produces:
  - `DashboardState { session: Arc<str>, bootstrap: Arc<std::sync::Mutex<Option<Arc<str>>>>, launched_at: Instant, bound_port: u16, ... }`
  - Session TTL constant `SESSION_TTL: Duration = Duration::from_secs(30 * 60)`
  - Cookie name `hippius_dashboard`
  - `fn tokens_equal(a: &str, b: &str) -> bool` constant-time
  - `fn host_is_loopback(host: &str, bound_port: u16) -> bool`

`test_state` becomes a **session** token. Existing `?t=` on API routes no longer authenticates (spec: bootstrap is one-shot on `/` only). Update every test that used `?t=` on `/api/...` to send `x-dashboard-token` **and** `Host: 127.0.0.1`.

- [ ] **Step 1: Write the failing tests** (in the existing `#[cfg(test)]` module)

```rust
#[tokio::test]
async fn missing_host_is_rejected() {
    let app = router(test_state("secret-token"));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/vaults")
                .header("x-dashboard-token", "secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_loopback_host_is_rejected() {
    let app = router(test_state("secret-token"));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/vaults")
                .header("host", "evil.example")
                .header("x-dashboard-token", "secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn query_token_on_an_api_route_is_unauthorized() {
    let app = router(test_state("secret-token"));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/vaults?t=secret-token")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn tokens_equal_rejects_prefix_and_length_mismatch() {
    assert!(tokens_equal("abcd", "abcd"));
    assert!(!tokens_equal("abcd", "abce"));
    assert!(!tokens_equal("abcd", "abc"));
    assert!(!tokens_equal("abcd", "abcde"));
}
```

Also change `correct_token_is_authorized` / `header_token_is_authorized` / `get_req` to send `Host: 127.0.0.1` and use the header (not `?t=`). Keep `missing_token_is_unauthorized` and `wrong_token_is_unauthorized`.

- [ ] **Step 2: Run tests — expect FAIL** (no `host_is_loopback` / API `?t=` still 200)

```bash
cargo test -p hippius-mem --features dashboard --lib missing_host_is_rejected non_loopback_host_is_rejected query_token_on_an_api_route_is_unauthorized tokens_equal
```

- [ ] **Step 3: Implement**

`tokens_equal`: if lengths differ, return false; else XOR all bytes, compare to 0. Do not early-return on first mismatch.

`require_token` order:
1. `Host` must be `127.0.0.1` or `127.0.0.1:<bound_port>` (`host_is_loopback`). Else 403.
2. Session from `Cookie: hippius_dashboard=<session>` or `x-dashboard-token`. Not from `?t=` on any path except the bootstrap handler on `/`.
3. `tokens_equal` against `state.session`. If `Instant::now() >= launched_at + SESSION_TTL`, 401.
4. Else `next.run(req)`.

`run` mints two tokens (`generate_token` twice). `bootstrap` starts as `Some`. Log listen URL **without** the token. Print bootstrap URL only when `--no-open` or headless. `open_in_browser` still receives the bootstrap URL but tracing on success must not include it (`tracing::info!("opened the dashboard in your default browser")` with no `url` field).

`test_state_seeded` sets `bound_port: 0` (Host `127.0.0.1` with no port still matches) and `launched_at: Instant::now()`, `bootstrap: Mutex::new(None)` for API tests (no bootstrap).

- [ ] **Step 4: Run the new tests + existing dashboard tests**

```bash
cargo test -p hippius-mem --features dashboard --lib
```

Expected: PASS. Update every `oneshot` that now 403s for missing Host.

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: session token, Host gate, no API query token"
```

---

### Task 2: One-shot bootstrap exchange + security headers

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`index_html` → stateful, new bootstrap handler)

**Interfaces:**
- Consumes: Task 1 `DashboardState` bootstrap mutex + session
- Produces:
  - `GET /?t=<bootstrap>` → `Set-Cookie: hippius_dashboard=<session>; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`, invalidate bootstrap, `302` to `/`
  - Replay of the same `?t=` → `401`
  - `GET /` with valid cookie → HTML with CSP nonce
  - Every response: CSP (nonce), `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Permissions-Policy: camera=(), microphone=(), geolocation=()`
  - HTML is no longer `&'static str`: inject nonce into `<script>` / `<style>` (for now, string-replace a `__CSP_NONCE__` placeholder added to `dashboard.html`)

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn bootstrap_sets_session_cookie_and_redirects() {
    let state = test_state_with_bootstrap("session-tok", "boot-tok");
    let app = router(state);
    let resp = app.oneshot(host_get("/?t=boot-tok")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get("location").unwrap(), "/");
    let cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie.contains("hippius_dashboard=session-tok"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(!cookie.contains("boot-tok"), "bootstrap must not become the cookie");
}

#[tokio::test]
async fn bootstrap_replay_is_unauthorized() {
    let state = test_state_with_bootstrap("session-tok", "boot-tok");
    let app = router(state.clone());
    let _ = app.oneshot(host_get("/?t=boot-tok")).await.unwrap();
    let app = router(state);
    let resp = app.oneshot(host_get("/?t=boot-tok")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cookie_authenticates_after_bootstrap() {
    let state = test_state_with_bootstrap("session-tok", "boot-tok");
    let app = router(state);
    let resp = app
        .oneshot(host_get_cookie("/api/vaults", "hippius_dashboard=session-tok"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn html_and_api_responses_carry_security_headers() {
    let app = router(test_state("secret-token"));
    let resp = app
        .oneshot(host_header_get("/api/vaults", "secret-token"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(resp.headers().get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    assert_eq!(resp.headers().get("cache-control").unwrap(), "no-store");
    let csp = resp.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'none'"));
    assert!(!csp.contains("unsafe-inline"));
}
```

- [ ] **Step 2: Run — expect FAIL** (no bootstrap handler / no headers)

```bash
cargo test -p hippius-mem --features dashboard --lib bootstrap_sets_session_cookie bootstrap_replay cookie_authenticates html_and_api_responses_carry
```

- [ ] **Step 3: Implement**

Split `/` into: if `?t=` present, bootstrap exchange (does not require session cookie); else `require_token` then serve HTML.

Layer a response middleware that attaches the security headers and a fresh 16-byte hex nonce onto every response. For HTML, replace `__CSP_NONCE__` in the included file; add `nonce="__CSP_NONCE__"` to the existing `<script>` and `<style>` tags.

`index_serves_html` must send Host + session header; still asserts `notes-table` marker until Task 12.

- [ ] **Step 4: Run dashboard lib tests** — PASS

```bash
cargo test -p hippius-mem --features dashboard --lib
```

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: one-shot bootstrap cookie and security headers"
```

---

### Task 3: Origin gate for POST + fail-closed bind

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`run` bind check; add `require_loopback_origin` for POST)

**Interfaces:**
- Consumes: `bound_port` on state (set from `local_addr` after bind; tests use 3847 or 0)
- Produces:
  - `fn is_loopback_addr(addr: SocketAddr) -> bool`
  - `fn origin_is_loopback(origin: &str, bound_port: u16) -> bool` — exact `http://127.0.0.1` or `http://127.0.0.1:<port>`
  - POST without matching Origin → 403
  - After bind, non-loopback `local_addr` → return error, no listen log

No POST routes exist yet. Add a test-only `POST /api/vaults/{vault}/__origin_probe` **or** implement the Origin middleware now and attach it; Task 8/9 will add the real POSTs. Prefer a `from_fn` that 403s any non-GET without the Origin, so future POSTs cannot forget it.

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn is_loopback_addr_accepts_v4_loopback_only() {
    assert!(is_loopback_addr("127.0.0.1:9".parse().unwrap()));
    assert!(!is_loopback_addr("0.0.0.0:9".parse().unwrap()));
    assert!(!is_loopback_addr("8.8.8.8:9".parse().unwrap()));
}

#[tokio::test]
async fn post_without_origin_is_forbidden() {
    let app = router(test_state("secret-token"));
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/vaults/test-team/refresh")
                .header("host", "127.0.0.1")
                .header("x-dashboard-token", "secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
```

`POST /refresh` may 404 until Task 9; the Origin layer must run **before** the route table so missing Origin is 403, not 404. If the route is absent, still assert 403 (middleware short-circuits).

- [ ] **Step 2: Run — expect FAIL**

```bash
cargo test -p hippius-mem --features dashboard --lib is_loopback_addr_accepts post_without_origin_is_forbidden
```

- [ ] **Step 3: Implement** Origin middleware + bind check in `run`.

- [ ] **Step 4: Run dashboard lib tests** — PASS

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: Origin gate on non-GET and fail-closed loopback bind"
```

---

## PR 2 — Store access

### Task 4: Per-vault lock; stop `refresh_if_stale` on inspect GETs

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`DashboardState::stores`, `store_for`, `health`, `overview`, `list_notes`, `list_repos`, `get_note`, `report`)

**Interfaces:**
- Consumes: current `Arc<Mutex<HashMap<String, Arc<MemoryStore>>>>`
- Produces: `stores: Arc<Mutex<HashMap<String, Arc<OnceLock-or-per-vault-Mutex>>>>` such that a cache hit for vault B does not wait on vault A's build. Pattern: map lock only to look up/insert a per-vault `Arc<tokio::sync::Mutex<Option<Arc<MemoryStore>>>>`; drop the map lock; then lock the per-vault cell to build.

Health/repos/notes/get/report/history: delete `refresh_if_stale` calls.

- [ ] **Step 1: Failing test** — a `MemoryStore` wrapper is too heavy. Instead test the lock shape with a `store_for` that records lock hold: seed two vaults in the map (already built) and assert concurrent `store_for("a")` and `store_for("b")` both return without serializing on a single mutex. Simpler discriminating test:

```rust
#[tokio::test]
async fn inspect_health_does_not_call_refresh_if_stale() {
    // Seed a store whose auto-refresh last_check is None and whose blob
    // cannot LIST (MemoryBlobStore can). Instead: after store_for cache hit,
    // health must not change synced_op_count / last_check.
    // Discriminator: health JSON has no "synced" key (Task 6) and a second
    // health call does not invoke oplog.op_object_count.
}
```

Until Task 6, the discriminator is: put a custom `BlobStore` that panics on `list`/`list_prefix` used by `op_object_count`; health must still 200. If `refresh_if_stale` remains, it panics.

Implement a `PanicOnList` blob in the test module that forwards get/put/delete to `MemoryBlobStore` and panics on list. Wire it only if needed; if `MemoryBlobStore` list is cheap, spy by checking health no longer returns `synced`.

**Chosen discriminator (do this):** health response after Task 6 has `stale`/`last_sync` and **must not** have `synced`. In this task, remove the `refresh_if_stale` calls and add:

```rust
#[tokio::test]
async fn health_does_not_require_a_stale_probe() {
    let (state, store) = test_state_seeded("t");
    let app = router(state);
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/health", "t")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Probe would be a no-op on MemoryBlobStore; the lock change is tested by
    // two pre-seeded vaults returning concurrently (see store_for_cache_hit_is_per_vault).
}

#[tokio::test]
async fn store_for_cache_hit_is_per_vault() {
    let (mut state, store_a) = test_state_seeded("t");
    let store_b = test_store();
    {
        let mut g = state.stores.lock().await;
        // After the lock refactor this insert API will be the per-vault cell;
        // adapt the helper in the same commit.
        g.insert("other".into(), /* cell with store_b */);
    }
    let a = state.store_for("test-team");
    let b = state.store_for("other");
    let (a, b) = tokio::join!(a, b);
    assert!(a.is_ok() && b.is_ok());
}
```

- [ ] **Step 2: Run — expect FAIL** on the new lock type / insert API

- [ ] **Step 3: Implement** per-vault cells; strip `refresh_if_stale` from GET handlers.

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: per-vault store lock, no implicit refresh on GET"
```

---

### Task 5: `MemoryIndex::len` + `get`

**Files:**
- Modify: `hippius-mem-core/src/index/mod.rs` (trait + `InMemoryIndex` + tests)
- Modify: `hippius-mem-core/src/store/mod.rs` (`index_len`, `index_get` + test)
- Test: same files' `#[cfg(test)]` (trait has other test impls — add `len`/`get` to every `MemoryIndex` impl, including test fakes)

**Interfaces:**
- Produces:
  - `fn len(&self) -> Result<usize, MemError>`
  - `fn get(&self, id: NoteId) -> Result<Option<IndexRecord>, MemError>`
  - `MemoryStore::index_len(&self) -> Result<usize, MemError>`
  - `MemoryStore::index_get(&self, id: NoteId) -> Result<Option<IndexRecord>, MemError>`

- [ ] **Step 1: Failing tests** next to `all_records_returns_every_upserted_record`

```rust
#[test]
fn len_counts_upserted_records() -> TestResult {
    let index = InMemoryIndex::with_hash_embedder();
    assert_eq!(index.len()?, 0);
    index.upsert(record("team", RepoScope::Global, NoteType::Decision, "a", 1)?)?;
    index.upsert(record("team", RepoScope::Global, NoteType::Gotcha, "b", 2)?)?;
    assert_eq!(index.len()?, 2);
    Ok(())
}

#[test]
fn get_returns_the_upserted_record_and_none_for_unknown() -> TestResult {
    let index = InMemoryIndex::with_hash_embedder();
    let rec = record("team", RepoScope::Global, NoteType::Decision, "alpha", 1)?;
    let id = rec.note_id;
    index.upsert(rec.clone())?;
    assert_eq!(index.get(id)?.as_ref().map(|r| r.summary.as_str()), Some("alpha"));
    assert!(index.get(NoteId::from_bytes([0; 16]))?.is_none());
    Ok(())
}
```

Use whatever `NoteId` constructor the file already uses if `from_bytes` is wrong.

- [ ] **Step 2: Run — expect FAIL** (methods missing)

```bash
cargo test -p hippius-mem-core --lib len_counts_upserted_records get_returns_the_upserted_record
```

- [ ] **Step 3: Implement** on the trait and every impl. Store wrappers delegate.

- [ ] **Step 4:**

```bash
cargo test -p hippius-mem-core --lib
cargo test -p hippius-mem --features dashboard --lib
```

- [ ] **Step 5: Commit**

```bash
git commit -m "core: MemoryIndex len and get for dashboard health and search"
```

---

### Task 6: Health without dump; delete overview notes

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`HealthDto`, `health`, remove `overview` or empty it)

**Interfaces:**
- Produces: `HealthDto { team, semantic, note_count, stale, last_sync }`
- `last_sync`: unix ms, dashboard-owned. Track `HashMap<String, Instant>` on state, set on `store_for` sync and `POST /refresh` (Task 9). `stale` iff `last_sync` older than `Duration::from_secs(5 * 60)`.
- Delete `OverviewDto.notes` and the `overview` route if unused.

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn health_reports_stale_and_count_without_synced_or_notes() {
    let (state, store) = test_state_seeded("t");
    seed(&store, NoteType::Decision, "one").await;
    let app = router(state);
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/health", "t")).await.unwrap();
    let body = json_body(resp).await;
    assert_eq!(body["note_count"], 1);
    assert_eq!(body["semantic"], false);
    assert!(body.get("synced").is_none());
    assert!(body.get("notes").is_none());
    assert!(body.get("stale").is_some());
    assert!(body.get("last_sync").is_some());
}

#[tokio::test]
async fn overview_route_is_gone() {
    let app = router(test_state("t"));
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/overview", "t")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
```

Rewrite `overview_lists_seeded_notes` to use `/notes` or delete it.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: health freshness fields, drop overview dump"
```

---

## PR 3 — Inspect APIs

### Task 7: Reconcile + report `?since=` + 60s cache

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs`

**Interfaces:**
- `GET /api/vaults/{vault}/reconcile` → `Json<ReconcileReport>`
- `GET /api/vaults/{vault}/report?since=` uses `parse_since_value`; default `7d`; unknown → 400
- Cache last report/reconcile per vault until Refresh or 60s

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn reconcile_returns_the_core_report_shape() {
    let app = router(test_state("t"));
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/reconcile", "t")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body.get("ok").is_some() || body.get("checked_batches").is_some());
    assert!(body.get("quarantined_authors").is_some());
    assert!(body.get("missing_ops").is_some());
}

#[tokio::test]
async fn report_since_uses_parse_since_value() {
    let (state, store) = test_state_seeded("t");
    seed_report_fixture(&store).await;
    let app = router(state);
    let bad = app.oneshot(host_header_get("/api/vaults/test-team/report?since=7m", "t")).await.unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let ok = app.oneshot(host_header_get("/api/vaults/test-team/report?since=2w", "t")).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}
```

Keep `report_endpoint_returns_the_same_numbers_the_cli_renders`.

Check `ReconcileReport` serde: if there is no `ok` field, assert the vectors only (`checked_batches`, `missing_ops`, `root_mismatches`, `quarantined_authors`, `suppressed_tails`, `head_regressions`).

- [ ] **Step 2: Run — expect FAIL** (404)

- [ ] **Step 3: Implement** handlers + cache on `DashboardState`.

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: reconcile endpoint and report since window"
```

---

### Task 8: Structured doctor + POST live

**Files:**
- Modify: `hippius-mem/src/doctor.rs` (extract `DoctorReport`)
- Modify: `hippius-mem/src/dashboard/mod.rs`

**Interfaces:**
- `pub(crate) struct DoctorReport { profile, bucket, access_key_id, author_ss58, ok: bool }` — no secret fields
- `pub(crate) fn offline_report(profile: &TeamProfile) -> Result<DoctorReport, ...>`
- `GET /api/vaults/{vault}/doctor` → offline `DoctorReport` for **that vault's** profile (not cwd resolve)
- `POST /api/vaults/{vault}/doctor/live` → live probe; Origin required (Task 3)

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn doctor_offline_has_public_coordinates_and_no_secrets() {
    let app = router(test_state("t"));
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/doctor", "t")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["profile"].is_string());
    assert!(body["bucket"].is_string());
    assert!(body["access_key_id"].is_string());
    assert!(body["author_ss58"].is_string());
    assert_eq!(body["ok"], true);
    let s = body.to_string();
    assert!(!s.contains("team_key"));
    assert!(!s.contains("author_seed"));
    assert!(!s.contains("secret"));
}

#[tokio::test]
async fn live_doctor_get_is_not_a_route() {
    let app = router(test_state("t"));
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/doctor/live", "t")).await.unwrap();
    assert!(resp.status() == StatusCode::METHOD_NOT_ALLOWED || resp.status() == StatusCode::NOT_FOUND);
}
```

Existing `doctor.rs` unit tests for `offline_report_lines` stay; new function can wrap them.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement** extraction + routes. Live POST on in-memory test store: 200 or 502, but GET must not write.

- [ ] **Step 4: Tests PASS** including `cargo test -p hippius-mem --lib doctor`

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: structured doctor, live probe is POST only"
```

---

### Task 9: POST refresh

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs`

**Interfaces:**
- `POST /api/vaults/{vault}/refresh` → `{ "indexed": <usize>, "ran": true }`
- Calls `store.sync()`, stamps `last_sync`, invalidates reconcile/report cache
- Missing Origin → 403 (Task 3)

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn refresh_syncs_and_requires_origin() {
    let app = router(test_state("t"));
    let forbidden = app
        .oneshot(host_header_post("/api/vaults/test-team/refresh", "t", None))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let ok = app
        .oneshot(host_header_post(
            "/api/vaults/test-team/refresh",
            "t",
            Some("http://127.0.0.1"),
        ))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let body = json_body(ok).await;
    assert_eq!(body["ran"], true);
    assert!(body["indexed"].is_number());
}

#[tokio::test]
async fn get_refresh_is_not_a_route() {
    let app = router(test_state("t"));
    let resp = app.oneshot(host_header_get("/api/vaults/test-team/refresh", "t")).await.unwrap();
    assert!(resp.status() == StatusCode::METHOD_NOT_ALLOWED || resp.status() == StatusCode::NOT_FOUND);
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: POST refresh syncs the local index"
```

---

## PR 4 — Notes parity

### Task 10: Browse pagination

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`list_notes`, `NotesDto`)

**Interfaces:**
- `NotesDto { notes, next_cursor: Option<String> }`
- Default `limit=50`, cap `100`. `cursor` = decimal offset.

- [ ] **Step 1: Failing test** — seed 60 notes, default list for `?repo=global` returns 50, `next_cursor` present, second page returns 10.

```rust
#[tokio::test]
async fn browse_pages_default_fifty() {
    let (state, store) = test_state_seeded("t");
    for i in 0..60 {
        seed(&store, NoteType::Context, &format!("note-{i:02} pagination")).await;
    }
    let app = router(state);
    let page1 = json_body(
        app.oneshot(host_header_get("/api/vaults/test-team/notes?repo=global", "t")).await.unwrap(),
    )
    .await;
    assert_eq!(page1["notes"].as_array().unwrap().len(), 50);
    assert_eq!(page1["next_cursor"], "50");
    assert!(page1["notes"][0].get("body").is_none());
}
```

`router` is consumed by `oneshot` — clone state and build two apps, or use `oneshot` on a cloned router (`router` is `Clone` via state).

- [ ] **Step 2: Run — expect FAIL** (60 rows, no cursor)

- [ ] **Step 3: Implement** slice after existing filter/sort.

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: paginate browse notes"
```

---

### Task 11: Search MCP parity + followable history flags

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (`search_rows`, `DEFAULT_LIST_K` → use `DEFAULT_RECALL_K` (12), `NotesDto.semantic`, history drawer already has flags)

**Interfaces:**
- Search `k` default 12, cap 50, optional `token_budget`
- `parse_repo` unchanged
- Join via `store.index_get`, not `list_records` map
- Response `{ notes, semantic }`
- History DTO already has `tombstoned`/`redacted` — add a test that a forgotten note's history reports `tombstoned: true`

- [ ] **Step 1: Failing tests**

```rust
#[tokio::test]
async fn search_defaults_to_mcp_k_and_advertises_semantic() {
    let (state, store) = test_state_seeded("t");
    for i in 0..20 {
        seed(&store, NoteType::Context, &format!("unique-token-{i} apple")).await;
    }
    let app = router(state);
    let body = json_body(
        app.oneshot(host_header_get("/api/vaults/test-team/notes?q=apple", "t")).await.unwrap(),
    )
    .await;
    assert!(body["notes"].as_array().unwrap().len() <= 12);
    assert_eq!(body["semantic"], false);
}

#[tokio::test]
async fn history_reports_tombstoned_after_forget() {
    let (state, store) = test_state_seeded("t");
    let id = seed(&store, NoteType::Gotcha, "forget-me").await;
    store.forget(id).await.unwrap();
    let app = router(state);
    let body = json_body(
        app.oneshot(host_header_get(
            &format!("/api/vaults/test-team/notes/{id}/history"),
            "t",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(body["tombstoned"], true);
}
```

Confirm `MemoryStore::forget` exists; if the test API differs, use the same path `mcp_protocol` tests use.

- [ ] **Step 2: Run — expect FAIL** (50 hits, no `semantic`)

- [ ] **Step 3: Implement**

- [ ] **Step 4: Tests PASS**

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: search k and token_budget match MCP recall"
```

---

## PR 5 — UI

### Task 12: Split HTML source + CSP nonce placeholders

**Files:**
- Create: `hippius-mem/src/dashboard/page.html`, `styles.css`, `app.js`
- Modify: `dashboard.html` deleted or reduced to a compile-time concat
- Modify: `mod.rs` `index_html`

**Interfaces:**
- Served document is still one HTML file (no extra HTTP assets)
- `__CSP_NONCE__` on every script/style tag

- [ ] **Step 1:** Move CSS/JS out; `index_serves_html` still finds `notes-table` (or the new inspect-home marker `id="inspect-home"`). Update the marker test in the same task.

- [ ] **Step 2:** `cargo test -p hippius-mem --features dashboard --lib index_serves_html` — FAIL until concat works

- [ ] **Step 3:** Concat in `index_html`: page + inlined css/js with nonce substitution

- [ ] **Step 4:** Tests PASS

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: split UI source, still one served document"
```

---

### Task 13: Inspect-home IA + progressive fetch + Refresh

**Files:**
- Modify: `hippius-mem/src/dashboard/app.js` (and page markup)

**Interfaces:**
- `#/` vaults (unchanged, store-free)
- `#/vault/<name>` inspect home: identity, freshness, Refresh, reconcile, doctor, report, repo cards
- `#/vault/<name>/repo/<repo>` notes + search
- Fetch order: health + doctor + repos in parallel, then reconcile, then report
- Refresh: `POST /api/vaults/{name}/refresh` with cookie (no token in JS), then reload panels
- Note text still via `el(..., { text })` only
- `head_regressions` copy: "possible listing lag" not "compromised"

- [ ] **Step 1:** Update `index_serves_html` to assert `inspect-home` (or `id="view-inspect"`) exists in the served HTML. Add a string-level test that `app.js` contains `reconcile` then `report` fetch sequencing (fragile) **or** skip JS unit tests and assert markup ids: `inspect-refresh`, `inspect-reconcile`, `inspect-doctor`, `inspect-report`, `repos-list`.

```rust
#[tokio::test]
async fn index_serves_inspect_home_markers() {
    let html = served_html().await; // helper: GET / with cookie
    assert!(html.contains("id=\"view-inspect\"") || html.contains("id=\"inspect-home\""));
    assert!(html.contains("inspect-refresh") || html.contains("id=\"btn-refresh\""));
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement** hash router change. Notes view keeps accordion + history. Links in detail navigate to `get` the target (hash `#/vault/<name>/repo/<repo>` and expand, or fetch-in-drawer). Forgotten/redacted banners from history payload.

- [ ] **Step 4:** dashboard lib tests PASS; manually note that a browser pass is required before merge (operator runs `hippius-mem dashboard`).

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: inspect-home first, notes one click away"
```

---

## PR 6 — Rate limits + docs

### Task 14: Rate limits, REFERENCE, I-DASH

**Files:**
- Modify: `hippius-mem/src/dashboard/mod.rs` (token bucket per session)
- Modify: `docs/REFERENCE.md` dashboard section
- Modify: `docs/INVARIANTS.md`
- Modify: team-memory note `mem_01KWW3Y0CAQS9CS5MM8YC5GKC8` via `edit` after merge (token-in-URL and `#/vault` = repos are now false)

**Interfaces:**
- In-memory counters on `DashboardState`, keyed by route class
- Budgets from the spec: refresh 1/5s, reconcile 1/10s, live doctor 1/60s, search 10/10s, history 5/10s
- `429` + `Retry-After`

- [ ] **Step 1: Failing test**

```rust
#[tokio::test]
async fn reconcile_rate_limit_returns_429() {
    let app_state = test_state("t");
    for _ in 0..2 {
        let app = router(app_state.clone());
        let resp = app
            .oneshot(host_header_get("/api/vaults/test-team/reconcile", "t"))
            .await
            .unwrap();
        if /* second */ {
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().get("retry-after").is_some());
        }
    }
}
```

Drive two calls on the **same** `DashboardState` (clone the state, two `router`s). First 200, second 429.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement** limiter + docs.

`I-DASH` rows (statement + exact test name + job `test-all-features`):

| ID | Statement | Test |
|---|---|---|
| I-DASH-HOST | Non-loopback Host is rejected | `non_loopback_host_is_rejected` |
| I-DASH-BOOT | Bootstrap URL works once | `bootstrap_replay_is_unauthorized` |
| I-DASH-ORIGIN | POST without loopback Origin is 403 | `post_without_origin_is_forbidden` / `refresh_syncs_and_requires_origin` |
| I-DASH-BODY | List/repos JSON has no body field | `browse_pages_default_fifty` |
| I-DASH-K | Search default k is 12 | `search_defaults_to_mcp_k_and_advertises_semantic` |
| I-DASH-GET | Inspect GETs do not refresh_if_stale | `health_does_not_require_a_stale_probe` |

REFERENCE.md: replace standing `?t=` session language with one-shot bootstrap; inspect-home routes; read-only; first-paint order; Refresh; rate limits; 30-minute TTL.

- [ ] **Step 4:**

```bash
cargo fmt
cargo clippy -p hippius-mem -p hippius-mem-core --all-targets --features dashboard -- -D warnings
cargo test -p hippius-mem --features dashboard
cargo test -p hippius-mem-core --lib
```

- [ ] **Step 5: Commit**

```bash
git commit -m "dashboard: rate limits, REFERENCE, I-DASH invariants"
```

---

## Execution notes

- After each PR-sized group (Tasks 1–3, 4–6, 7–9, 10–11, 12–13, 14), open a PR if the operator wants review mid-stream; otherwise keep one branch and one PR at the end.
- Browser verification of Task 13 is required before calling the UI done (`hippius-mem dashboard`, click vault, confirm inspect home, Refresh, open a repo, search, expand history).
- Do not bind `0.0.0.0` in tests.
- JS must never read the session token; cookie is HttpOnly.

## Spec coverage

| Spec section | Tasks |
|---|---|
| §1 IA | 13 |
| §2 API | 6–11 |
| §3 Security | 1–3, 8–9, 12 (nonce), 14 (limits) |
| §4 Performance | 4–6, 10–11 |
| §5 Frontend | 12–13 |
| §6 Testing / I-DASH | each task + 14 |
| §7 Sequence | this plan's PR grouping |
