# Dashboard inspect console

Date: 2026-08-15
Status: design (awaiting review)
Author surface: `hippius-mem` (`src/dashboard/`), small `hippius-mem-core` index additions
Branch (when implementing): `feat/dashboard-inspect-console`

## Goal

Turn `hippius-mem dashboard` from a Phase-1 browse UI into a **human inspect /
audit console**: integrity and freshness first, then notes. Stay read-only.
Harden the loopback+token boundary. Stop dumping the index into the browser
and stop double-reading the op-log on first paint.

Writes (remember / edit / forget / redact / link) stay on the MCP tools. The
browser is not a second write path.

## Locked decisions

- **Job:** inspect / audit, not an operations console and not a full GUI.
- **Scope:** one spec covering integrity, freshness, search/history parity,
  richer report, and security/perf; implementation is six sequenced PRs.
- **Security bar:** hardened local inspect (not operator-unlock).
- **First paint:** current vault's inspect home. Cheap panels (health, offline
  doctor, repos) render first; reconcile then report load after. Notes are one
  click away. No note-list dump.

## Non-goals

- Note curation from the UI (remember / edit / forget / redact / link).
- A hosted / non-loopback dashboard, TLS on loopback, or a native desktop app.
- Live doctor on first paint (it writes `_doctor/` probe objects).
- A new `MemoryIndex` pagination API (handler slice is enough until measured).
- A link-graph visualization (followable ids in the existing drawer).
- Background service / always-on daemon (still a foreground CLI).
- Rewriting the UI in a JS framework.

## Constraints

- Feature-gated: `dashboard` still pulls `axum`; default stdio binary does not
  link it. Installer / dist stay `--features embeddings,dashboard`.
- Global config default unchanged (`~/.config/hippius-mem/hippius-mem.toml`);
  `HIPPIUS_MEM_CONFIG` still overrides.
- `store_for` still calls `admin::bootstrap_epochs` (mnemonic-gated). Omitting
  that silently drops rotated-epoch notes.
- Reconcile and report numbers come from the core types (`ReconcileReport`,
  `TeamReport` + `build_report` / `window_since`), not dashboard-local copies.
- `#![forbid(unsafe_code)]`, clippy `-D warnings`, rustfmt Default heuristics.
- Tests: in-process `tower` `oneshot`, in-memory `MemoryStore` + `HashEmbedder`.
  No live S3, no real browser, no coverage/mutants CI gate.

## Current state (main)

Phase 1 (`hippius-mem/src/dashboard/`): vaults → repos → notes, search
(`DEFAULT_LIST_K = 50`), accordion get + lazy history, health (`synced` means
"this request synced"), fixed 7-day report, loopback + `?t=` token (also
`x-dashboard-token`). `GET .../overview` and browse `list_notes` ship every
`list_records` row. Every vault GET calls `refresh_if_stale`. One process-global
mutex around `store_for`. `dashboard.html` is a 1.2k-line self-contained page.

---

## 1. Information architecture

Hash routes stay. `#/vault/<name>` becomes inspect home, not the repos/report
page.

| Route | What you see |
|---|---|
| `#/` | Vault cards from config only. No store build, no sync, no notes. "This repo" badge unchanged. |
| `#/vault/<name>` | **Inspect home.** Integrity and freshness first. Repo cards (counts only) below. |
| `#/vault/<name>/repo/<repo>` | Paginated notes + search. Accordion for body/tags; Full detail for history, links, forgotten/redacted. |

No fourth route for a single note. Old `#/vault/<name>` bookmarks land on
inspect home; the repo cards are still there.

**Inspect home, top to bottom**

1. Vault identity (name, retrieval mode, note count).
2. Freshness: last sync / stale, **Refresh** (local index only).
3. Integrity: reconcile, doctor (offline by default), quarantined authors /
   dropped ops. Status, not a silent green badge. `head_regressions` is labeled
   possible LIST-lag / eventual consistency, not "the vault is compromised"
   (see `mem_01KZRCDS23YE3A04QP8VFTY7DY`).
4. Compact report: default 7-day window, control for other `window_since`
   values. Same numbers as `hippius-mem report`.
5. Repo cards (`global` first, then count desc, then name).

Landing stays store-free so launch stays instant.

---

## 2. HTTP API

Vault-scoped. Landing list is the only store-free data route. No write tools.

### Inspect home

| Method | Path | Store / lib | Contract |
|---|---|---|---|
| `GET` | `/api/vaults` | config | Unchanged. |
| `GET` | `/api/vaults/{vault}/health` | cached index | `team`, `semantic`, `note_count`, `stale`, `last_sync` (unix ms of last successful `store_for` sync or `POST /refresh`). `stale` is true when that instant is older than **5 minutes** — not MCP's 20s `AUTO_REFRESH_WINDOW`. **Not** today's `synced: bool`. No notes array. Does not sync. |
| `GET` | `/api/vaults/{vault}/reconcile` | `MemoryStore::reconcile()` | Wire `ReconcileReport` as-is (vectors, not only `ok`). |
| `GET` | `/api/vaults/{vault}/doctor` | structured doctor | **Offline only:** `profile`, `bucket`, `access_key_id`, `author_ss58`, `ok`. No secret field names. |
| `POST` | `/api/vaults/{vault}/doctor/live` | live probe | Opt-in. Writes `_doctor/encryption-boundary-probe`. Not first paint. |
| `GET` | `/api/vaults/{vault}/report?since=` | `build_report` + `window_since` | Default `7d`. `since` uses `parse_since_value` (`Nd` / `Nw` only). Unknown window → `400`. |
| `GET` | `/api/vaults/{vault}/repos` | `list_records` → counts | Unchanged shape. No summaries or bodies. |
| `POST` | `/api/vaults/{vault}/refresh` | `MemoryStore::sync()` | Local index only. `{ indexed, ran: true }`. Not `refresh_if_stale`. |

### Notes

| Method | Path | Store / lib | Contract |
|---|---|---|---|
| `GET` | `/api/vaults/{vault}/notes` | browse or `recall` | See below. Body-free rows. |
| `GET` | `/api/vaults/{vault}/notes/{id}` | `get` | Body, version, link ids. No history. |
| `GET` | `/api/vaults/{vault}/notes/{id}/history` | `history` | Already has `tombstoned` / `redacted`; the drawer must show them. Links in the detail pane are clickable (`get` the target). |

**Browse** (`q` absent): filter `repo` / `type` / `tag`, then `limit` + `cursor`.
Default `limit=50`, hard cap `100`. `cursor` is an opaque decimal offset
(0-based into the filtered+sorted list); the next page is `cursor + limit`.
No cursor on search (search is top-`k` only).

**Search** (`q` present): same `RecallInput` + `parse_repo` as MCP. Default
`k=12` (`DEFAULT_RECALL_K`), optional `k` and `token_budget`, `k` capped at 50.
Response includes `semantic`. Join `Pointer` → `IndexRecord` is **server-side**
via `MemoryIndex::get`.

**Removed from the wire:** `GET .../overview`'s `notes: []` dump. Team /
semantic / count live on `health`. Delete the overview route if nothing else
calls it; do not keep a silent second dump.

**Doctor extraction:** add a structured function in `doctor.rs`. CLI keeps
printing lines. Dashboard does not scrape logs.

**First-paint client set:** `health` + `doctor` (offline) + `repos`, then
`reconcile`, then `report`. Never `notes`, `history`, or live doctor.

---

## 3. Security

Two-fold boundary stays: loopback bind + per-launch CSPRNG token. Hardening is
how the token is carried, how long it lives, and what a tab can make it do.

### Bind (fail closed)

After `bind`, if `local_addr` is not `127.0.0.1` (or `[::1]` if we ever bind
v6), refuse to serve and do not print a URL. Reject any request whose `Host` is
not `127.0.0.1[:port]`.

### Two tokens

| Token | Where | Lifetime |
|---|---|---|
| Bootstrap | One-shot `/?t=` in the URL the CLI opens or prints | Single successful exchange, then dead |
| Session | Cookie `hippius_dashboard`: `HttpOnly; SameSite=Strict; Path=/`. No `Secure` (this is `http://127.0.0.1`). | Absolute **30 minutes** from launch. No JS refresh |

Flow: open/print `http://127.0.0.1:<port>/?t=<bootstrap>` → validate, set
session cookie, invalidate bootstrap, `302` to `/` with no query. Replay of the
bootstrap URL is `401`. After TTL, `401` and the UI says re-run
`hippius-mem dashboard`.

`x-dashboard-token` accepts the **session** token only (tests / `oneshot`).
The page never reads the token: same-origin `fetch` sends the cookie. Compare
both tokens in constant time (equal length then XOR). No new crate.

`oneshot` tests must send `Host: 127.0.0.1`. A missing or non-loopback `Host`
is a reject.

### Logging

Listening log is `http://127.0.0.1:<port>/` only. The bootstrap URL is printed
once, and only when the operator needs it (`--no-open` or headless). Auto-open
must not `tracing` the token. Never log the cookie, the header, or note bodies.

### Side-effecting inspect = POST

`POST /refresh` and `POST /doctor/live` only. A GET must not sync the index or
write the probe object. Every POST requires `Origin` exactly
`http://127.0.0.1:<bound_port>` (missing/wrong → `403`).

### Headers (every response)

- `Content-Security-Policy` with a **per-response nonce** (no `'unsafe-inline'`):
  `default-src 'none'; script-src 'nonce-…'; style-src 'nonce-…'; connect-src 'self'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Cache-Control: no-store`
- `Permissions-Policy` disabling camera, microphone, geolocation

### Rate limits (per session)

`429` + `Retry-After`:

| Route | Budget |
|---|---|
| `POST .../refresh` | 1 / 5s |
| `GET .../reconcile` | 1 / 10s |
| `POST .../doctor/live` | 1 / 60s |
| `GET .../notes?q=` | 10 / 10s |
| `GET .../notes/{id}/history` | 5 / 10s |

Health, repos, browse (no `q`), offline doctor: no extra limit.

### Data that never crosses the wire

List / search / repos / health stay body-free. Doctor JSON has no secret
fields. The existing `el()` helper (`text` → `textContent`, never `innerHTML`)
stays an invariant — note text is untrusted in the HTML context.

---

## 4. Performance

Launch stays instant (no store until a vault is opened). A cold vault still
takes seconds on first `store_for` (build + `bootstrap_epochs` + `sync`). That
is the op-log, not the UI. Success: inspect home usable after **one** sync, no
full-index dump, no double op-log read, no global lock, Refresh is the only
extra sync.

### Cost table

| Work | Cost | Rule |
|---|---|---|
| `store_for` sync | Seconds | Once per vault per process. Vault-loading state. Do not prefetch other vaults. |
| `reconcile` | Verified op-log read | Inspect-home panel, after cheap routes. |
| `build_report` | `read_and_filter()` — a **second** op-log read — plus `list_records` | After reconcile, never in parallel with it. |
| `history` | Full op-log | On-demand in the drawer only. |
| `recall` | CPU / ONNX | `spawn_blocking`. Default `k=12`, cap 50. |
| `list_records` | In-process clone of summaries | Server only (repo counts, browse page). Never the full array on the wire. |

### First-paint sequence (one vault)

1. `store_for` (one sync).
2. Parallel cheap: `health`, `doctor` (offline), `repos`.
3. Then `reconcile`.
4. Then `report`.

### Stampede

- Inspect-home GETs do **not** call `refresh_if_stale`. `store_for` already
  synced; Refresh is `POST .../refresh`. Health reports `stale` / `last_sync`
  from dashboard-owned timestamps (5-minute stale), not the MCP 20s window.
- Replace the process-global `stores` mutex with a **per-vault** lock (named
  as the Phase-1 follow-up on `DashboardState::stores`). Cache hits for vault B
  must not wait on vault A's sync.
- Cache the last `ReconcileReport` and `TeamReport` per vault until Refresh or
  **60s**, whichever first. Rate limits still apply.

### Core additions (only these)

`MemoryIndex` has no `len` or `get(id)` today. Add:

- `fn len(&self) -> Result<usize, MemError>`
- `fn get(&self, id: NoteId) -> Result<Option<IndexRecord>, MemError>`

`MemoryStore` exposes both. Health uses `len`. Search join uses `get`. Browse
paging stays `filter → sort → slice` over `list_records` in the handler.

---

## 5. Frontend

Keep axum + an embedded self-contained page. Split `dashboard.html` into
source files (shell, CSS, JS) concatenated at compile time (`include_str!` or
equivalent) so the served document is still one offline HTML file — nothing
loads from the network. `GET /` is **not** a static `&'static str`: the
handler injects the per-response CSP nonce into the script/style tags before
serving.

Inspect-home JS fetches in the Section 4 order. Refresh button →
`POST /refresh`, then invalidate the reconcile/report cache and reload the
panels. Search box on the notes route only (not inspect home).

---

## 6. Testing

In-process `tower` `oneshot` against `router()`. Discriminating mutations: a
test that still passes if we drop the check is not a test. New `I-DASH` rows
in `docs/INVARIANTS.md`. Dashboard tests already ride `test-all-features`.

### Security (must die if the gate is weakened)

- Missing / wrong / empty token → `401` (keep today's three).
- Bootstrap `?t=` sets the session cookie, `302`s to `/` with no query, and a
  **second** use of the same bootstrap URL is `401`.
- After TTL, cookie is `401`.
- `Host` not `127.0.0.1` → reject.
- `POST /refresh` without the exact loopback `Origin` → `403`.
- GET cannot refresh or run live doctor (no such routes, or they `405`).
- Listening / auto-open logs do not contain the token (captured tracing).
- `el()` never treats note text as `innerHTML`.
- Bind of a non-loopback addr refuses to serve (unit-test the check; do not
  bind `0.0.0.0` in CI).

### API / parity

- `reconcile` JSON is a `ReconcileReport` (vectors present).
- Offline `doctor` has the four public coordinates and no secret field names.
- `report?since=` matches `build_report` + `window_since` for the same store
  (same style as `report_endpoint_returns_the_same_numbers_the_cli_renders`).
- Search uses `parse_repo`, default `k=12`, honors `token_budget`, advertises
  `semantic`.
- Browse `limit`/`cursor`: a 60-note repo does not return 60 rows at default 50.
- `GET .../notes` and `.../repos` have no `body` key.
- History payload still carries `tombstoned` / `redacted`.

### Performance (handler-level)

- Inspect-home handlers do not call `refresh_if_stale`.
- `store_for` for vault B is not blocked for the duration of vault A's build.
- Search `get(id)` path does not put the full index on the response.

### Docs

Update `docs/REFERENCE.md`: bootstrap URL (not a standing `?t=` session),
inspect-home routes, read-only, first paint, Refresh, rate limits. Update the
existing team-memory note on the dashboard when this lands (token-in-URL and
`#/vault/<name>` = repos are both now false).

---

## 7. Implementation sequence

Six PRs off `main`, each with tests for its slice and an adversarial review
before merge.

1. **Security foundation** — two tokens, cookie exchange, Host/Origin,
   headers/CSP nonce, no token in logs, fail-closed bind. Existing routes keep
   working via cookie or session header.
2. **Store access** — per-vault lock, `MemoryIndex::len` + `get`, health
   without note dump, drop `overview.notes`, stop `refresh_if_stale` on inspect
   GETs.
3. **Inspect APIs** — reconcile, structured doctor, `POST` refresh, `POST`
   live doctor, `report?since=`, per-vault report/reconcile cache.
4. **Notes parity** — pagination, MCP `k` / `token_budget` / `semantic`,
   surface forgotten/redacted + followable link ids.
5. **UI** — inspect-home IA, split `dashboard.html` source, progressive fetch
   order, Refresh button.
6. **Rate limits + REFERENCE.md + I-DASH**.

---

## Error handling

- Unknown vault → `404` (no build). Vault build failure → `500`
  (`VaultUnavailable`), same as today.
- Malformed note id → `400`; unknown id on `get` → `404`; `history` of an
  unknown id stays an empty trail (MCP contract).
- Reconcile / report / refresh / live doctor failures → `502`/`500` with a
  non-secret message; inspect home shows the panel error, not a blank page.
- Rate limit → `429` + `Retry-After`.
- Expired / missing session → `401`; HTML/JS tells the operator to re-run the
  CLI.

## Out of scope leftovers (do not sneak in)

- Operator-unlock / tty confirm.
- Changing `AUTO_REFRESH_WINDOW` or MCP auto-refresh.
- Prefetching every configured vault.
- Server-rendered multi-page rewrite.
- Coverage or cargo-mutants gates.
