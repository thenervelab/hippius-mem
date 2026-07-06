//! Local browse/search dashboard served over loopback HTTP.
//!
//! This module is compiled ONLY under the `dashboard` feature so the default
//! stdio MCP binary never links axum. The `hippius-mem dashboard` command binds
//! loopback and speaks plain HTTP; the handlers return *decrypted plaintext*
//! (note bodies the team stores encrypted at rest), so exposure of this surface
//! is exposure of the team's cleartext memory. The security boundary is
//! therefore two-fold and non-negotiable: bind loopback only, and gate every
//! route behind a per-launch token (`require_token`). Neither alone suffices —
//! loopback stops the network, the token stops other local users and CSRF-style
//! drive-by requests from a browser tab.
#![expect(
    dead_code,
    reason = "skeleton wired incrementally: the router is mounted by the dashboard \
              subcommand in Task 6 and `store` is read by real handlers in Task 4. \
              Until then every item is reachable only from tests; this expectation \
              becomes unfulfilled (and forces its own removal) once wired."
)]

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use hippius_mem_core::MemoryStore;

/// Shared handler state. Both fields are reference-counted so `Clone` (required
/// by axum for state) is two atomic increments, not a deep copy: the store is a
/// single process-wide instance and the token is an immutable per-launch secret.
#[derive(Clone)]
pub(crate) struct DashboardState {
    /// The one live memory store; handlers read notes/pointers through it.
    pub store: Arc<MemoryStore>,
    /// Per-launch secret compared by `require_token`. `Arc<str>` (not `String`)
    /// because it is read-only and cloned into every request via the state.
    pub token: Arc<str>,
}

/// Build the dashboard router with the token gate applied to *every* route.
///
/// The `.layer(require_token)` sits above all routes, so there is no path — not
/// even `/api/health` — reachable without presenting the token. Task 4 replaces
/// the stub handler bodies with real DTOs; the routing and the gate are stable.
pub(crate) fn router(state: DashboardState) -> Router {
    // An empty token would make `presented == Some("")` authorize any request
    // that sends `?t=` (or the header) with an empty value — the gate would be
    // open. Pin the hazard at the boundary; Task 6 supplies the real CSPRNG
    // token, so a violation here is a construction bug, not a runtime input.
    debug_assert!(
        !state.token.is_empty(),
        "dashboard launch token must be non-empty"
    );
    Router::new()
        .route("/", get(index_html))
        .route("/api/overview", get(overview))
        .route("/api/notes", get(list_notes))
        // axum 0.8 path-param syntax is `{id}` (0.7's `:id` no longer parses).
        .route("/api/notes/{id}", get(get_note))
        .route("/api/health", get(health))
        .layer(from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

/// Reject any request that does not present the launch token, before it reaches
/// a handler. The token may arrive as the `?t=<token>` query parameter (so a
/// plain browser navigation works) or the `x-dashboard-token` header (so
/// programmatic clients need not leak it into logs via the URL). Comparison is
/// exact equality against `state.token`; a miss returns `401` and the request
/// never touches the store.
///
/// The `?t=` value is NOT percent-decoded. That is correct ONLY because the
/// launch token is CSPRNG bytes rendered as hex (already URL-safe, no reserved
/// characters to escape). If the token encoding ever changes to base64 (which
/// contains `+` and `/`), this must switch to `form_urlencoded` or a wrong-but-
/// look-alike raw value would be compared and legitimate tokens would 401.
///
/// A present-but-wrong `?t=` short-circuits the header fallback: `or_else` only
/// runs when the query lookup yields `None`, so a bad query token returns `401`
/// without consulting `x-dashboard-token`. Intended — a client that sends a
/// query token at all should not be sending a wrong one and silently retried
/// against the header.
async fn require_token(State(state): State<DashboardState>, req: Request, next: Next) -> Response {
    let presented = req
        .uri()
        .query()
        .and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("t=").map(str::to_owned))
        })
        .or_else(|| {
            req.headers()
                .get("x-dashboard-token")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });

    if presented.as_deref() == Some(state.token.as_ref()) {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "missing or invalid dashboard token",
        )
            .into_response()
    }
}

async fn index_html() -> Html<&'static str> {
    // TODO(Task 4): real payload
    Html("<!doctype html><title>hippius-mem</title>")
}

async fn overview() -> Json<serde_json::Value> {
    // TODO(Task 4): real payload
    Json(serde_json::json!({}))
}

async fn list_notes() -> Json<serde_json::Value> {
    // TODO(Task 4): real payload
    Json(serde_json::json!({}))
}

async fn get_note() -> Json<serde_json::Value> {
    // TODO(Task 4): real payload (accept `Path(id): Path<String>` and look it up)
    Json(serde_json::json!({}))
}

async fn health() -> Json<serde_json::Value> {
    // TODO(Task 4): real payload
    Json(serde_json::json!({}))
}

// The enclosing `mod dashboard` is itself `#[cfg(feature = "dashboard")]` in
// main.rs, so `feature = "dashboard"` is already guaranteed inside this file;
// a plain `#[cfg(test)]` here is equivalent (and canonical for tooling).
#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on in-memory fixtures where construction cannot fail"
    )]

    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use hippius_mem_core::{
        BlobStore, HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, NetworkPrefix,
        NoopAnchor, OpLogStore, SecretKey, Signer, Sr25519Signer,
    };
    use tower::ServiceExt;

    use super::{DashboardState, router};

    /// Anchor threshold high enough that the token tests never trip anchoring;
    /// mirrors the fixture in `src/server.rs`'s test module.
    const ANCHOR_THRESHOLD: usize = 16;

    fn test_state(token: &str) -> DashboardState {
        let blob: Arc<dyn BlobStore> = Arc::new(MemoryBlobStore::default());
        let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
        let key = SecretKey::from_bytes([7u8; 32]);
        let oplog = OpLogStore::new(blob.clone());
        let signer: Arc<dyn Signer> = Arc::new(
            Sr25519Signer::from_seed_with_prefix(&[5u8; 32], NetworkPrefix::HIPPIUS)
                .expect("valid test seed"),
        );
        let store = Arc::new(MemoryStore::new(
            blob,
            index,
            oplog,
            Arc::new(NoopAnchor),
            signer,
            std::collections::BTreeMap::from([(0_u64, key)]),
            0,
            "test-team".to_owned(),
            ANCHOR_THRESHOLD,
        ));
        DashboardState {
            store,
            token: Arc::from(token),
        }
    }

    #[tokio::test]
    async fn missing_token_is_unauthorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn correct_token_is_authorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview?t=secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_token_is_unauthorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview?t=not-the-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn header_token_is_authorized() {
        let app = router(test_state("secret-token"));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/overview")
                    .header("x-dashboard-token", "secret-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
