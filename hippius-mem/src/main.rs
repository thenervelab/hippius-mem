//! Hippius Memory MCP server binary entry point.
//!
//! Serves the `remember` / `recall` / `get` tools over stdio. For now the store
//! is a process-local in-memory placeholder so the binary runs end to end; Task
//! 9 (config) replaces it with the real S3-backed store.

mod server;

use std::error::Error;
use std::sync::Arc;

use hippius_mem_core::{
    HashEmbedder, InMemoryIndex, MemoryBlobStore, MemoryStore, SecretKey, Ss58,
};
use rmcp::ServiceExt;
use rmcp::transport::stdio;

use crate::server::MemoryServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // TODO(Task 9): build MemoryStore from real config (S3 sub-token, team key, author).
    let store = placeholder_store()?;
    let service = MemoryServer::new(store).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Build an in-memory placeholder store so the binary runs before Task 9 wires
/// real configuration. All state is process-local and lost on exit; the key is
/// all-zero and the author is a well-formed placeholder SS58 address.
fn placeholder_store() -> Result<Arc<MemoryStore>, Box<dyn Error + Send + Sync>> {
    let blob = Arc::new(MemoryBlobStore::default());
    let index = Arc::new(InMemoryIndex::new(Arc::new(HashEmbedder::default())));
    let key = SecretKey::from_bytes([0u8; 32]);
    let author = Ss58::new("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")?;
    Ok(Arc::new(MemoryStore::new(
        blob,
        index,
        key,
        "placeholder-team".to_owned(),
        author,
    )))
}
