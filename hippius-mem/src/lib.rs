//! Library surface for the `hippius-mem` binary.
//!
//! `hippius-mem` ships as a binary (`main.rs`), and this `[lib]` target
//! historically did not exist: every module lived only inside `main.rs`'s
//! private module tree, unreachable from anywhere outside the compiled
//! binary. That made `server.rs`'s MCP tool surface untestable except by
//! calling its transport-free `logic_*` methods from `server.rs`'s own unit
//! test module — the macro-generated `call_tool` dispatch an agent actually
//! talks to (see `tests/mcp_protocol.rs`) had no test standing outside
//! `server.rs`.
//!
//! `main.rs` now depends on this crate for `server`, exactly as any other
//! consumer would, so `server.rs` is still compiled exactly once; nothing
//! about the shipped binary's behavior changes.
pub mod server;
