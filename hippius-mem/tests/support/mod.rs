//! The binary under test, spawned without the caller's `HIPPIUS_MEM_*`
//! settings.
//!
//! The config loader overlays every `HIPPIUS_MEM_*` variable on the config
//! file, so a developer's ambient `HIPPIUS_MEM_TEAM_KEY_HEX` (or any other)
//! would change what a spawned test binary does. Each test sets what it needs
//! on the returned command.

use std::process::Command;

/// The `hippius-mem` binary with every inherited `HIPPIUS_MEM_*` variable
/// removed, except `HIPPIUS_MEM_ALLOW_INSECURE_ENDPOINT`: the live suites run
/// against a plain-HTTP loopback gateway, and the caller's choice to allow it
/// is passed through.
pub(crate) fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hippius-mem"));
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| {
            name.starts_with("HIPPIUS_MEM_") && name != "HIPPIUS_MEM_ALLOW_INSECURE_ENDPOINT"
        }) {
            command.env_remove(name);
        }
    }
    command
}
