//! Links clang's compiler runtime into macOS builds that include ONNX Runtime.
//!
//! The only aarch64-apple-darwin ONNX Runtime that ort 2.0.0-rc.15 ships is
//! the `CoreML` build, and its Objective-C `@available` checks compile to calls
//! to `___isPlatformVersionAtLeast`, which lives in clang's
//! `libclang_rt.osx.a`. rustc links with `-nodefaultlibs`, so clang does not
//! add that archive. std exports a weak copy of the symbol (Rust 1.91+), but
//! the thin LTO of `[profile.dist]` drops it because no Rust code references
//! it (<https://github.com/rust-lang/rust/issues/164915>). The v0.6.0 release
//! build then failed with "Undefined symbols: ___isPlatformVersionAtLeast" on
//! the macos-15 runner. On a newer SDK (Xcode 27) the link succeeds but leaves
//! the symbol to be bound at run time, and no macOS system library exports
//! it, so the first `CoreML` version check would abort. Passing the archive to
//! the binary's link defines it there on every SDK; the linker pulls only the
//! archive member that defines it.
//!
//! Turning off LTO also keeps std's copy, but it grows the binary on all four
//! release targets for a macOS-only problem. `rustc-link-lib=static` is not
//! used because it bundles the whole archive into the lib rlib, ahead of
//! `compiler_builtins`, so `clang_rt` would replace about a dozen other
//! builtins too.
//!
//! TODO(GeorgiosDelkos, rust-lang/rust#164915): delete this script once the
//! pinned toolchain keeps std's copy under LTO.

use std::process::Command;

#[expect(
    clippy::expect_used,
    reason = "a build script reports failure by panicking"
)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let embeddings = std::env::var_os("CARGO_FEATURE_EMBEDDINGS").is_some();
    // `cfg!` in a build script describes the host. A cross `cargo check` from
    // Linux never links, and there is no `xcrun` to ask.
    if target_os != "macos" || !embeddings || !cfg!(target_os = "macos") {
        return;
    }

    let output = Command::new("xcrun")
        .args(["clang", "--print-runtime-dir"])
        .output()
        .expect("run `xcrun clang --print-runtime-dir`: install the Xcode command line tools");
    assert!(
        output.status.success(),
        "`xcrun clang --print-runtime-dir` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runtime_dir =
        String::from_utf8(output.stdout).expect("clang prints its runtime directory as UTF-8");
    let archive = format!("{}/libclang_rt.osx.a", runtime_dir.trim());
    assert!(
        std::path::Path::new(&archive).exists(),
        "{archive} not found: install the Xcode command line tools or set DEVELOPER_DIR"
    );

    // The path carries clang's major version. Watching it reruns this script
    // when an Xcode update removes it or DEVELOPER_DIR changes; an
    // `xcode-select` switch that keeps the old Xcode installed needs
    // `cargo clean -p hippius-mem`.
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-changed={archive}");
    println!("cargo:rustc-link-arg-bins={archive}");
}
