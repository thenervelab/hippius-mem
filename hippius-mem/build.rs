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
//! the symbol undefined for the loader to find at run time, which the system
//! libraries of older macOS releases may not provide. Linking the archive
//! defines it in the binary on every SDK.
//!
//! Turning off LTO also keeps std's copy, but it grows the binary on all four
//! release targets for a macOS-only problem. Delete this script when the
//! upstream issue is fixed in the pinned toolchain.

use std::process::Command;

#[expect(
    clippy::expect_used,
    reason = "a build script reports failure by panicking; each message names the fix"
)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let embeddings = std::env::var_os("CARGO_FEATURE_EMBEDDINGS").is_some();
    if target_os != "macos" || !embeddings {
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

    println!("cargo:rustc-link-search=native={}", runtime_dir.trim());
    println!("cargo:rustc-link-lib=static=clang_rt.osx");
}
