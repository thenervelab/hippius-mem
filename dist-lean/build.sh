#!/usr/bin/env bash
# Builds the lean (no-embeddings) hippius-mem binary for the one target that
# cannot compile the `embeddings` feature: x86_64-apple-darwin has no prebuilt
# ONNX Runtime in ort-sys 2.0.0-rc.12 (ONNX Runtime >= 1.24 dropped the
# platform), so ort-sys hard-errors at build time. See dist-lean/dist.toml.
set -euo pipefail

# dist runs build-command from this package directory; the Cargo workspace is
# one level up. CARGO_DIST_TARGET is the triple dist wants us to produce.
target="${CARGO_DIST_TARGET:?dist always sets CARGO_DIST_TARGET for generic builds}"

# GitHub's macOS images ship rustup; the workspace's rust-toolchain.toml pins
# the toolchain, which rustup auto-installs on first cargo invocation. The
# explicit `target add` covers a host!=target invocation (e.g. a local
# `dist build` from an arm64 Mac).
rustup target add "$target"

# --locked: the lean artifact must resolve the exact Cargo.lock the three
# dist-built artifacts use; without it this build could silently re-resolve
# newer deps and ship a different dependency tree than the rest of the release.
cargo build --locked --profile dist -p hippius-mem --features dashboard --target "$target" \
  --manifest-path ../Cargo.toml

# dist looks for the declared `binaries` relative to this package directory.
cp "../target/$target/dist/hippius-mem" ./hippius-mem
