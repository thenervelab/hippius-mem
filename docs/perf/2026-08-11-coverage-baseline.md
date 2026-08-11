# Coverage baseline — first `cargo llvm-cov` measurement

Date: 2026-08-11
Commit: `5d6f18a` (branch `test/coverage-completion`)
Host: `aarch64-apple-darwin` (Apple Silicon)
Toolchain: Rust **1.97.1** (`rust-toolchain.toml`) plus the `llvm-tools-preview` component
Tool: `cargo-llvm-cov` **0.8.7**
Command: `cargo llvm-cov --workspace --all-features --locked --no-report`, then
`cargo llvm-cov report --summary-only`

Suite as measured: **1010 passed, 0 failed, 16 ignored** (all-features; the ignored
set is the live-gateway and real-model tests that semantic-nightly.yml and rust.yml's
MinIO job own). The default-features suite at the same commit is 922 passed / 0
failed / 7 ignored.

## This is a baseline, not a target

There is deliberately no percentage gate in `.github/workflows/nightly.yml`, and one
should not be added. A ratio rewards covering whatever is cheapest to cover. Every
gap the 2026-08 coverage pass closed was a handful of lines on a hard path — the
chain anchor readback, `doctor`'s S3 branch, the semantic dedup gate — and a number
raised by testing getters and `Display` impls would have gone up while all three
stayed untested. Worse, a gate punishes the PR that finally covers a hard path if it
also adds uncovered code beside it.

Compare a later run against these numbers. Do not compare either against a
round-number goal.

## Top line

| Metric | Total | Missed | Cover |
|--------|------:|-------:|------:|
| Regions | 45,754 | 5,644 | **87.66 %** |
| Functions | 3,129 | 318 | **89.84 %** |
| Lines | 26,430 | 2,025 | **92.34 %** |

## The line number is inflated, and by how much

`llvm-cov` instruments `#[cfg(test)] mod tests` bodies as ordinary code. This
workspace keeps most of its tests inline at the bottom of the source file — 6,100 of
`store/mod.rs`'s 10,884 lines are its test module — so those lines, which are
near-100 % covered by construction, sit in the denominator above.

Recomputing from the same `lcov.info` while discarding every record at or below each
file's last top-level `#[cfg(test)]`:

| Denominator | Covered / total | Cover |
|-------------|----------------:|------:|
| All instrumented lines | 22,886 / 24,690 | **92.69 %** |
| Production lines only (inline test modules cut) | 7,654 / 8,946 | **85.56 %** |

Seven points. That gap is the concrete reason a percentage gate on the headline
number would measure the wrong thing.

Two caveats on the derived figure. The cut point is each file's last top-level
`#[cfg(test)]`, which is exact for this repo's convention (tests last) but would
misattribute a `#[cfg(test)]` helper placed mid-file. And the all-lines figure here
(92.69 %) differs slightly from `--summary-only`'s 92.34 % because lcov `DA:` records
and llvm-cov's own line metric count multi-region lines differently; the headline
table above is llvm-cov's own arithmetic, unmodified.

## Lowest-covered files (region coverage)

| File | Regions | Missed | Cover |
|------|--------:|-------:|------:|
| `hippius-mem/src/gc.rs` | 51 | 51 | **0.00 %** |
| `hippius-mem/src/brief.rs` | 80 | 42 | 47.50 % |
| `hippius-mem/src/main.rs` | 251 | 128 | 49.00 % |
| `hippius-mem/src/mint.rs` | 163 | 74 | 54.60 % |
| `hippius-mem-core/src/index/fastembed.rs` | 263 | 99 | 62.36 % |
| `hippius-mem-core/src/audit/anchor.rs` | 504 | 157 | 68.85 % |
| `hippius-mem/src/admin.rs` | 1,510 | 424 | 71.92 % |
| `hippius-mem/src/upgrade.rs` | 896 | 192 | 78.57 % |
| `hippius-mem/src/invite.rs` | 421 | 90 | 78.62 % |

Read that list with its reasons, not as a to-do ranking:

- **`gc.rs` at 0.00 % is the one genuine finding here.** No test executes a single
  line of the `gc` subcommand — the mark-and-sweep that *deletes blobs from the
  team's bucket*. Its 27 production lines and 3 functions are entirely unexecuted.
  Of everything in this table it is the only entry whose emptiness is not explained
  by something structural.
- `fastembed.rs` and `audit/anchor.rs` are low because their expensive halves are
  reached only by tests that are `#[ignore]`d (the real ONNX model) or need a live
  chain node (`SubxtAnchor`). Those paths are covered by semantic-nightly.yml, which
  this measurement does not include.
- `main.rs` is argv dispatch and process exit; `brief.rs` and `mint.rs` are thin
  command wrappers over covered library code.

## Reproduce

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked --version 0.8.7

cargo llvm-cov --workspace --all-features --locked --no-report
cargo llvm-cov report --summary-only
cargo llvm-cov report --lcov --output-path lcov.info
```

`--all-features` loads the real embedding model: `Config::semantic_embeddings`
defaults to `cfg!(feature = "embeddings")`, so ten non-`#[ignore]`d tests reach
`FastEmbedder::try_with` and one runs a real `embed`. On a machine with a cold
`~/.cache/hippius-mem/fastembed` that is a ~90 MB download before the suite can
finish.
