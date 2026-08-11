# Bench re-check — does the 2026-06-27 baseline still hold?

Date: 2026-08-11
Commit: `5d6f18a` (branch `test/coverage-completion`)
Host: `aarch64-apple-darwin` (Apple Silicon)
Toolchain: Rust **1.97.1** (`rust-toolchain.toml`)
Command: `cargo bench -p hippius-mem-core --bench store_benches`

Run before wiring the benches into `.github/workflows/nightly.yml`, to check that
the harness in `docs/perf/2026-06-27-phase4-baseline.md` still executes and still
describes the benches that exist. A baseline that quietly stopped matching is a dead
signal, which is the exact failure this nightly job is meant to prevent.

## The bench set still matches

`hippius-mem-core/benches/store_benches.rs` defines exactly the three benches the
2026-06-27 note measures — `recall`, `history_hot_note`, `sync_cold_rebuild` — with
`CORPUS_NOTES = 500` and `HOT_LINKS = 250`, which is that note's "realistic corpus"
row. Nothing was renamed, added, or removed. `sample_size(10)` is unchanged.

(The plan text for this task calls the middle bench `history`; its real name is
`history_hot_note`.)

## Medians, against the 2026-06-27 "after" column

Three runs, same machine, same binary, nothing changed between them:

| bench | 2026-06-27 | run 1 | run 2 | run 3 | vs baseline |
|-------|-----------:|------:|------:|------:|-------------|
| `recall` | 225.26 µs | 225.19 µs | 226.38 µs | 227.79 µs | unchanged |
| `history_hot_note` | 34.164 ms | 33.232 ms | 32.798 ms | 33.583 ms | unchanged (marginally faster) |
| `sync_cold_rebuild` | 34.755 ms | 40.652 ms | 43.952 ms | 40.394 ms | **+16 % to +26 %** |

Two of three land on the old numbers; `recall` matches to within 0.03 % on run 1.
`sync_cold_rebuild`'s runs 1 and 3 cluster at about +17 %; run 2 is the high one.

`sync_cold_rebuild` does not, and the other two are what make that interesting. A
faster or slower host shifts all three benches together; here the two that share
`OpLogStore::read_all` with `sync` — `recall` (which does not) and `history_hot_note`
(which does) — both sit on their old medians while `sync_cold_rebuild` alone moved.
That points at code, not hardware.

This note does **not** claim a regression. Two things prevent it: the 2026-06-27 note
records no host, so its absolute numbers may have come from different hardware; and a
great deal of `store/mod.rs` changed between the two dates (incremental sync,
checkpoints, snapshot content-addressing), so a cold rebuild is not doing the same
work it did then. It is flagged here as the one number worth attributing before
anyone treats the 2026-06-27 table as current.

## Run-over-run variance, which is why the nightly is not a gate

Run 2 is the same binary on the same machine with no change in between. criterion's
own comparison of run 2 against run 1:

| bench | change (95 % CI) | p | verdict |
|-------|------------------|--:|---------|
| `recall` | [-2.66 %, +4.96 %] | 0.61 | No change in performance detected |
| `history_hot_note` | [-5.44 %, +7.69 %] | 0.88 | No change in performance detected |
| `sync_cold_rebuild` | [+0.12 %, +10.39 %] | 0.09 | No change in performance detected |

At `sample_size(10)` the interval is already ±5-10 % on an idle laptop. A shared
hosted runner is worse. Any threshold tight enough to catch a real 10 % regression
would fire on noise most nights, so the nightly job reports and never fails.

## The comparison needs its own storage

criterion computes the `change:` line from estimates saved under `target/criterion/`.
Verified here: run 1 started with no such directory and printed only `time:` lines,
with no comparison at all; run 2 printed `change:` and a verdict. A hosted runner
starts every job with that directory absent, so without something carrying it between
runs the nightly would print three `time:` lines and no signal. The `bench` job in
`.github/workflows/nightly.yml` restores it from an `actions/cache` entry under a
rolling key for that reason.

## Reproduce

```sh
cargo bench -p hippius-mem-core --bench store_benches
```

`--bench store_benches` and not a bare `cargo bench -p hippius-mem-core`: the bare
form (and `--benches`) also selects targets carrying the default `bench = true`, so it
builds the crate's lib test harness in the release profile and runs it for a result of
"0 passed; 495 ignored" before reaching the criterion target.
