# Dashboard one-command launch: auto-open the browser + bundle in the installer

Date: 2026-07-06
Branch: `feat/dashboard-auto-open`

## Problem

Launching the dashboard takes three manual steps today, two of which are avoidable
friction:

1. **It is not installed.** `scripts/install.sh` builds `--features embeddings` only, so
   a user who ran the installer cannot run `hippius-mem dashboard` — the subcommand bails
   asking them to rebuild with `--features dashboard`.
2. **It does not open the browser.** `dashboard::run` logs the token URL to stderr
   (`dashboard/mod.rs`, the `listening` line) and stops there; the user copies a
   `http://127.0.0.1:<port>/?t=<token>` URL into a browser by hand.

Target experience (chosen): run `hippius-mem dashboard`, the browser opens at the token
URL. No rebuild, no copy-paste. It stays a foreground command (not a background service).

## Goals

1. **Bundle the dashboard in the installer** so a fresh install can run it with no rebuild.
2. **Auto-open the default browser** at the token URL when `hippius-mem dashboard` starts.
3. **Degrade cleanly** where auto-open is wrong (servers, SSH tunnels): an explicit
   `--no-open` flag and an automatic headless skip, both falling back to today's printed
   URL.

## Non-goals

- A background service / always-on server-hosted dashboard (a larger change; rejected in
  favor of the one-command model).
- A native desktop / menu-bar launcher (per-OS packaging; out of scope).
- Adding a browser-launching dependency (`open`/`webbrowser` crate): the zero-dependency
  OS opener is preferred, matching the project's dependency discipline.

## Design

### Behavior

`hippius-mem dashboard [--port <n>] [--no-open]`:

1. Bind the loopback listener and mint the per-launch token (unchanged).
2. Log the `http://127.0.0.1:<port>/?t=<token>` line to stderr (unchanged — always the
   fallback path).
3. **Then** attempt to open the browser at that exact URL, unless suppressed. Serve until
   Ctrl-C.

**Ordering is the one correctness point.** Open the browser only *after* the listener is
bound and accepting; opening before `serve()` is ready races the browser to a dead port
("connection refused"). The open happens in the gap between "listener bound" and the
`serve` await.

**Suppression precedence:** `--no-open` OR `is_headless(env)` ⇒ skip and log a hint; else
attempt.

### Data structures / seam

Keep the OS shell-out at the edge; the decisions are pure and unit-testable (the
extract-a-seam pattern the project already uses for feature-gated/live-service code):

- `fn browser_command(url: &str) -> (&'static str, Vec<String>)` — pure per-OS mapping via
  `cfg!(target_os = …)`: `open` (macOS), `xdg-open` (Linux/other), `cmd /c start ""`
  (Windows). No I/O.
- `fn is_headless(env: &BrowserEnv) -> bool` — pure predicate over injected env values:
  true when `SSH_CONNECTION`/`SSH_TTY` is set, or (Linux only) neither `DISPLAY` nor
  `WAYLAND_DISPLAY` is set. `BrowserEnv` is a tiny struct of the relevant `Option<String>`
  values so the test injects them without touching the real environment.
- `fn open_in_browser(url: &str)` — the only I/O boundary: builds the command, `.spawn()`s
  it (never `.status()`/`.output()` — do not block the CLI on the browser), and on spawn
  error logs `tracing::warn!` and returns. Deliberately trivial so the untested part is
  minimal.

### Ownership / concurrency

No shared state, no async. `open_in_browser` spawns a child and drops the handle (the
opener exits in milliseconds; a short-lived unreaped child until the server exits is
acceptable for a foreground CLI, the same lifetime rationale as the omitted
flush-on-shutdown). Nothing crosses a thread or `.await`.

### Error strategy

No new error variants. Browser-open is best-effort: a spawn failure is a `tracing::warn!`,
never propagated, so it cannot fail the `dashboard` command. The URL is already printed,
so the user always retains the copy-paste fallback. This matches the existing best-effort,
non-fatal startup paths (epoch bootstrap, warmup sync).

### Installer

`scripts/install.sh` (the two `cargo install` lines and the header comment): change
`--features embeddings` → `--features embeddings,dashboard`. The `dashboard` feature is
pure-Rust `axum` — light compile, and **no** runtime download (unlike the ONNX model
behind `embeddings`) — so bundling it costs a little binary size and nothing at runtime.

### README

The Dashboard section drops the "build with `--features dashboard`" framing → "the
installer already includes it; run `hippius-mem dashboard`". The manual-install note keeps
the explicit feature for from-source builds. The `--no-open` flag is documented for
headless/tunnel use.

## Test plan

Pure functions, no spawning in tests (the spawn is the mocked-out OS boundary):

- `browser_command` returns the expected program for the compiled `target_os` (`open` on
  macOS, `xdg-open` on Linux) with the URL as the final argument.
- `is_headless`: true when SSH env is present; on Linux true when both display vars are
  unset and false when either is set; SSH presence dominates.
- CLI parsing: `--no-open` is recognized alongside `--port`; order-independent; an unknown
  flag still errors as today.

The end-to-end "browser actually opened" is not asserted — it is the OS boundary the seam
keeps thin; its inputs (command choice, headless decision, flag) are covered by the pure
tests.
