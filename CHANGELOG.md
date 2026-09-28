# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `hippius-mem profile`: times each cold-start phase (store build, refresh probe,
  op-log read + verify, checkpoint load, cold sync and re-sync, recall) against the
  bound team's real bucket, splitting wall time from S3 time with LIST/GET counts
  and bytes. The gateway is wrapped read-only, so it never writes to the bucket.
- `InstrumentedBlobStore` (core): a `BlobStore` decorator counting calls, S3 time
  and bytes per operation, with an optional read-only mode.
- `sync_phases` criterion bench: per-phase CPU cost over a 5,000-note corpus plus
  a round-trip census, run nightly beside `store_benches`.

### Changed

- The newest index checkpoint is cached (in memory, and beside the blob cache for
  S3 profiles) and reused while the bucket still lists it, instead of being
  downloaded on every sync. A new session and every refresh re-sync skip the
  download (90 MiB for a 4.6k-note team); measured cold sync 16s to 4.4s,
  re-sync ~19s to ~4s.

### Fixed

- An author's first sync in every new process no longer discards and re-runs its
  whole pass (op-log read, checkpoint download, rebuild): the install stamp is
  now taken after the read re-seeds the chain head. Halves cold-start sync time
  for anyone who has written a note (36s to 16s measured on a 4.6k-note team).
- Live-S3 CI job runs against versitygw (sha256-pinned release binary) instead
  of MinIO: MinIO archived the project, and neither `quay.io/minio/minio` nor
  dl.min.io serves it any more, which failed this required check on every PR.

## [0.3.0] - 2026-09-18

One shared MCP process per machine: Claude / Grok / Codex talk to
`hippius-mem serve` over loopback HTTP, so N sessions no longer each load
ONNX ([#108](https://github.com/thenervelab/hippius-mem/issues/108)).

### Added

- `hippius-mem serve`: loopback streamable-HTTP MCP daemon so N Grok/Claude/Codex
  sessions share one process and one ONNX load ([#108](https://github.com/thenervelab/hippius-mem/issues/108)).
  `install` (embeddings+http-mcp builds) writes a user LaunchAgent / systemd
  unit, points those clients at `http://127.0.0.1:17432/mcp` with a standing
  bearer token (Grok: `headers`; Codex: `http_headers` — Codex ignores
  Grok's key), and keeps Gemini/OpenClaw/Hermes on stdio. Bare `hippius-mem`
  is still the stdio server. `install` only rewrites those clients to HTTP
  after `/health` succeeds; otherwise it leaves stdio entries and prints a
  warning. The HTTP handshake tells agents to pass `repo` (omitted `repo` is
  team-global — the daemon has no client cwd). One process cannot route per
  repo, so `serve` refuses a config with more than one team profile or a sole
  org-routed profile; `install` also refuses a `storage = "local"` trial vault
  (a never-exiting service would own that vault's exclusive write role).
  `install --uninstall --agent grok` leaves the unit running if Claude or Codex
  still points at it. Flag parse and port bind happen before the ONNX load.
  HTTP sessions idle for up to 24 hours before eviction. Client configs that
  embed the bearer token are written `0600`.

### Fixed

- Hermes first-landing: `FOR-AGENTS.md` Goal 3 and the `AGENTS.md` / README
  opener now say "wire the client" (MCP for most agents, the memory-provider
  plugin for Hermes) instead of "register the MCP server".
- `scripts/install.sh` Done block tells Hermes to restart so the plugin loads.
- `hippius-mem doctor --offline` fails when Hermes is present but the plugin,
  sidecar, or `memory.provider` is missing, and names `install --agent hermes`.
  The check is on the `doctor` CLI only — not the encryption probe that
  `quickstart` / `upgrade` share — so `--solo` still finishes on a machine
  that already has `~/.hermes`.
- Hermes plugin `plugin.yaml` now lists `system_prompt_block`. `doctor --offline`
  treats a copied yaml that omits that hook as unwired (the 0.2.0 install).
  Re-run `hippius-mem install --agent hermes` (or `install.sh --update`).
- `cargo deny`: chacha20 0.10.2 — 0.10.1 was yanked (`rmcp` → `rand`).
- Source `scripts/install.sh` (`--from-source` / `--update`) now builds
  `embeddings,dashboard,http-mcp`, matching the shipped dist binary. Without
  `http-mcp`, `install --all-detected` would keep Claude/Grok/Codex on stdio.

## [0.2.0] - 2026-09-15

Hermes becomes a first-class client (native memory-provider plugin, not MCP),
and `install` stops silently rewriting every local agent config.

### Added

- Hermes memory-provider plugin (`install --agent hermes`): copies a stdlib
  Python plugin into `$HERMES_HOME/plugins/hippius-mem/`, pins the binary and
  `HIPPIUS_MEM_CONFIG` in a sidecar, and sets `memory.provider: hippius-mem`.
  Prefetch is `recall`; the session brief is the new `brief` MCP tool on one
  long-lived `hippius-mem` subprocess; the model sees `remember` / `recall` /
  `get`. Conversation turns are not auto-remembered.
- `brief` MCP tool: the same token-bounded digest the SessionStart CLI prints,
  so a long-lived server can inject conventions/gotchas without a second
  embedder load.
- `--hermes-home`, `--hermes-profile`, `--hermes-all-profiles` on `install`.
- `CHANGELOG.md`.

### Changed

- Bare `hippius-mem install` no longer autodetects. A TTY prompts; otherwise
  pass `--agent <name[,…]>` or `--all-detected`. `scripts/install.sh` already
  passed `--all-detected`.
- `hippius-mem init` no longer writes `~/.claude.json`. MCP registration is
  `install --agent claude`.
- `install --agent hermes` no longer registers an MCP server (the 11-tool
  schema does not fit Hermes's memory budget). A leftover `mcp_servers.hippius-mem`
  entry from 0.1.0 is stripped.
- Mandates and playbook wording: `recall` takes `text`; `remember` takes
  `note_type`.

### Fixed

- Hermes `is_available()` now finds the sidecar-pinned binary, not only PATH,
  so fleet/GUI launches without `hippius-mem` on PATH still activate.
- Installer tests no longer read process `HERMES_HOME` (would rewrite a real
  profile).
- `cargo deny`: rustls 0.23.45 for [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285).
- Live-MinIO CI pulls `quay.io/minio/minio` (Docker Hub `minio/minio` was removed).

## [0.1.0] - 2026-09-09

First public release: encrypted, signed, hash-chained team memory as an MCP
stdio server, with semantic recall (`bge-small-en-v1.5`), Claude Code / Grok
hooks, and cargo-dist prebuilts.

[Unreleased]: https://github.com/thenervelab/hippius-mem/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/thenervelab/hippius-mem/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/thenervelab/hippius-mem/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/thenervelab/hippius-mem/releases/tag/v0.1.0
