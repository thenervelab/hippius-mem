# Releasing hippius-mem

Operator runbook for the cargo-dist release pipeline (`dist-workspace.toml` +
`.github/workflows/release.yml`). Pushing a version tag publishes prebuilt
binaries as GitHub Releases on **this** repository
(`thenervelab/hippius-mem`). `scripts/install.sh` fetches the matching
archive from `releases/latest`, verifies the sha256, and falls back to a
source build if no asset exists.

The dedicated `thenervelab/hippius-mem-releases` repo was a D1
private-source workaround and is not used. Do not recreate it or set
`GH_RELEASES_TOKEN`.

Artifacts per release tag `v{VERSION}`:

| Target | App | Features |
|---|---|---|
| aarch64-apple-darwin | `hippius-mem` | `embeddings,dashboard` |
| x86_64-unknown-linux-gnu | `hippius-mem` | `embeddings,dashboard` (native `ubuntu-24.04`; ONNX Runtime needs glibc 2.38+) |
| aarch64-unknown-linux-gnu | `hippius-mem` | `embeddings,dashboard` (native `ubuntu-24.04-arm`) |
| x86_64-apple-darwin | `hippius-mem-lean` | `dashboard` only — ONNX Runtime ≥ 1.24 ships no Intel-mac library, so this artifact has lexical-only recall (see README "Retrieval honesty") |

All four artifacts are built with Cargo `[profile.dist]`: thin LTO, one
codegen unit, symbol strip. That is cargo-dist's recommended release
profile plus the two size/optimization knobs that stay cheap enough in CI.
Fat LTO is not used — it would multiply CI time on the ONNX-linked targets
for little gain on an I/O-bound MCP server. Portable releases must not set
`target-cpu = "native"`. `dist-lean/build.sh` uses `--profile dist` so the
Intel-mac artifact matches the other three.

## 1. Ready-to-fire checklist

1. Create a PAT scoped to push access on `thenervelab/homebrew-tap`
   (classic `repo` scope, or fine-grained with Contents: Read and write
   limited to that one repo); store as `HOMEBREW_TAP_TOKEN` in
   `thenervelab/hippius-mem`. The `publish-homebrew-formula` job that
   `publish-jobs = ["homebrew"]` adds to `release.yml` checks out and
   pushes to the tap with this token. Without it, the homebrew job fails
   even after `host` has already published the GitHub Release. GitHub
   Releases themselves use `GITHUB_TOKEN` (`contents: write` on this
   repo) — no extra PAT.
2. Preflight the tap token BEFORE tagging — a bad token otherwise
   surfaces only after the ~30-minute build matrix and `host` have
   already run:

   ```sh
   GH_TOKEN=$HOMEBREW_TAP_TOKEN gh api repos/thenervelab/homebrew-tap
   ```

   Must return the repo (not 404/401).
3. Version-lockstep: `hippius-mem/Cargo.toml`,
   `hippius-mem-core/Cargo.toml`, and `dist-lean/dist.toml` must share
   the same version. Confirm the `version-lockstep` workflow passed on
   the bump PR BEFORE tagging. (It only runs on PRs — a direct push to
   main bypasses it.)
4. Tag the merged commit `v{VERSION}` and push the tag.
5. Verify on a clean machine with no Rust toolchain:
   `sh scripts/install.sh` takes the binary path (sha256-verified
   prebuilt, not a source build).
6. Verify `brew install thenervelab/tap/hippius-mem && hippius-mem
   doctor --offline` on a clean machine.
7. After 5 and 6 pass, the README Install section can lead with
   Homebrew (`brew install thenervelab/tap/hippius-mem`), then
   `install.sh`, then source. Until then it correctly describes
   `install.sh` (prebuilt from this repo's GitHub Releases, source
   fallback).

## 2. Cutting a release

1. Bump **all three** version fields together, on a PR:
   - `hippius-mem/Cargo.toml`
   - `hippius-mem-core/Cargo.toml`
   - `dist-lean/dist.toml`

   For a release candidate use the prerelease form in all three (e.g.
   `0.2.0-rc.1`) — dist's `plan` job fails if the tag's version does not
   match the manifests, so tag `v0.2.0-rc.1` requires manifests at
   `0.2.0-rc.1`. dist marks prerelease-suffixed tags as GitHub
   prereleases and does not push them to Homebrew unless
   `publish-prereleases = true`.
2. Confirm the `version-lockstep` workflow passed on that bump PR
   **before tagging**.
3. Run the tap-token preflight from section 1.
4. Tag the merged commit and push the tag:

   ```sh
   git tag v0.1.0 && git push origin v0.1.0
   ```

5. The `Release` workflow builds the four artifacts and publishes the
   GitHub Release on `thenervelab/hippius-mem`. `source-tarball = false`
   keeps dist from uploading a second source tarball — GitHub already
   attaches one from the tag. Never remove it.

First public cut: manifests are already `0.1.0`, so skip the bump PR
and tag `v0.1.0` on the commit that merged this pipeline onto `main`.

## 3. What a user gets

- **GitHub Release** at
  `https://github.com/thenervelab/hippius-mem/releases/tag/v{VERSION}`
  with per-target `.tar.xz` archives and `.sha256` files.
- **`scripts/install.sh`** downloads
  `https://github.com/thenervelab/hippius-mem/releases/latest/download/{app}-{triple}.tar.xz`
  (Intel mac: `hippius-mem-lean-x86_64-apple-darwin.tar.xz`).
- **Homebrew** formula on `thenervelab/homebrew-tap`:
  `brew install thenervelab/tap/hippius-mem`.
- cargo-dist also uploads `hippius-mem-installer.sh` (binary-only curl
  installer into `CARGO_HOME`). Prefer `scripts/install.sh`: it wires
  config, MCP, and `doctor`. Use `--from-source` to skip the prebuilt.

## 4. Upgrading cargo-dist

1. Bump `cargo-dist-version` in `dist-workspace.toml`, install that dist
   locally, run `dist init --yes` (or `dist generate`), and review the
   `release.yml` diff.
2. Re-audit the regenerated template — the zizmor ignores in
   `.github/zizmor.yml` are category-wide for `release.yml`, so a new
   injection sink would be silently covered:

   ```sh
   zizmor --no-config .github/workflows/release.yml
   ```

   Baseline for the 0.32.0 template: **1 excessive-permissions +
   8 template-injection** findings. Anything beyond that is new — review
   it, don't assume it's covered.
3. Re-verify the `[dist.github-action-commits]` pin table: the new
   template may use different actions or major versions; re-resolve each
   tag to a full commit SHA and update the `# vX.Y.Z` comments.
4. `dist plan` must still show all four targets across the two apps;
   `actionlint` and `zizmor` must be clean.

   Invoke zizmor with `--config .github/zizmor.yml` explicitly — bare
   `zizmor .github/workflows/release.yml` relies on local auto-discovery,
   which has been observed to not reliably apply this file's combined
   ignore rules (confirmed reproducible on zizmor 1.29.0, 2026-08-08).
