# Releasing hippius-mem

Operator runbook for the cargo-dist release pipeline (`dist-workspace.toml` +
`.github/workflows/release.yml`). Release posture per decision gate D1
(2026-07-12): the source repo stays **private**; releases publish to the
**public** `thenervelab/hippius-mem-releases` repo so external users install
prebuilt binaries without repo access.

Artifacts per release tag `v{VERSION}`:

| Target | App | Features |
|---|---|---|
| aarch64-apple-darwin | `hippius-mem` | `embeddings,dashboard` |
| x86_64-unknown-linux-gnu | `hippius-mem` | `embeddings,dashboard` |
| aarch64-unknown-linux-gnu | `hippius-mem` | `embeddings,dashboard` (native `ubuntu-24.04-arm` runner) |
| x86_64-apple-darwin | `hippius-mem-lean` | `dashboard` only — ONNX Runtime ≥ 1.24 ships no Intel-mac library, so this artifact has lexical-only recall (see README "Retrieval honesty") |

## 1. Ready-to-fire checklist (run top to bottom when the green light lands)

1. Create the public repo `thenervelab/hippius-mem-releases` (one commit on
   the default branch).
2. Create a `repo`-scoped PAT for it; store as `GH_RELEASES_TOKEN` in
   `thenervelab/hippius-mem`.
3. Create a second PAT scoped to push access on `thenervelab/homebrew-tap`
   (classic `repo` scope, or fine-grained with Contents: Read and write
   limited to that one repo); store as `HOMEBREW_TAP_TOKEN` in
   `thenervelab/hippius-mem`. This is distinct from `GH_RELEASES_TOKEN`: the
   `publish-homebrew-formula` job that `publish-jobs = ["homebrew"]` adds to
   `release.yml` checks out and pushes to the tap repo with this token, not
   the releases-repo one. Without it, the homebrew publish job fails even
   after `host` has already succeeded.
4. Preflight both tokens BEFORE tagging — a bad token otherwise surfaces only
   after the ~30-minute build matrix (and, for the tap token, only after
   `host` too) has already run:

   ```sh
   GH_TOKEN=$GH_RELEASES_TOKEN gh api repos/thenervelab/hippius-mem-releases
   GH_TOKEN=$HOMEBREW_TAP_TOKEN gh api repos/thenervelab/homebrew-tap
   ```

   Both must return their repo (not 404/401).
5. Version-lockstep PR: 0.1.0 in `hippius-mem/Cargo.toml`,
   `hippius-mem-core/Cargo.toml`, `dist-lean/dist.toml`; confirm the
   `version-lockstep` workflow passed BEFORE tagging.
6. Tag the merged commit `v0.1.0` and push the tag.
7. Verify on a clean machine: `brew install thenervelab/tap/hippius-mem &&
   hippius-mem doctor --offline`.
8. Verify `sh scripts/install.sh` takes the binary path on a machine with no
   Rust toolchain.
9. Flip the README Install section to binary-first (brew, then install.sh,
   then source).

## 2. Cutting a release

1. Bump **all three** version fields together, on a PR:
   - `hippius-mem/Cargo.toml`
   - `hippius-mem-core/Cargo.toml`
   - `dist-lean/dist.toml`

   For a release candidate use the prerelease form in all three (e.g.
   `0.2.0-rc.1`) — dist's `plan` job fails if the tag's version does not
   match the manifests, so tag `v0.2.0-rc.1` requires manifests at
   `0.2.0-rc.1`. dist marks prerelease-suffixed tags as GitHub prereleases.
2. Confirm the `version-lockstep` workflow passed on that bump PR **before
   tagging**. (It only runs on PRs — a direct push to main bypasses it, so
   this confirmation is the backstop.)
3. Run the token preflight from section 1.
4. Tag the merged commit and push the tag:

   ```sh
   git tag v0.2.0-rc.1 && git push origin v0.2.0-rc.1
   ```

5. The `Release` workflow builds the four artifacts and publishes the
   GitHub Release on `thenervelab/hippius-mem-releases`. `source-tarball =
   false` keeps the private source off the public release — never remove it.

## 3. Upgrading cargo-dist

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
   8 template-injection** findings. Anything beyond that is new — review it,
   don't assume it's covered.
3. Re-verify the `[dist.github-action-commits]` pin table: the new template
   may use different actions or major versions; re-resolve each tag to a
   full commit SHA and update the `# vX.Y.Z` comments.
4. `dist plan` must still show all four targets across the two apps;
   `actionlint` and `zizmor` must be clean.
