# External-Adoption Program Implementation Plan

> **Status: completed — historical record.** This plan was executed; do not re-run
> it. Kept for the rationale and task breakdown.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Every Rust-bearing task additionally runs the full Rust review discipline (plan the data structures first, then run tests + clippy and answer the adversarial self-review before finalizing), and every session starts with `mcp__hippius-mem__recall` on the task.

**Goal:** Open the adoption funnel so an external engineering team can install, trial solo, and run hippius-mem as a team — without repo access, a Rust toolchain, a Hippius account, or a founder runbook.

**Architecture:** Seven propositions (recorded in team memory as `mem_01KXB0SZWS4PEEPABHHYAZ83KM`) grouped into six phases, ordered so cheap verifications land first and each phase ships as its own PR off `main`. The substrate (op-log, crypto, recall precision) is untouched; all work is distribution, CLI lifecycle, onboarding UX, and docs. Cross-cutting rule inherited from the second-brain program: every state change stays a signed op; no side channels.

**Tech Stack:** Rust 1.92 workspace (`hippius-mem-core`, `hippius-mem`), cargo-dist + GitHub Actions for release artifacts, clap CLI, aws-sdk-s3 (already endpoint-configurable), existing `--features embeddings,dashboard,console,chain,import` feature matrix.

**Hippius-first (program constraint, 2026-07-12):** this is a Hippius ecosystem product. Hippius S3 is the default and headline backend in every doc, prompt, and quickstart; adoption growth is meant to pull users toward Hippius storage. Generic-S3 compatibility (Phases 0/3) is a de-risking fallback for teams that cannot adopt Hippius storage on day one — documented, tested, never the pitch.

---

## Decision gates (resolve with the user before the phase that needs them)

| Gate | Needed by | Options | Recommendation |
|------|-----------|---------|----------------|
| **D1: Release posture** | Phase 1 | (a) public repo, (b) private repo + public GitHub Releases, (c) stay fully private | **RESOLVED 2026-07-12: (b)** — private repo + public GitHub Releases. Revisit (a) later; the "verify, don't trust" pitch eventually wants source open. |
| **D2: Default backend for outsiders** | Phase 3 | (a) Hippius S3 default, generic S3 documented option; (b) neutral default | **RESOLVED 2026-07-12: (a)** — user directive: this is a Hippius project; Hippius S3 is the default and the pitch, generic S3 is the compatibility fallback. |
| **D3: Console Memory-key wizard scope** | Phase 4 | in-program / out-of-program | Out — it lives in hippius-console (separate repo, own team); this program ships the CLI equivalent (`invite`/`join`) so onboarding does not block on console work. |

---

## Phase 0 — Verification spikes (days; no product code)

### Task 0.1: Prove BYO-bucket against MinIO

**Files:**
- Create: `docs/plans/2026-07-12-byo-bucket-verification.md` (findings log)
- Test: manual spike, then `hippius-mem-core/tests/` follow-up in Task 0.3

**Step 1:** Start a throwaway MinIO: `docker run --rm -p 9000:9000 -e MINIO_ROOT_USER=test -e MINIO_ROOT_PASSWORD=testtest1 quay.io/minio/minio server /data`. Create a bucket `mem-spike` with `mc` or the console.

**Step 2:** Write a scratch config pointing at it (`s3_endpoint = "http://127.0.0.1:9000"`, `s3_region = "us-east-1"`, generic access key/secret, fresh `team_key_hex`/`author_seed_hex`) and run `hippius-mem doctor` — the live seal→put→get→open probe is exactly the compatibility test. Known gotchas to honor from team memory: the config `bucket` must exactly match what the credential can reach, and any `SdkError::ServiceError` means client-side auth/bucket, not an outage.

**Step 3:** Exercise the full loop: `remember` → `recall` → `get` → `refresh` → `history` → `reconcile` via a live MCP session or the dashboard.

**Step 4:** Record findings in the doc: what worked, any Hippius-gateway assumptions hit (path-style vs virtual-host addressing, region handling, sub-token-shaped auth). Expected outcome: works or a short fix list — `s3_endpoint` is already configurable and the client is stock aws-sdk-s3.

**Step 5:** `mcp__hippius-mem__remember` the verdict (gotcha or reference) — teammates should never re-run this spike.

### Task 0.2: Repeat against Cloudflare R2 (or AWS S3)

Same steps with a free R2 bucket. R2's S3 dialect differs from MinIO's (no ACLs, different multipart edges), so one non-MinIO data point is required before we document "any S3-compatible bucket."

### Task 0.3: Automate the compatibility check

**Files:**
- Create: `hippius-mem-core/tests/s3_compat_minio.rs` (ignored-by-default integration test, `#[ignore = "needs docker"]`)
- Modify: `.github/workflows/semantic-nightly.yml` — add a nightly job that starts MinIO as a service container and runs the test.

**Steps:** failing test first (asserts the doctor probe + one remember/recall round-trip against `MINIO_ENDPOINT` env), watch it fail without the container, wire the container, watch it pass, commit. If live-service coupling makes the test awkward, use the recorded team pattern: extract a small `#[async_trait]` seam trait gated `#[cfg(any(feature, test))]` so a mock covers the logic and the ignored test covers the wire. This is the regression net that keeps the BYO-bucket claim true. *(Rust task → full Rust review discipline.)*

---

## Phase 1 — Kill the install cliff (P1; ~1 week)

Depends on: D1.

### Task 1.1: cargo-dist release pipeline

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.metadata.dist]`)
- Create: `.github/workflows/release.yml` (generated by `dist init`, then pinned to SHAs per repo standards)

**Step 1:** Look up the current stable cargo-dist version (do not assume from memory) and run `dist init` selecting targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.

**Step 2:** Configure the released binary to build `--features embeddings,dashboard` (the installer's default bundle). Known risk to verify early: `fastembed`'s ONNX Runtime linkage on each target — if a target can't build ONNX statically, ship that target lexical-only and say so in the artifact name (`-lean`), honoring the Retrieval-honesty doc rather than silently degrading.

**Step 3:** Tag a `v0.x.y-rc` on a branch, run the workflow, download each artifact, and on at least macOS-arm + linux-x86 run `hippius-mem doctor --offline` from the raw binary.

**Step 4:** Pin all actions to full SHAs with version comments, `persist-credentials: false`, run `zizmor` + `actionlint` clean. Commit.

### Task 1.2: Homebrew tap

**Files:**
- Create: `thenervelab/homebrew-tap` repo with `Formula/hippius-mem.rb` (cargo-dist can generate/update this on release)

**Steps:** enable the cargo-dist Homebrew installer, cut a release, then on a clean machine (or fresh macOS user) verify `brew install thenervelab/tap/hippius-mem && hippius-mem doctor --offline` works with zero Rust toolchain.

### Task 1.3: Re-point install docs at binaries

**Files:**
- Modify: `README.md` Install section; `scripts/install.sh` (add a "download release binary if no cargo" fast path, keep source build as fallback)

**Steps:** update docs so the first-listed path is `brew install` / release download; the git-clone + cargo path moves to "building from source". Measure the target: fresh machine → first successful `doctor` in under 5 minutes.

---

## Phase 2 — Unbundle the README (P7; days, parallel-safe with Phase 1)

### Task 2.1: Split the 1,072-line README

**Files:**
- Modify: `README.md` → shrink to: pitch, 5-minute quickstart, feature table, links.
- Create: `docs/SECURITY.md` (threat model + encryption boundary + verifiable-history walk — lifted, not rewritten, from current README sections)
- Create: `docs/REFERENCE.md` (config table, MCP tools table, operating model, phases 2–3 internals)
- Create: `docs/TEAMS.md` (found/add/remove runbooks, multi-team routing)

**Step 1:** Move content verbatim first (pure cut-and-link commit — reviewable as no-prose-change). **Step 2:** Second commit tightens the new short README around the positioning line: *"Team memory for coding agents that your security team will actually approve — encrypted on your machine, stored in your bucket, every change cryptographically provable."* **Step 3:** Run a link checker over the moved anchors (the README is anchor-heavy); fix all. Commit each step separately.

### Task 2.2: Docs drift guard

**Files:**
- Modify: `.github/workflows/semantic-nightly.yml` or new `docs.yml` — markdown link check on PRs touching `*.md`.

---

## Phase 3 — Bring-your-own-bucket, documented (P3; days, after Phase 0)

Depends on: Task 0.1–0.3 findings, D2.

### Task 3.1: Document and default-check generic S3

**Files:**
- Modify: `docs/REFERENCE.md` (new "Backends" section: Hippius S3 default; MinIO/R2/AWS verified matrix from Phase 0), `README.md` quickstart (one line: "any S3-compatible bucket works")
- Modify (only if Phase 0 found gaps): `hippius-mem-core/src/` S3 client setup (e.g. a `s3_force_path_style` config field) — *Rust task → full Rust review discipline; typed config error in the established error-enum shape; edge-probing tests for the external API surface.*

### Task 3.2: `doctor` names the backend

**Files:**
- Modify: `hippius-mem/src/` doctor output — print the resolved endpoint + addressing mode so support triage ("storage error: service error" = client-side auth/bucket, per the recorded gotcha) starts from facts. *(Rust task → Rust review discipline.)*

---

## Phase 4 — One-command team lifecycle (P4; ~1 week; Rust-heavy)

Depends on: D3. Each task is its own PR; they serialize on the CLI surface.

### Task 4.1: `hippius-mem rotate` — wire `rotate_team_key` to the CLI

The last library-only gap (README "Operating model"). Also expose write-epoch advancement (`set_current_epoch`) as part of the same flow — rotation without advancing the write epoch is a foot-gun.

**Files:**
- Modify: `hippius-mem/src/main.rs` (subcommand), `hippius-mem-core` (only if the library call needs a pin-aware wrapper)
- Test: extend the existing provision→join e2e to rotate-excluding-a-removed-member at the CLI level

**Steps:** failing e2e first (CLI rotate → removed member cannot decrypt new-epoch note → remaining member can), then implement, then pass, then commit. Update `max_epoch` guidance in docs — rotation must print a loud "raise max_epoch to N on every machine" line, since a stale `max_epoch` silently hides new-epoch notes (documented config gotcha; also the recorded `bootstrap_epochs` gotcha applies to any new entry point this adds).

### Task 4.2: `hippius-mem invite` (founder) — one paste-ready bundle

Collapses the four-value hand-off. Mints the sub-token (reusing the `console`-feature mint path — sub-tokens can only be minted by the bucket owner, per team memory), assembles `{bucket, team, team_key_hex or wrapped-key instructions, access_key_id, secret}` into a single copy-paste block (or file) the joiner feeds to Task 4.3.

**Files:**
- Modify: `hippius-mem/src/main.rs`; possibly `hippius-mem-core` config serializer
- Test: invite → join round-trip e2e (fake blob store where possible; live behind `#[ignore]`)

**Security step (explicit):** the bundle contains secrets — print to tty only, never write to a default file path, and say "share out of band, then delete." *(Rust task → Rust review discipline; hostile-critic item is the secret-handling surface.)*

### Task 4.3: Extend `hippius-mem join` to consume the bundle

Today `join` publishes a member key (wrapped-key flow). Extend it to accept the invite bundle (stdin/file) and write the `[[teams]]` profile itself (reusing `--add-team`'s appender), then run `doctor`. End state: joiner runs exactly one command.

### Task 4.4: `hippius-mem remove <ss58>` — the three-step runbook as one command

Orchestrates: republish membership without the member → rotate (Task 4.1) → print the one manual step (revoke their sub-token at the gateway, which only the founder's console session can do — link the exact console path). Refuses to run if not the founder (typed error).

---

## Phase 5 — Solo-first quickstart (P2; design-first)

### Task 5.1: Design doc — `hippius-mem quickstart`

**Files:** Create `docs/plans/2026-07-XX-quickstart-design.md`.

The open design question is the zero-decision bucket: an outsider has no Hippius account. Options to explore in the doc: (a) local filesystem blob-store backend for trial mode (new `BlobStore` impl — the trait seam exists), (b) free-tier Hippius bucket minted via a public endpoint, (c) point at any S3 bucket the user already has (post-Phase 3 this is one prompt). Per the Hippius-first constraint, recommend (b) as the primary path — quickstart should funnel a new user into a Hippius bucket (this needs a hippius-console/gateway conversation about a public free-tier mint endpoint) — with (a) local trial mode as the no-signup fallback and (c) documented for the reluctant; `quickstart` upgrading a local vault to a bucket later via op-log replay (the index/op-log design makes the store location swappable in principle — the design doc must verify this).

### Task 5.2: Implement per the accepted design (own PR, scoped after 5.1 review).

---

## Phase 6 — Prove the ROI + widen the agent story (P5, P6; parallel-safe)

### Task 6.1: `hippius-mem report`

Weekly digest from convergent data: recalls served (Reinforce ops — distinct-author counts already Sybil-bounded), top gotchas that fired, dedup refusals, notes added/edited/tombstoned. Renders markdown; dashboard gets the same panel.

**Files:** `hippius-mem/src/` (subcommand), `hippius-mem-core` (aggregation over converged state — read-only, no new op kinds), dashboard template. *(Rust task → Rust review discipline. Note: recall telemetry beyond Reinforce is machine-local by design — the recorded index-is-derived memory — so the report states its data honestly: "reinforced-note usage across the team; raw recall counts are this machine only.")*

### Task 6.2: AGENTS.md mandates block + degraded-modes doc

**Files:**
- Modify: `hippius-mem/src/` init/install writers — emit the mandates block into `AGENTS.md` alongside `CLAUDE.md` (same marker-delimited, idempotent mechanism)
- Create: `docs/AGENTS-SUPPORT.md` — a truth table: Claude Code (hooks = enforced loop), Cursor/Codex/other MCP clients (mandates text only = honor system), plus what breaks (no PreToolUse gate, no Stop nudge, no session brief).

---

## Sequencing summary

```
Phase 2 (docs)   ──► FIRST: parallel-safe, sharpens the Hippius pitch, no gates
Phase 1 (dist)   ──► needs D1; Hippius-aligned, high leverage
Phase 4 (lifecycle CLI): 4.1 ► 4.2 ► 4.3 ► 4.4 (serialize on CLI surface)
Phase 0 (spikes) ──► Phase 3 (BYO-bucket docs) — demoted: compatibility fallback,
                     not positioning (Hippius-first constraint)
Phase 5 (quickstart): design doc after Phase 4; primary path = Hippius free-tier
Phase 6: parallel-safe any time; 6.1 benefits from waiting for real Reinforce data
```

Every phase = its own PR(s) off `main`, adversarial review before merge (the pattern that caught real gaps in #42), and a `remember` note for any durable learning (backend quirks, ONNX build constraints, design decisions).
