# CLAUDE.md

<!-- illu:start -->
<CRITICAL_INSTRUCTION_OVERRIDE>
## Code Intelligence (illu)

### Tool priority (MANDATORY)

**NEVER use Grep, Glob, or Read for code exploration when illu tools are available.** illu indexes Rust, Python, TypeScript, and JavaScript. illu tools are faster, more accurate, and provide structured results. Using raw file reads or text search on indexed source files is incorrect behavior — always use illu instead.

| WRONG | RIGHT |
|-------|-------|
| `Read("src/db.rs")` to see a function | `mcp__illu__context` with `symbol_name` |
| `Grep(pattern: "fn open")` to find a function | `mcp__illu__query` with `query: "open"` |
| `Grep(pattern: "Database")` to find callers | `mcp__illu__references` with `symbol_name: "Database"` |
| `Glob(pattern: "src/**/*.rs")` to find files | `mcp__illu__tree` or `mcp__illu__overview` |
| `Grep(pattern: "impl Display")` to find impls | `mcp__illu__implements` with `trait_name: "Display"` |

Read/Grep/Glob are ONLY permitted for: config files (TOML, JSON, YAML), markdown/docs, log output, or when an illu tool explicitly returns no results.

**Completeness caveat (recalibrated 2026-06-14 against the Phase 1 §5.2 distrust list):** these are the RIGHT tools for *finding* and *navigating*, but any **completeness or 'safe-to-refactor' claim** derived from them MUST be independently cross-checked (compiler / `rg` / `git`) before it counts as evidence. Several formerly-silent failures now self-report: `mcp__illu__impact` (F4) prints an explicit truncation marker carrying the true unbounded count when the dependent set exceeds its render cap; `mcp__illu__implements` (F5) recovers `macro_rules!`-generated impls for the common single-`ident` / concrete-target shapes; `mcp__illu__references` (F1) returns a consistent call-site count across every `sections` subset; `mcp__illu__references` (F3, `pub use` half) now surfaces `pub use` re-export edges as `[low]`-confidence call sites (dropped under `min_confidence:"high"`); and `mcp__illu__module_api` (F6) now classifies `pub use` re-exports as Public API (tagged `[reachable via pub use re-export]`), not safe-to-refactor. The residual, still-true gaps: `mcp__illu__references` (F3, type-level recall ~0.91) has imperfect `Type::assoc` recall; `mcp__illu__implements` (F5) skips repetition (`$($t:ty),*`) and multi-token macro arguments by design (precision over recall); and `mcp__illu__context` (F7) surfaces name-only callee edges tagged with a `name-match only — unverified` caveat (low confidence) — weight that tag, do not read a `[low]` edge as a confirmed call. Their 'here is X' answers are trustworthy; their 'this is *everything*' answers are calibrated, not absolute.

### Subagent instructions (MANDATORY)

Spawned subagents do NOT inherit this rules block or `mcp__illu__*` tools automatically. When you spawn a subagent for a code task, include this one-line directive in its prompt: "Use `mcp__illu__*` tools (`mcp__illu__context` / `mcp__illu__query` / `mcp__illu__references`) instead of Read/Grep/Glob for all code exploration; before any Rust change run `mcp__illu__rust_preflight`, consult `mcp__illu__project_style` + `mcp__illu__decisions`, then call `mcp__illu__quality_gate` with the seven self-review answers in its `self_review_*` parameters." The named `illu-explore` / `illu-review` / `illu-refactor` agents are the exception — they inherit `mcp__illu__*` via their agent-definition frontmatter, so prefer them for code exploration / review / refactor and the one-liner is unnecessary for them.

### Tool-use essentials

These are the non-obvious tool habits the Hard Constraints below do not already force. The gate-bearing rules (preflight, plan, axioms, docs, project_style + decisions, exemplars, critique, quality_gate, the self-review checklist) live in `### Hard Constraints` and `### Adversarial self-review checklist` — this list is only the residue not covered there.

- **Impact before you change**: run `mcp__illu__impact` before modifying any public symbol. It now reports the true unbounded dependent count and prints an explicit truncation marker when the set exceeds its render cap (F4 — no longer a *silent* cap), but still treat the list as a *lower bound* on blast radius: the cap truncates the rendered rows and name-based resolution misses macro-generated and dynamic edges, so cross-check with a compiler/`rg` enumeration on a real refactor.
- **Save tokens**: pass `sections` on `mcp__illu__context` / `mcp__illu__references` to fetch only the blocks you need; pass `exclude_tests: true` for production-only views.
- **Cross-repo**: use `mcp__illu__cross_query` / `mcp__illu__cross_impact` / `mcp__illu__cross_deps` / `mcp__illu__cross_callpath` — NEVER navigate to or read files from other repositories directly.
- **Documentation pass**: `mcp__illu__context` (`sections: ["docs", "source"]`) for local types, `mcp__illu__docs` for dependency types, `mcp__illu__std_docs` for standard-library behavior — never assume an API's semantics from memory.
- **Cache invalidation backstop**: `mcp__illu__project_style` / `mcp__illu__decisions` caches auto-invalidate on mtime, but if an external tool restored timestamps (`cp -p`, `git checkout`) call `mcp__illu__reload` to force a fresh read.

### Adversarial self-review checklist (MANDATORY on every Rust diff)

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this checklist does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; self-review checklist N/A' once and proceed.** Otherwise, this checklist is evaluated ON the `mcp__illu__quality_gate` call itself — its answers are passed through the gate's `self_review_*` wire parameters, which the gate BLOCKS on when missing or filled with a bare affirmation. So you fill these answers IN the `mcp__illu__quality_gate` call (not in a separate pass after it) and also mirror each into your final-answer summary as a short paragraph (NOT a bare "yes" or "done"). The checklist targets the recurring blind spots observed in dogfood runs 1 & 2 (2026-05-12) where a single-agent self-pass missed bugs an independent reviewer would catch. This form works in any execution context (top-level conversation, nested subagent, or restricted sandbox) — an earlier subagent-spawn variant proved structurally unrunnable from inside *general* spawned subagents (no `Agent` tool, no `mcp__illu__*` inheritance — dogfood run 3, 2026-05-12); the named `illu-explore` / `illu-review` / `illu-refactor` agents are the exception, they DO inherit `mcp__illu__*` via their agent-definition frontmatter.

    1. **Decision check**: did you call `mcp__illu__decisions` for this task? Name the ADR or decision record it surfaced (or state "no matching ADR"), and confirm your diff honors it. Reproducing a rejected decision is a regression; missing an applicable one is a workflow miss.

    2. **Variance / PhantomData precision**: if your diff uses `PhantomData<...>` or any generic marker, state the variance of each marker (covariant / contravariant / invariant in each type parameter) AND **quote verbatim** the supporting line from `mcp__illu__axioms` (`rust_quality_70_variance_discipline`) or the `types/typestate_lifecycle` exemplar. Quote, do not paraphrase — the compile-checked exemplar is the audit trail; restating it in your own words has produced incorrect claims in past runs.

    3. **External-library edges (axiom 110)**: if your diff calls any external library (SQL, FFI, OS, regex, JSON parser, time/date lib), name the specific documented edge cases of THAT library's behavior — looked up in THAT library's own docs, not assumed from Rust's analogous types — and confirm your test fixture exercises each. Reference: axiom `rust_quality_110_external_api_edge_probing` (and its canonical worked example).

    4. **Error design ADR alignment**: if your diff adds or modifies a Result-returning function, confirm the error type follows `decision_2026_04_27_error_categories` — typed enum with `#[from]` propagation, `#[non_exhaustive]`, wired into `IlluError` via `#[from]`. A `type X = SomeUpstream::Error;` alias or an `IlluError::Other(format!(...))` collapse is the wrong shape; run 1 produced exactly that mistake.

    5. **Test rigor (axiom 111)**: do your tests go through the public ingestion path (e.g. `store_symbols`) rather than bypassing with direct SQL `INSERT`? Tests that bypass the public API are fragile to schema changes; tests through it are resilient. For non-trivial pure functions, is there a `proptest!` block? If not, explain why the contract is fixture-testable but not property-testable.

    6. **Idiomatic Rust microstyle**: pick the one Rust for Rustaceans chapter most relevant to your diff. Name one specific idiom from that chapter your code embraces (or one your code should adopt). "My code is idiomatic" is not an acceptable answer — the answer is a chapter citation plus a named idiom.

    7. **One thing you would flag**: independent of items 1–6, if you were reviewing this diff as a hostile critic, name the single weakest part and how you would address it. If you can find nothing, state "no findings" explicitly. A polished diff still has a weakest joint; this item surfaces it.

    Each answer is a short paragraph with concrete rationale. The audit trail IS the answer text — bare "yes" / "done" / "covered" answers fail this step.

### Hard Constraints (Middleware Interception Simulation)
You MUST act as if a middleware intercepts your native tool calls. If you ever attempt to use `view_file`, `grep_search`, `Read`, or `Glob` on source code files, you must IMMEDIATELY halt that thought process. Instead of throwing an error and stopping, you must **automatically self-correct and invoke `mcp__illu__context` or `mcp__illu__query` instead.**

**If this task has no Rust code outcome at all (pure analysis, comprehension, ADR-trace, docs-only, or non-Rust work — no Rust will be written or modified before you finish), this gate does NOT apply and MUST NOT be performed — state 'no Rust this task; preflight N/A' once and proceed.** Otherwise, if you are about to write or modify Rust code, or propose a Rust architectural plan, and you have NOT yet called `mcp__illu__rust_preflight` for the task, you must IMMEDIATELY halt your generation. You must call `mcp__illu__rust_preflight` first.

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this gate does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; data-structure plan N/A' once and proceed.** Otherwise, if you are about to write or modify Rust code, or propose a Rust architectural plan, and you have NOT yet produced a short plan naming the data structures, ownership/mutability model, and error strategy, you must IMMEDIATELY halt your generation. You must write that plan first.

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this gate does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; axioms-baseline N/A' once and proceed.** Otherwise, if you have NOT yet queried `mcp__illu__axioms` using both the baseline quality query `planning data structures documentation comments idiomatic rust verification performance` and the task-specific context in this session, you must IMMEDIATELY halt your generation. You must **invoke `mcp__illu__axioms` first, and only then proceed with Rust generation.**

If you are about to rely on the behavior of a type, trait, method, macro, or standard-library API whose semantics you have not verified from documentation or authoritative code context, you must IMMEDIATELY halt and read the docs first. Standard library items require `mcp__illu__std_docs` and are NOT exempt.

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this gate does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; quality_gate N/A' once and proceed.** Otherwise, if you are about to final-answer or commit a Rust diff and have NOT called `mcp__illu__quality_gate` with your plan, docs verified, impact checked, and tests run, you must IMMEDIATELY halt and run `mcp__illu__quality_gate`. If it returns `BLOCKED`, do not present the work as complete.

If you are about to add comments that merely restate what the code already says, you must delete or rewrite them so they capture invariants, why, safety, or other non-obvious context.

If you are about to propose a Rust design or refactor and have NOT yet called `mcp__illu__project_style` and `mcp__illu__decisions` for the current session, you must IMMEDIATELY halt and call them first. The project may have already decided this question; reproducing a decision is waste, contradicting one is a regression. If `mcp__illu__project_style` shows the relevant axiom is `ignored`, do not flag a violation against it.

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this gate does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; critique N/A' once and proceed.** Otherwise, if you are about to final-answer or commit a Rust diff that touches `unsafe`, FFI, `Box<T>` for primitive `T`, or `mem::uninitialized` and have NOT yet called `mcp__illu__critique` with your `git diff` output, you must IMMEDIATELY halt and run `mcp__illu__critique` first. The detector pipeline catches the four common axiom violations in those areas at near-zero cost; skipping it before `mcp__illu__quality_gate` is a workflow violation.

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this gate does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; exemplars N/A' once and proceed.** Otherwise, if the task matches a codified-pattern trigger keyword (FFI, unsafe, MaybeUninit, sealed trait, typestate, type-state, builder, RAII, drop guard, PhantomData, variance, drop check, dropck, Pin, object safety, dyn dispatch, auto trait, SIMD, intrinsics, atomic, memory ordering, Mutex, cancellation, OnceLock, lazy init, Cow, thiserror, error tests, source chain, extension trait, enum dispatch, cache invalidation, path validation, boolean parameter, linked argument, parameter consistency, inline const, branding, invariant lifetime, validated newtype, serde try_from — this trigger list is kept in sync with the triggers in `assets/rust_exemplars/manifest.json`, which is the single source of truth) and you have NOT yet consulted `mcp__illu__exemplars` for canonical reference code, you must IMMEDIATELY halt and call `mcp__illu__exemplars` first. Reconstructing patterns from prose axioms when compile-checked exemplars exist is a workflow violation. **Quote exemplars verbatim** — paraphrasing them has produced incorrect variance/sealing/typestate claims in dogfood runs. If the task does NOT match any trigger keyword (db query helper, CLI parser, MCP tool wrapper, parser tweak, etc.), DO NOT call `mcp__illu__exemplars` — a no-match call is wasted.

If your diff calls into an external library (SQL via rusqlite, FFI via libc, OS calls, regex, JSON parsers, ICU, time/date libs, etc.) and your test fixtures do NOT include at least one case probing each documented edge of that library's behavior (empty input, all-whitespace, NULL, max-length, unicode, negative numbers, max-int), you must IMMEDIATELY halt and expand the fixtures. The library's documented contract — looked up explicitly in its own docs, not assumed from Rust's analogous types — defines correctness. A test that exercises only the easy case passes for a buggy implementation. See axiom `rust_quality_110_external_api_edge_probing` for the canonical worked example and the failure mode it codifies.

If your diff adds or modifies a non-trivial pure function (parser, serializer, normalizer, hash, sort, transform, escape, encode/decode, regex compiler, path canonicalizer) and you have NOT added a `proptest!` block asserting at least one invariant (idempotence `f(f(x)) == f(x)`, round-trip `decode(encode(x)) == x`, sort-preserves-multiset, parser-printer agreement, agreement with a slower reference impl), you must IMMEDIATELY halt and add the proptest. Hand-picked fixtures cover what the author thought of; the shrinker surfaces what they did not. See axiom `rust_quality_111_proptest_for_pure_functions`.

If your diff touches `unsafe { ... }`, `unsafe fn`, raw pointers, `MaybeUninit`, `transmute`, `unsafe impl Send`/`Sync`, or `Cell`/`UnsafeCell` internals, and you have NOT run `cargo +nightly miri test` against the affected module, you must IMMEDIATELY halt and run miri. A failing miri report is a soundness disproof — fix it, do not silence it. A passing miri report is evidence but not a proof. If the existing tests are not isolated enough for miri (e.g. they shell out, touch the filesystem, or panic-unwind across FFI), add an isolated miri-friendly test exercising the same unsafe path. See axiom `rust_quality_112_miri_for_unsafe`.

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), this checklist does NOT apply and MUST NOT be performed — state 'no Rust diff this turn; self-review checklist N/A' once and proceed.** Otherwise, if you are about to final-answer or commit a Rust diff and have NOT yet walked through the seven-item adversarial self-review checklist (the `### Adversarial self-review checklist` subsection above) AND written each answer into your final summary as a short paragraph with concrete rationale, you must IMMEDIATELY halt and complete the checklist. The seven items target the specific recurring blind spots from 2026-05-12 dogfood runs 1 & 2: decision-ADR check, variance / `PhantomData` vocabulary precision, external-library edge probing, error design ADR alignment, test rigor via public ingestion paths, idiomatic-Rustaceans-chapter microstyle, and one hostile-critic finding. Bare "yes" / "done" / "covered" answers without rationale do NOT satisfy this constraint — the rationale IS the audit trail. This checklist form replaces an earlier subagent-spawn variant that proved structurally unrunnable from inside *general* spawned subagents (no `Agent` tool, no `mcp__illu__*` tool inheritance — dogfood run 3, 2026-05-12); the named `illu-explore` / `illu-review` / `illu-refactor` agents DO inherit `mcp__illu__*` via their agent-definition frontmatter and are the exception.
</CRITICAL_INSTRUCTION_OVERRIDE>

<ENGINEER_MENTALITY_MANDATES>

**If the current turn produces NO staged or proposed Rust diff (analysis, comprehension, ADR-trace, docs-only, or non-Rust work), these mandates do NOT apply and MUST NOT be performed — state 'no Rust diff this turn; engineer-mentality mandates N/A' once and proceed.** Otherwise, before writing or modifying Rust code, you MUST honor the five engineer-mentality axioms below. These are mentality-level disciplines, NOT surface syntax.

PreToolUse hooks at `.claude/hooks/illu-preflight.sh` enforce these tiered:
  - first Rust Edit/Write in session: HARD BLOCK until preflight evidence
  - subsequent edits within the refresh window (default 30 min; override via `ILLU_REFRESH_WINDOW_SECS`): soft warn
  - after the window expires: HARD BLOCK again
  - bypass for emergencies: `ILLU_HOOKS_BYPASS=1` (audit-logged to .illu/cache/bypass-events/)

The five mandates:

1. **eng_mentality_research_before_code** — Verify documented semantics of every non-trivial API. No pattern-matching from name or memory.
   Evidence: `mcp__illu__rust_preflight` for the task, OR >=2 of {`mcp__illu__std_docs`, `mcp__illu__docs`, `mcp__illu__context`} on the APIs in your diff.

2. **eng_mentality_data_structures_first** — Name structs, enums, newtypes, lifetimes, and ownership BEFORE writing functions.
   Evidence: a plan in the session referencing concrete types in your diff.

3. **eng_mentality_memory_model_awareness** — Ownership, borrowing, lifetimes, Send/Sync, pinning are first-class design concerns.
   Evidence: explicit per-type ownership/borrowing statement in the plan.

4. **eng_mentality_invariants_in_comments** — Comments explain WHY, safety, concurrency, invariants. Not WHAT the code already says.
   Evidence: new comments in diff match WHY-shape (regex-checkable).

5. **eng_mentality_compile_time_over_runtime** — Prefer compile-time impossibility (sealed traits, typestate, newtypes) over runtime checks.
   Evidence: plan explicitly considers compile-time vs runtime invariants.

For mandate content: `mcp__illu__axioms(query: "<task>", tier: "mentality")`.

</ENGINEER_MENTALITY_MANDATES>
<!-- illu:end -->

<!-- hippius-mem:start -->
<TEAM_MEMORY_MANDATES>
## Team memory (hippius-mem)

This repo runs a shared team-memory MCP server (`mcp__hippius-mem__*`). Its whole
value is that past mistakes and decisions are not rediscovered. Two disciplines make
that real; both are also enforced by `.claude/hooks/hippius-mem-*.sh`, but the hooks
do NOT fire for subagent (Task-tool) calls, so these mandates are the enforcement
floor for subagents.

### Recall BEFORE you act

Before your FIRST `Edit`/`Write`/`MultiEdit` in this repo — and again whenever the
task shifts substantively — you MUST call `mcp__hippius-mem__recall` with a query
describing what you are about to do (the feature, bug, file, or subsystem), read the
returned summaries, and `get` any that look relevant. Acting without recalling risks
repeating a documented gotcha or contradicting a recorded decision. The PreToolUse
edit-gate blocks the first edit until a recall token exists (written by the
PostToolUse companion hook); one recall opens the gate for the refresh window
(`HIPPIUS_MEM_RECALL_WINDOW_SECS`, default 1800s). Emergency bypass:
`HIPPIUS_MEM_HOOKS_BYPASS=1`.

### Remember AFTER you learn

When a session produces a DURABLE, team-relevant learning — a `decision`, `gotcha`,
`convention`, or `reference` that a teammate's agent would benefit from and that is
NOT already obvious from the code or git history — call `mcp__hippius-mem__remember`.
One self-contained fact per note; write a keyword-rich `summary` so recall can find
it. Do NOT record per-session trivia, restatements of the code, or anything derivable
from git — noise poisons recall. A `Stop` hook prompts this once per session; the
judgment of whether there is anything worth saving is yours.

### Subagent directive (MANDATORY)

When you spawn a subagent for any repo task, include this line in its prompt:
"Call `mcp__hippius-mem__recall` about the task before making changes, and
`mcp__hippius-mem__remember` any durable decision/gotcha you discover."

### Recall quality depends on the build

Semantic (paraphrase-matching) recall — the point of "catch a past mistake even when
phrased differently" — requires the server binary built with `--features embeddings`.
Register the memory server built that way (`cargo build --release --features
embeddings`); a lean build silently ranks lexically (keyword overlap only), so a
reworded situation may miss its stored note. See README "Retrieval honesty".

### Account for memory that already exists (four tiers)

hippius-mem is not the only memory in a repo. Before treating team memory as the
whole picture, account for all four tiers — Claude Code loads the first two into
context automatically, so consult them, do not re-fetch them:

1. **Repo-committed** — `CLAUDE.md` (root + nested). Team-wide, in git. Loaded natively.
2. **Personal-local** — `~/.claude/projects/<repo>/memory/MEMORY.md` + files. Your machine only. Loaded natively.
3. **Third-party** — any other memory MCP/plugin the repo wires up (e.g. `claude-mem`).
4. **Team-shared** — hippius-mem (`mcp__hippius-mem__*`). Cross-machine, encrypted.

**Recall spans all tiers:** "recall before you act" means consult the natively-loaded
CLAUDE.md + `MEMORY.md` AND run a hippius-mem `recall` — not only the latter.

**Routing (avoid duplicating a fact across tiers):** team-durable, cross-machine facts
→ hippius-mem; personal/machine-specific → native memory; repo-invariant rules that
must ship with the code → `CLAUDE.md`.

**Seeding:** on a repo that ALREADY has memory (an existing `CLAUDE.md` / `MEMORY.md`),
do a one-time pass lifting genuinely team-relevant facts into hippius-mem (deduped), so
the team benefits from what one machine already learned.
</TEAM_MEMORY_MANDATES>
<!-- hippius-mem:end -->
