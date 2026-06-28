---
name: illu-rs
description: Use when exploring, reviewing, or modifying Rust, Python, or TypeScript/JavaScript code in this repo - prefer illu MCP tools (query, context, references, impact) over raw file search.
---

# illu-rs Code Intelligence

This project is indexed by illu-rs. Use the following MCP tools to explore the codebase and its dependencies.

## Tools (61 available)

### Search & Navigate

- **query** — Search symbols, docs, files, bodies, or string literals. Filters: kind, attribute, signature, path.
- **context** — Full symbol context: source, callers, callees, trait impls. Supports `Type::method`, `sections` filter, `exclude_tests`.
- **batch_context** — Context for multiple symbols in one call.
- **symbols_at** — Find symbols at a file:line location.
- **overview** — Public symbols under a path, grouped by file.
- **tree** — File/module hierarchy.

### Rust Quality

- **axioms** — Rust rules, safety constraints, and best-practice guidance.
- **exemplars** — Compile-checked canonical reference code for codified patterns (FFI, error design, RAII, builder, MaybeUninit, sealed trait, type-state) cross-referenced to axioms. Quote rather than reconstruct.
- **rust_preflight** — Required evidence packet before Rust design/code: axioms, symbol context, impact hints, std/dependency docs, and model-failure reminders.
- **std_docs** — Local standard-library rustdoc lookup for items and methods.
- **critique** — Regex-based axiom-violation detection on `git diff`. Covers six detector patterns only (bare unsafe blocks, undocumented `unsafe fn`, `Box<CopyType>`, `mem::uninitialized`, speculative single-implementor traits, newly-added Cargo.toml dependencies); a clean `critique` pass is NOT a soundness or idiom clearance — idiom violations (Cow vs String, runtime vs typestate, `is_err()` vs `matches!()`) live in `axioms`/`quality_gate`. Run before `quality_gate` for the six covered patterns; consult `axioms` and `exemplars` for the rest.
- **quality_gate** — PASS/WARN/BLOCKED check for Rust diff evidence before final answer or commit. PASS reflects evidence-shape compliance (plan, docs, impact, tests); it is NOT soundness clearance. Empty or non-Rust diffs are annotated `(evidence-shape only — no Rust diff scanned)` and warn that the evidence-only result is not Rust soundness clearance. Test-only diffs are annotated `(test-only diff)`. For real assessment, supply `git_ref` so the gate can scan the actual diff.
- **playbook** — Project Rust Playbook — full text, or `titles_only` for the `## ` headings. Static per session; fetch once rather than per preflight.
- **spec_critique** — Scan a task description for known API anti-patterns (`Option<bool>`, `&[String]`, unwrap, panic, …) BEFORE planning; returns redirects naming the axiom + exemplar to quote.

### Project Conventions

- **project_style** — Active per-project axiom overrides (`ignored`/`demoted`/`noted`/`elevated`) and project-local axioms loaded from `.illu/style/project.json`. Consult before flagging axiom violations — an `ignored` axiom must not drive recommendations.
- **decisions** — ADR-style design records loaded from `.illu/style/decisions/`. Consult before recommending designs to avoid reproducing or contradicting a prior decision; if a decision rejected your approach, surface that instead of restating its tradeoff.
- **reload** — Force-invalidate the `project_style` and `decisions` caches and re-read from disk. The caches use mtime/snapshot-based auto-invalidation on every read — call this only when an external tool restored timestamps (`cp -p`, `git checkout`, `tar -p`) or when explicitly verifying a reload.
- **decision_resolve** — Flip a `proposed` ADR to `accepted`/`rejected`/`superseded` and append a resolution-history entry; reloads the decisions cache. Use after merging a PR that consumed a proposed ADR.

### Impact Analysis

- **impact** — Transitive dependents of a symbol (configurable depth).
- **diff_impact** — Batch impact for all symbols in a git diff.
- **test_impact** — Which tests break when changing a symbol.

### Call Graph

- **callpath** — Shortest or all paths between two symbols.
- **neighborhood** — Callers/callees within N hops (list or tree format).
- **references** — Unified view: call sites, type usage, trait impls.
- **type_usage** — Where a type appears in signatures and struct fields.
- **file_graph** — File-level dependency graph.
- **graph_export** — Export call or file graphs as DOT, compact edge list, or summary. `exclude_tests` filters symbol call graphs only.

### Discovery & Audit

- **debt** — List `// illu:debt:` shortcut markers across the repo.
- **unused** — Symbols with no incoming references.
- **orphaned** — Symbols with no callers AND no test coverage.
- **untested** — Symbols no `#[test]` transitively calls (defaults to `kind: function`). Counterpart to `unused`, which finds symbols with no callers at all.
- **module_api** — Public API vs internal-only classification for a module.
- **similar** — Functions with matching signatures and call patterns.
- **rename_plan** — All locations to update before renaming a symbol.
- **doc_coverage** — Undocumented symbols with coverage percentage.
- **hotspots** — Most-referenced, most-complex, and largest functions.
- **stats** — File/symbol counts, test coverage, top references.

### Dependencies & Git

- **docs** — Version-pinned dependency documentation, filterable by topic; `max_chars` caps long rendered output.
- **implements** — Trait/type implementation relationships.
- **crate_graph** — Workspace inter-crate dependency graph.
- **blame** — Git blame on a symbol's line range.
- **history** — Git commit history for a symbol, with optional diffs.
- **freshness** — Index staleness check.
- **health** — Index quality diagnosis.

### Cross-Repo

- **repos** — Dashboard of all registered repos with status and symbol counts.
- **cross_query** — Search symbols across all registered repos.
- **cross_impact** — Find references to a symbol in other repos.
- **cross_deps** — Inter-repo dependency relationships via Cargo.toml.
- **cross_callpath** — Find call chains spanning repo boundaries. Strict by default: noisy bridge names are suppressed; set `include_noisy_bridges` for legacy/noisy inspection.

### rust-analyzer (compiler-accurate, positions use file:line:col)

- **ra_definition** — Go to definition — resolves through macros, trait impls, generics.
- **ra_hover** — Type information and documentation at a position.
- **ra_diagnostics** — Compilation errors and warnings, optionally filtered by file.
- **ra_call_hierarchy** — Callers and/or callees at a position (direction: in/out/both).
- **ra_type_hierarchy** — Supertypes (traits) and subtypes for a type.
- **ra_rename** — Rename a symbol: mode=preview (default) reports impact; mode=apply performs it with compilation error checking.
- **ra_code_actions** — Available quick fixes and refactors at a position.
- **ra_expand_macro** — Expand macro at a position, showing generated code.
- **ra_ssr** — Structural search and replace (e.g. `foo($a) ==>> bar($a)`): mode=preview (default) reports the resolved WorkspaceEdit JSON; mode=apply writes the edit and reports changed files. Preview is the safe default — an omitted or garbled mode never silently rewrites the workspace. Output hard-bounded by `max_bytes` (default 64 KB) with a truncation marker.
- **ra_context** — Full compiler-accurate context: definition, hover, callers, callees, impls, tests. `max_items` and `include_tests` compact noisy output.
- **ra_syntax_tree** — Show syntax tree for a file (debugging/parse structure). Output hard-bounded by `max_bytes` (default 64 KB) with a truncation marker; pass `symbol_name` to narrow.
- **ra_related_tests** — Find tests related to a symbol — more accurate than text matching.

## Rust Design Discipline

Before writing, modifying, or recommending Rust code, do these in order:

1. **Search before write.** `query` for the symbol or helper you are about to introduce — it may already exist. `query` for parallels in related modules. `exemplars` for codified patterns to quote rather than reconstruct. The single highest-leverage step in this workflow: search tools redirect, analysis tools confirm. Skipping the search step is the most common failure mode caught by review.
2. Run `rust_preflight` to gather axioms, local symbol evidence, impact hints, std/dependency docs, and model-failure reminders.
3. Consult `project_style` and `decisions` so your work respects the project's axiom overrides and prior design choices. An axiom marked `ignored` must not drive recommendations; a decision that rejected your approach should be surfaced rather than reproduced or contradicted.
4. Plan first — name the data flow, invariants, failure cases, and the concrete types (structs / enums / newtypes / collections) you will use.
5. Choose data structures deliberately; prefer representations that make invalid states unrepresentable. Use typed per-module error enums wrapped via `#[from]` on the crate-wide error type — not `IlluError::Other(format!(...))` collapse. Add `# Errors` rustdoc to every `pub fn` returning `Result`.
6. Read the docs before assuming any non-trivial API's behavior. Standard-library items require `std_docs`; dependencies use `docs`; local types use `context`.
7. Query `axioms` twice if preflight did not already supply both: once with `planning data structures documentation comments idiomatic rust verification performance` and once with the concrete task context.
8. When the task matches a codified pattern (FFI, error design, RAII, builder, MaybeUninit, sealed trait, type-state, Cow transformer, drop guard, typed-error tests), pull the canonical reference code from `exemplars` and quote from it rather than reconstructing the pattern from prose axioms.
9. Write idiomatic Rust per The Rust Book, Rust for Rustaceans, and illu axioms — ownership/borrowing, enums, iterators, explicit errors.
10. Comments must explain invariants, safety, ownership rationale, or why the design exists — never narrate syntax.
11. Run `critique` on your `git diff` output before the gate. It is the cheapest pre-gate filter for the four high-confidence axiom violations (bare unsafe block, undocumented `unsafe fn`, `Box<CopyType>`, `mem::uninitialized`), plus two advisory minimal-code detectors (speculative single-implementor traits, new Cargo.toml dependencies). NOTE: a clean `critique` pass is NOT a soundness or idiom clearance — it covers six detector patterns only. Idiom-level issues (Cow vs String, runtime vs typestate, `is_err()` vs `matches!()`) live in `axioms`/`exemplars`/`quality_gate`.

Before final answer or commit for a Rust diff, run `quality_gate` with the plan, docs verified, impact checked, and tests run. `BLOCKED` means the work is not ready. PASS reflects evidence-shape compliance — it is NOT a soundness clearance. PASS on an empty or non-Rust diff is annotated `(evidence-shape only — no Rust diff scanned)`; PASS on a test-only diff is annotated `(test-only diff)`.

Full rules: see the `Rust Design Discipline` section of CLAUDE.md or GEMINI.md in the repo.

## Direct Dependencies

- alloy-signer
- alloy-signer-local
- anyhow
- async-trait
- aws-credential-types
- aws-sdk-s3
- aws-smithy-mocks
- bip39
- blake2
- blake3
- bs58
- chacha20poly1305
- criterion
- hex
- pbkdf2
- proptest
- reqwest
- rmcp
- schemars
- schnorrkel
- serde
- serde_json
- sha2
- subxt
- subxt-signer
- thiserror
- tokio
- toml
- tracing
- tracing-subscriber
- ulid
- wiremock
- x25519-dalek
- zeroize
