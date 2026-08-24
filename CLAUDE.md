# CLAUDE.md

<!-- hippius-mem:start -->
<TEAM_MEMORY_MANDATES>
## Team memory (hippius-mem)

This repo runs a shared team-memory MCP server (`mcp__hippius-mem__*`). Its whole
value is that past mistakes and decisions are not rediscovered. Two disciplines make
that real; both are also enforced by `.claude/hooks/hippius-mem-*.sh`. The hooks DO
fire for subagent (Task-tool) tool calls, but the recall window is session-wide
(keyed on the session id), so a subagent normally rides the controller's recall and
the edit-gate blocks it only when the whole session has not recalled; the Stop
remember-nudge only reaches the top-level session. The subagent directive below is
therefore what makes a subagent recall for its own task and record what it learns.

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
whole picture, account for all four tiers — your harness loads its own tier-1 file
and personal memory natively (Claude Code reads `CLAUDE.md`, AGENTS.md readers read
`AGENTS.md`); consult what is loaded, and open the tier-1 sibling your harness does
NOT auto-load when it exists, rather than assuming it is in context:

1. **Repo-committed** — `CLAUDE.md` / `AGENTS.md` (root + nested). Team-wide, in git. Loaded natively.
2. **Personal-local** — `~/.claude/projects/<repo>/memory/MEMORY.md` + files. Your machine only. Loaded natively.
3. **Third-party** — any other memory MCP/plugin the repo wires up (e.g. `claude-mem`).
4. **Team-shared** — hippius-mem (`mcp__hippius-mem__*`). Cross-machine, encrypted.

**Recall spans all tiers:** "recall before you act" means consult the natively-loaded
CLAUDE.md + `MEMORY.md` AND run a hippius-mem `recall` — not only the latter.

**Routing (avoid duplicating a fact across tiers):** team-durable, cross-machine facts
→ hippius-mem; personal/machine-specific → native memory; repo-invariant rules that
must ship with the code → `CLAUDE.md` / `AGENTS.md`.

**Seeding:** on a repo that ALREADY has memory (an existing `CLAUDE.md` / `AGENTS.md` /
`MEMORY.md`), do a one-time pass lifting genuinely team-relevant facts into hippius-mem
(deduped), so the team benefits from what one machine already learned.
</TEAM_MEMORY_MANDATES>
<!-- hippius-mem:end -->
