# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-11-24

A minor release: it adds a bucket object (`{team}/_keycheck/{epoch}`), a local
state file (`writer-tip-v3-<bucket>.json`), a CLI command and an MCP result
field.

### Upgrade notes

- **Restart every hippius-mem session after upgrading** (each agent session's
  MCP server, and a `serve` daemon). Until then 0.7.1 processes run beside this
  version. This version keeps 0.7.1's `writer-tip.json` current while it names
  this author's op on this bucket (never another seed's or another bucket's),
  so a 0.7.1 process under the same seed chains to its writes, and when it sees
  that a 0.7.1 process wrote, it checks its own published head too and logs "an
  older hippius-mem (0.7.1 or earlier) wrote on this machine". What stays as in
  0.7.1 while both run: a 0.7.1 write whose head publish failed can fork the
  chain, 0.7.1 processes under two seeds break each other's chains as before,
  and an edit's `expected_version` does not see a 0.7.1 process's concurrent
  edit.
- **Publish the team-key check once.** A server no longer publishes it at boot.
  On a team that predates it, run `hippius-mem admin keycheck publish` from a
  machine whose key is the team's (the founder's). Until then a wrong team key
  is only warned about, not refused. `rotate` and `provision` publish it from
  now on. 0.7.1 clients ignore the object.
- **What the storage gateway must support.** Publishing the key check is a
  create-only write (`If-None-Match: *` on PutObject, answered with 412 when the
  key exists), which makes two publishers with different keys unable to
  overwrite each other. `hippius-mem doctor` reports whether the gateway
  enforces it; Hippius gateway support is not confirmed. Without it, a check
  read back after it is written still catches every publisher that is not
  concurrent, and nothing else changes. Nothing else in this release needs new
  gateway support: completing an unconfirmed op and the same-machine
  `expected_version` check use plain PUTs, GETs and local files. Edits from
  two machines that read the same version still converge last-writer-wins.
- Tool results' `warnings` entries are `{ code, message }` objects.

### Added

- `hippius-mem admin keycheck publish [--replace]` publishes the team-key check
  for every epoch this machine holds a key for; `--replace` overwrites a wrong
  or unreadable one.
- `doctor` reports whether the storage gateway enforces create-only writes.

### Security

- `url` 2.5.8 -> 2.5.9 (and `form_urlencoded` 1.2.2 -> 1.2.3, which it
  requires) for RUSTSEC-2026-0592; `cargo deny check` passes again.
- `cookie` 0.18.2 -> 0.18.3 for RUSTSEC-2026-0594 (lockfile only).

### Fixed

- Two author seeds writing one team from the same state directory no longer
  break each other's op chains. `writer-tip.json` held one tip with no author,
  so the second author chained its op to the first author's op, and a fresh
  reader dropped almost every note both wrote. This version keeps its own tip
  file, `writer-tip-v3-<bucket>.json`, with one entry per author key and one
  file per bucket, so one team name used against two buckets no longer breaks
  the second bucket's chain either. The file is named after the bucket, not
  the endpoint URL, so sessions that reach one bucket through different URLs
  (a trailing slash, a host alias, a proxy) share one tip per author. An
  author has one entry per endpoint, and a write uses another endpoint's
  newer entry only after a GET finds that entry's op in this bucket, so two
  gateways that each hold a bucket of the same name keep separate chains and
  never erase each other's pending op. It keeps
  `writer-tip.json` current for 0.7.1 processes still running on the machine;
  see the upgrade notes. A `writer-tip-v2-<location>.json` from a pre-release
  build of this version is not read and can be deleted.
- A session killed after its op reached the bucket, or while its op PUT was
  still in flight, no longer makes the next same-seed session's acknowledged
  write vanish. The writer records the signed op as pending before the append,
  and the next writer completes it (an idempotent PUT of the same bytes) and
  chains to it.
- An op append the gateway does not confirm no longer forks the chain when it
  landed anyway. Under the writer lock the op stays pending and the next write
  completes it, and the write fails with "may not be stored yet; do not
  re-issue it" (`MemError::WriteOutcomeUnknown`) instead of a plain storage
  error. The note's ciphertext is kept.
- A write that waits more than 30 s (was 10 s) for another process to release
  the writer lock now fails with an error naming the lock file, and appends
  nothing. It used to mint without the lock, which forked the author's chain
  against the other process's write and could drop either one.
- A wrong but well-formed team key is detected. Each key epoch can have a
  key-check object at `{team}/_keycheck/{epoch}` (new in the bucket; older
  clients ignore it). `rotate`, `provision` and the new `hippius-mem admin
  keycheck publish` publish it, as a create-only write that is read back; a
  server never publishes one at boot. The server compares its key at boot and
  re-reads the check about once a minute after that. A mismatch
  refuses writes and index checkpoints, before any ciphertext is uploaded, with
  an error naming the fix, and `doctor` fails. With no check the server only
  warns, loudly when its key opens fewer than half of the epoch's oldest notes.
  A publish (`--replace` included) tries the key on those notes first and
  publishes nothing when it opens fewer than half of them, and `doctor` reports
  that probe and fails on it while no check is published and the team has not
  rotated past epoch 0 (beside a matching check, or after a rotation, it warns),
  so a machine with a wrong key can neither publish its check nor pass `doctor`
  on a team with notes and no check. `rotate` reports in its outcome, and warns, when it could not publish the new epoch's check, including when that epoch already has notes this machine's new key does not open. `admin keycheck publish --replace` replaces a wrong or unreadable
  check. See
  [Security](docs/SECURITY.md#team-key-check).
- `get` on a note whose stored ciphertext was altered, replaced or sealed under
  another key fails with "failed its integrity check" (`MemError::Integrity`),
  in a fresh process as in a warm one. A fresh process used to say "not found",
  and a warm one returned a generic storage error. `reconcile` gains
  `skipped_malformed_ops`, the count of `_oplog/` objects that do not decode as
  an op; they used to be skipped with a log line only.
- Write tools add a `warnings` array of `{ code, message }` entries to their
  result for what went degraded during that call (a write without the writer
  lock, a failed tip or head update after the op was durable, a team key that
  no published check confirms and that opens few of the team's notes), and
  `recall` and `refresh` add one when notes are left out of recall as
  undecodable. The key is absent otherwise. These used to reach stderr only.
  Each call reports only its own degradations, also on a `serve` daemon shared
  by several sessions.
- A gateway that accepts a connection and never answers fails an S3 request
  after 20 s per attempt, instead of holding it for the 5-minute attempt
  timeout while the session waits. With three attempts and the retry backoff
  one call fails in about 62 s; a write on a server that started moments before
  first waits up to 90 s for the warmup read, so it fails after about 2.5
  minutes (151 s was measured against a hung versitygw). A PUT's bound grows
  with its body, so a large index checkpoint on a slow link is not cut short.
- `edit` with a stale `expected_version` conflicts when the newer edit came from
  another process or machine. The check used the process's own index, so a
  second session that read v0 could overwrite an edit another session made from
  v0. On one machine the check now runs under the writer lock against an index
  that holds every op the machine's sessions committed, so of two concurrent
  edits from the same version the later one conflicts. The edit also syncs any
  author whose published head moved before it compares, which catches an edit
  committed on another machine before the call; one committed on another machine
  while the call runs still converges last-writer-wins. An edit that cannot see
  this machine's sessions settle after three syncs fails with
  `EditPreconditionBusy` and writes nothing.
- A malformed team key set through `HIPPIUS_MEM_TEAM_KEY_HEX` is reported under
  that name instead of `team_key_hex`, and the load error no longer tells a
  machine with an existing but invalid configuration to run `quickstart`.
- The size limits on `remember` and `edit` are documented in the tool schema and
  in `docs/REFERENCE.md`: summary 512 characters, body 131072 characters
  (Unicode scalar values, not bytes), 64 tags of 128 characters.
- `link` with `rel` `supersedes` (or another typed relation) takes effect in the
  next `recall` on the same machine; it used to wait for a refresh or restart.
- `gc --dry-run --grace-hours 0` previews instead of being refused; the refusal
  of a zero window suggested `--dry-run` but ran before `--dry-run` was read.
- Docs: the founder build line in `docs/TEAMS.md` adds `http-mcp`, so it no
  longer replaces the installed binary with one where `serve` and the
  `url`-wired clients stop working. The docs no longer name a `hippius-mem
  snapshot` command, which does not exist, and no longer offer
  `--from-source` for semantic recall on Intel macOS, where the embeddings
  build does not link without a locally built ONNX Runtime.
- `remember` without `force` refuses a note whose summary matches an existing
  note in the same scope also when that note has tags. The stored side of the
  lexical comparison counted the tags as words, so a tagged note sent again
  was written a second time.
- A storage error from the S3 gateway is one short line: the HTTP status,
  the S3 error code, the gateway's message cut to 200 characters, and the
  request id. It used to carry the SDK's whole error chain, which repeated
  the access key id and the signed request on a signature mismatch and the
  full response body however large (20 MiB was measured).
- `remember` works in a repository whose name holds a character outside
  `[A-Za-z0-9_-]`, such as `next.js`. The name stays as is in the note and in
  `recall`; only its object-key segment is escaped (`_repo-next_2Ejs`), so the
  key alphabet does not change and every existing key keeps its name. A 0.7.1
  client skips such a note, since it reads the escaped segment as the repo
  name.
- A write the gateway did not confirm, followed by `gc` reclaiming its blob
  before the next write on that machine, no longer leaves the note
  unreadable for the whole team. The next write used to complete the op,
  which then named a deleted blob; it now drops that op and logs that the
  unconfirmed write is lost, and the note keeps its previous version. Such
  a write is also dropped once it is an hour old, because `gc` on another
  machine could delete its blob between the check and the op's PUT, and
  `gc` now refuses `--grace-hours` below 2 for a real sweep (it refused only
  0), so the two hours cover that hour plus an hour of clock difference.
- A checkpoint no longer deletes itself when the bucket holds three or more
  checkpoint objects at higher keys that this machine cannot open (a team
  re-created under the same name, a foreign upload). The retention sweep
  counted those, so every honest checkpoint fell outside the three it keeps
  and was removed right after it was written, and every sync rebuilt in
  full. The sweep now deletes only checkpoints older than the one just
  written, and a process downloads a checkpoint that does not open only
  once.
- Committing an anchor batch reads the next sequence number from this
  author's own `_anchors/{author}/` prefix only: one LIST, and a GET of the
  newest record, whose signature must verify under the author's key. The
  batch takes the first free number above that record. It used to download
  every anchor record of every teammate, under the writer lock, on each
  batch (201 GETs with 200 teammate records), and took the number from any
  record body that claimed this author, so one record naming the last
  possible number made every sixteenth write spin forever. A key at the last
  number that this author did not sign is now stepped over, and a run of
  collisions gives up after 8 attempts.
- A member whose `author_seed_hex` is not its mnemonic's seed (the setup
  `join --bundle` and the installer create, one random seed per machine)
  now loads the key of an epoch the founder rotated to. Its member key, and
  so the founder's wrap, is stored under the author address, but the
  bootstrap looked the wrap up under the mnemonic's address, so after
  `rotate` or `remove` no such member received the new key and every
  machine kept sealing under the old one. `doctor` now fails when the team
  has rotated past epoch 0 and this machine has no wrap of the newest
  epoch it can open, and `join` logs the address the founder provisions to.
- `rotate` and `remove` no longer mint an epoch the team already has when
  this machine's `max_epoch` is stale (for example a founder who rotated,
  restarted, and did not raise it). The new epoch was one past the local
  key ring and `max_epoch` only, so a second rotation minted the same epoch
  with a new key and overwrote its wraps, and notes sealed under the first
  key could not be opened after a restart. The new epoch is now also past
  the highest epoch with a wrap in the bucket, a rotation to an epoch that
  already has a key check is refused (`MemError::EpochTaken`), and a
  rotation's wraps are create-only writes where the gateway enforces them.
- The founder's `rotate`, `remove`, `provision`, `members` and recovery
  commands use the same manifest rollback protection as `sync`. They read
  the bucket's manifest directly, so when the newest manifest object was
  garbled or gone, a rotation wrapped the new key to a member that manifest
  had removed, and the next `remove` signed the removed member back in. A
  manifest this machine publishes now raises the watermark and the durable
  marker at once, and a manifest that differs from the applied one at the
  same version is refused.
- A writer tip file that names an op the bucket no longer holds (a team
  re-created under the same name, or a bucket restored from an older copy,
  with the machine's state directory kept) no longer orphans every later
  write. The writer chained new ops to the missing one and a fresh reader
  dropped them all, a restart included. When this machine's own tip entry
  is ahead of what the process already holds, the writer now checks with
  one GET that the bucket holds that op and ignores the entry when it does
  not.
- A session anchors the ops it buffered below the 16-op batch threshold when
  it ends: when the client closes a stdio server's stdin, or on SIGTERM or
  Ctrl-C (stdio and `serve`). The buffer lived only in memory, so a stdio
  session, one process per agent session, anchored nothing unless it wrote
  16 ops, and `reconcile` checked almost no batches. An ending session also
  anchors this author's earlier ops above its newest signed batch record,
  such as those of a session that crashed: one LIST of its anchor prefix
  and one GET, one LIST of the op log and a GET per such op, so the cost
  does not grow with the author's history. The exit flush is bounded at 4 s,
  under the Hermes plugin's 5 s grace, and what it leaves is anchored by the
  next session. A code comment and `docs/SECURITY.md` said this already
  happened.
- Docs: `docs/SECURITY.md` and `docs/AGENTS-SUPPORT.md` now state the full
  cost of one identity writing from two machines: after a fork the losing
  machine's later writes are dropped too until its process restarts, each
  still returning an id, and the team view can flip to the longer branch.
  Behaviour is unchanged.
- On the shared `serve` daemon, `remember` without `repo` is refused with
  "invalid repo", naming the two valid forms (a repository name, or
  `"global"`), as the CLI already refuses it. It used to write the note
  team-global, into the pool every repository's recall and brief read.
- `get` no longer waits for the `Reinforce` op it may append after a recent
  `recall` (the writer lock, up to 30 s when another process holds it, and
  the op and head PUTs); the server appends it in the background. A
  read-only session, such as a second session on a trial vault, appends
  none, and `edit` no longer appends a `Reinforce` ahead of its own `Edit`.
- The session brief no longer lists a note another live note supersedes or
  duplicates, frames its notes as reference data teammates wrote rather
  than instructions, and keeps every summary on one line, so a note synced
  from another machine with a newline in its summary cannot add a heading
  or line of its own. A note dated in the future still sorts first.
- `install` and `install --uninstall` edit Codex's and Grok's
  `config.toml` in place: comments, key order and inline tables outside the
  `[mcp_servers.hippius-mem]` table are kept, uninstall gives back the file
  as it was. A config that is a symlink (a dotfiles checkout) is refused
  with an error naming it, and neither the link nor its target is changed:
  writing through the link would put the entry, which can carry the bearer
  token, into a file the user may commit. The file used to be re-serialized
  whole. This adds the `toml_edit` crate to the binary, already in the
  lockfile.
- `upgrade` refuses a destination bucket whose team prefix already holds
  objects this trial vault did not write (another vault upgraded there:
  every quickstart vault is named `trial` by default), before it copies or
  touches the config. It used to copy in, mixing two histories under two
  team keys, and flip the config before its own check failed. A re-run
  after a partial copy still works, and the copy no longer picks up a team
  whose name only starts with this one's (`trial2` for `trial`).
- Without a writer lock (no state directory resolves, or a store built
  without one), a sync running while an op append fails no longer makes
  the reclaimed op this author's head. The next acknowledged write chained
  to the deleted op, and a fresh reader dropped it.
- `install` checks that the daemon answering on the shared loopback port
  17432 is this user's before it wires clients to it: the daemon answers a
  fresh challenge on the new unauthenticated `GET /token-proof?nonce=` with
  a keyed hash of its bearer token, which never leaves the client, and a
  wrong answer fails the install naming the cause. On a host
  with several users it used to accept any daemon whose unauthenticated
  `/health` answered, and send this user's token and tool calls to it. A
  hand-run `serve` still treats any healthy daemon on the port as its own.
- Hermes plugin: a request to a hippius-mem child that never answers fails
  after 120 s instead of blocking the turn, a dead child's broken pipe is
  reported like any other tool failure instead of raising into the turn,
  `shutdown` returns (closing stdin, then SIGTERM, then SIGKILL) even when
  a background refresh is waiting on a stuck child, and a failed boot
  reports the child's last stderr lines.
- After a `rotate` or `remove`, a process that holds no key for the new
  epoch refuses to write a note (`EpochSuperseded`, naming both epochs and
  the fix) instead of sealing it under the older key, which a removed member
  still holds. This includes the `serve` daemon the installer wires, which
  runs without `HIPPIUS_MEM_MNEMONIC` and so cannot load rotated keys; its
  writes stay refused until the member runs a server with the mnemonic. The
  check costs one LIST of `{team}/_keys/` per minute on the write path.
- Startup loads rotated keys up to the newest epoch the founder provisioned,
  so a rotation reaches a member's server (one with the mnemonic) without
  raising `max_epoch`. `max_epoch` is now only a lower bound, and the
  "max_epoch is stale" warnings in `doctor`, `serve`, `brief`, `report` and
  `garden` are replaced by a warning that the process holds no key for the
  team's newest epoch. `rotate` and `remove` no longer ask members to edit
  `max_epoch`.
- An epoch counts as rotated (for the next rotation's epoch, for startup,
  and for the write check above) only when a wrap at it is signed by the
  founder or the recovery key the manifest names. An object planted under
  `{team}/_keys/` used to set the next rotation's epoch: one at the highest
  epoch made every later `rotate` and `remove` fail.
- A membership publish (`publish-membership`, `remove`, `rotate --members`),
  naming a recovery key and `recover` take the first manifest version above
  the applied one that no object under `{team}/_manifest/` holds. A founder
  machine without the manifest marker that found the newest manifest garbled
  signed that version again from the previous roster and overwrote it, so
  readers that had applied it refused the new one and the others took a
  roster the garbled version had changed.

## [0.7.1] - 2026-11-19

### Fixed

- The edit-gate refuses edits under the Cursor CLI. `cursor-agent` loads a
  repository's `.claude/settings.json` hooks, but ignored the refusal
  `hippius-mem-recall-preflight.sh` printed and applied the edit, with nothing
  shown to the model. The hook now also prints the refusal as
  `hookSpecificOutput.permissionDecision`, which Cursor and Claude Code both
  honor. An installed repository gets the new hook on its next `hippius-mem
  init`.
- A recall that was rejected or returned an error no longer opens the
  edit-gate. `hippius-mem-recall-token.sh` wrote its token after any recall
  call; the Cursor CLI runs the hook for rejected and failed calls too, so a
  recall that never ran counted as one.

### Security

- A checkpoint can no longer change the text `recall` shows for a note, on a
  process running this version. A signed op attests a note's content hash, not its `summary`, `tags`, `updated` or
  `note_type`, so a current team member could rewrite those in a checkpoint
  record and every teammate's index took the rewrite. A process now indexes a
  checkpoint record only when it has itself decoded that revision's blob and
  read the same fields; any other record is decoded from its blob. The cost is
  one read of each live note on a process's first sync, which the local blob
  cache serves from disk on a machine that has synced before (one run each on
  a vault of 6,917 notes: 37 s against 11 s for a machine's first cold start,
  5 s against 7 s for the next). A machine with no blob cache directory reads
  every live note from the bucket in each new process. Teammates on 0.7.0 or
  older still index a forged record and copy it into the checkpoints they
  write, so the fix is complete once the whole team has upgraded. A
  checkpoint's embedding vectors are still unverified, and they affect
  ranking. See "A snapshot's `embedding` is not verified" in
  `docs/SECURITY.md`.

## [0.7.0] - 2026-11-18

### Added

- `hippius-mem eval [--sample N]` measures recall quality on your own vault,
  read-only: where recall ranks a note for a sentence taken from its body, and
  how many pointers off-topic queries return. Use it to compare two builds or
  two settings on the same vault.
- The `brief` tool takes a `repo` argument, scoped as for `recall`.
- Path notes: a note tagged `path:<file or directory>` (relative to the
  repository root, with `repo` set) is tied to that code. The edit hook shows
  it to an agent on its first edit of a file there, so the agent sees the note
  without having searched for it. `hippius-mem path-notes --repo-root <dir>
  --file <path>` prints them; it asks the shared HTTP daemon, so a session on
  the stdio server gets none. An installed repository gets the new hook on its
  next `hippius-mem init`.
- `hippius-mem garden [--json]` lists what in a vault needs attention: notes
  per scope, notes replaced and still live, likely duplicates, and stale notes
  nobody has reused. It writes nothing to the bucket.
- `hippius-mem verify-history <file>` checks the anchor proofs in a saved
  `history` result offline, with no config, key or network.
- `hippius-mem recall`, `get`, `remember` and `call <tool>`: the memory tools
  from a command line, as JSON, through the shared HTTP daemon. `call` reaches
  all eleven tools. They need the daemon and never build a store of their own.
  `remember` takes its scope from the `origin` remote of the current directory's
  repository and requires `--repo` where there is none.

### Changed

- A `get` after a `recall` no longer appends a `Reinforce` op when its author
  is already counted among the note's reinforcers and the note was reinforced
  in the last 24 hours (or is dated in the future). Such an op could not raise
  the reuse boost, which counts distinct authors, and each one is an op object
  every teammate's cold sync reads. The one-hour limit it complements lived in
  a single process's memory, so every new agent session repeated the op.
- `remember` without `repo` writes to the repository the server was launched
  in, as `recall` already reads from it. It used to write a team-wide note, so
  every repository's notes collected in the pool that every other repository's
  recall and brief read. Pass `repo: "global"` for a team-wide note. On the
  shared HTTP daemon, which is bound to no repository, an omitted `repo` still
  writes a team-wide note. The result now names the `repo` written to.
- `recall` ranks by how well a note matches before how recent or reused it is.
  The two legs now combine by magnitude, and recency and reuse only reorder
  notes of similar relevance. On a live vault of about 6,900 notes, a sentence
  from a note's body recalled that note first for 26% of notes and within the
  default 12 pointers for 60%; the ranking this replaces scored 8% and 44% on
  the same vault the same day, 24 notes earlier (`hippius-mem eval --sample
  150`).
- `recall` scores are comparable across queries: a fresh note covering the
  whole query scores `0.8` on keywords alone and up to `1.0` when the embedding
  model agrees. Scores from earlier versions were about `0.03` for
  every result and are not comparable with the new ones.
- `recall` returns every strong match and at most three weak ones, each marked
  `weak: true`, so a query nothing answers returns a few marked guesses, not a
  full page. `total_matched` counts only what a larger `k` would return. The
  dashboard's search is not capped.
- Function words in a query ("the", "for", "what") no longer count as keyword
  matches, unless the query holds nothing else. On the lexical build a query
  that shares only such words with a note does not recall it.
- `brief` (the tool, the `brief` command and the session-start hook) covers
  the current repository's notes plus team-wide ones, the repository's own
  first. It used to render every repository's notes. A client on the shared
  HTTP daemon, or a Hermes plugin whose process has no git remote, gets
  team-wide notes only unless it passes `repo`.
- `brief` keeps up to 30% of its budget for gotchas and 10% for the index of
  references, so more decisions than fit no longer leave the gotchas out.

### Fixed

- The edit hook's messages reach the agent. `hippius-mem-recall-preflight.sh`
  printed its context in a top-level `additionalContext` key, which Claude Code
  ignores for PreToolUse hooks; it now also prints it inside
  `hookSpecificOutput`. A repository gets the fixed hook on its next
  `hippius-mem init`.

## [0.6.0] - 2026-11-09

### Changed

- Builds now use Rust 1.99.1 (`rust-toolchain.toml`), and the minimum
  supported Rust version is 1.99. A source build needs Rust 1.99 or newer;
  prebuilt binaries and `install.sh` are unaffected.
- `mint-token` and `invite` (source builds with `--features console`) now
  verify api.hippius.com's certificate against the operating system's trust
  store instead of a bundled Mozilla root list (reqwest 0.13). A machine that
  intercepts TLS with a locally trusted CA now works. On Linux with no CA
  certificates installed, both commands exit with an error asking to install
  them or set `SSL_CERT_FILE`. Prebuilt binaries do not include `console`.
- The prebuilt binaries for Apple silicon and Linux now include ONNX Runtime
  1.31.0 instead of 1.24.2 (fastembed 7.6). Embedding models, the model
  cache, and stored vectors are kept: new vectors differ from old ones only by
  float rounding, so existing notes are not re-embedded. The Linux binaries
  still need glibc 2.38 or newer, and the x86_64 Linux binary needs a CPU
  with AVX2 (ort now warns about this at startup). Intel macs still get the
  lean (lexical-recall) build. The model download now also sends the
  `HF_TOKEN` environment variable to Hugging Face when it is set, as it
  already sent the token saved by `huggingface-cli login`. The Apple silicon
  binary now links the system CoreML framework, because the only ONNX Runtime
  build ort ships for that target includes the CoreML provider; hippius-mem
  still runs on the CPU.

### Security

- `import` now bundles SQLite 3.54.1 (rusqlite 0.41), fixing CVE-2026-119375:
  opening a crafted database and `-wal` pair could return uninitialized
  memory (RUSTSEC-2026-0459). This affects source builds with
  `--features import` only; prebuilt binaries do not include `import`.
- Updated rmcp to 3.9 (RUSTSEC-2026-0457; its OAuth client is not compiled
  into hippius-mem) and tokio to 1.54.1 with the `AsyncFd` I/O-safety fix
  (RUSTSEC-2026-0386), along with other dependencies to their latest
  compatible versions. The MCP server still negotiates protocol versions up
  to 2025-11-25 and does not accept the handshake-less 2026-07-28 protocol
  that rmcp 3 adds.
- RUSTSEC-2026-0387 (crypto-bigint timing side channels) remains in source
  builds with `--features console` (`mint-token`): no release of alloy-signer
  reaches the fixed crypto-bigint yet. Prebuilt binaries do not include
  `console`.

## [0.5.0] - 2026-10-23

### Added

- A redesigned `hippius-mem dashboard`: one screen with vaults and repos on
  the left, notes in the middle and the selected note on the right, over a
  dark glass theme with the Hippius logo. Above the list it shows live notes
  by type, the last 7 days of activity and the most reused notes. Search,
  type chips and tag filters compose; `/`, `j`/`k` and `g` work from the
  keyboard. The fonts (Geist, Geist Mono, Unbounded, all SIL OFL 1.1) and the
  logo are bundled in the binary and served from `/assets/`, so the page still
  loads nothing from the network.
- `MemoryStore::recall_all_repos` and `RecallScope` in `hippius-mem-core`:
  rank a query against every repository of a team, for tools that browse a
  whole vault. It does not mark hits as recalled, so it never reinforces.
  The agent-facing `recall` stays repo-scoped.
- `MemoryStore::refresh_now`: the cheap change check of `refresh_if_stale`
  without its 20-second window, for a person asking whether anything is new.
  The dashboard's sync pill uses it, so "Synced" now means it checked, and a
  failed check shows as failed.

- Wallet login (`POST /api/auth/verify/`, used to mint S3 sub-tokens) now
  sends `substrate_signature`: an sr25519 signature over the challenge message
  by the mnemonic's Substrate key, under the standard `substrate` context.
  The Hippius API will soon refuse logins from accounts that have never sent
  it (#128).

### Fixed

- Dashboard search with no repo selected now searches every repo of the
  vault. It used to search only team-wide notes. With a repo selected, search
  now returns only that repo's notes, matching the list.
- Opening a note found by a dashboard search no longer counts as a teammate
  reusing it. Reuse is an agent signal; a person browsing used to append a
  `Reinforce` op.
- The dashboard shows a note's links. They come from `Link` ops, which only
  the op-log history folds in, so the note detail always returned an empty
  list. Links now load with the audit trail (`/notes/{id}/history` carries
  `links`; the note detail no longer has the field).
- `recall` and `get` no longer stall for minutes behind a background sync
  (#125). Three causes, each fixed:
  - A `Relate` or `Reinforce` in the op-log tail forced a full index rebuild.
    A `get` after a `recall` writes a `Reinforce`, so this was most syncs. The
    incremental path now applies both.
  - A full rebuild ran the embedding model over every live note. It now reuses
    a vector this process computed when the note's summary is unchanged, and
    embeds the rest.
  - A corpus embed held the model lock from start to finish, so a query embed
    waited for all of it. A large embed now runs in batches of 256 and lets
    any waiting query or single-note embed go first before each batch, so a
    query waits for at most the batch in flight.
  - A sync pass discarded because this process wrote during it threw its
    vectors away, and the retry embedded the same text again (on a cold start,
    the whole corpus, up to four times). The retry now reuses them.
- A checkpoint's stored vectors are no longer reused by a different embedding
  model of the same width (`all-MiniLM-L6-v2` and `bge-small-en-v1.5` are both
  384). The checkpoint now records the model; a restore under another model
  discards the vectors and embeds again.

### Changed

- Checkpoints carry a new optional `vector_space` field. Older releases ignore
  it and keep reading new checkpoints. A checkpoint without it (written by an
  older release) has its vectors discarded: the first cold start after
  upgrading embeds the whole corpus once (minutes on a few-thousand-note team)
  and writes a stamped checkpoint that later cold starts on the same model
  reuse. While some machines still run an older release, each checkpoint they
  write can cost one more such cold start. A team whose members run different
  embedding models shares one checkpoint: a cold start that finds the other
  model's checkpoint newest embeds the whole corpus.

### Security

- Removing the full rebuild that ran on most syncs also removes a side effect:
  it used to clear a forged checkpoint record (a wrong summary, tags or
  vector written by a current team member) within a sync or two. Such a
  forgery now lasts until the note is edited or the index is rebuilt in full.
  A full rebuild embeds again every vector that came from a checkpoint,
  and a machine keeps a vector it computed itself over a checkpoint's. See "A snapshot's ... are not verified" in
  `docs/SECURITY.md`.

## [0.4.2] - 2026-09-28

Security update (rmcp 2.2.0) and a SessionStart brief that fits its time box
again. No format or protocol change; mixes freely with 0.4.x.

### Fixed

- The SessionStart brief (`hippius-mem brief`) syncs directly instead of probing
  first: a fresh process can never skip the sync, so the probe only repeated its
  op-log LIST. 7.6-11s to about 4s on a 4.6k-note team, which brings it back
  under the hook's 8s time box (past it, the hook injects nothing).

### Security

- `rmcp` 1.8.0 to 2.2.0, closing GHSA-9pj6-vhgr-3mwh (unauthenticated
  session-table leak in the Streamable HTTP server transport that
  `hippius-mem serve` uses; exposure here was limited to loopback behind the
  bearer token), GHSA-33f5-2c5q-wgwj (OAuth protected-resource metadata
  validation) and GHSA-9g45-5xwm-f3wc (custom headers leaking to cross-origin
  redirects). No protocol change for clients.

## [0.4.1] - 2026-09-28

Cheaper freshness checks: a recall that re-probes the shared log reads each
author's signed head instead of listing every op key. No format change; mixes
freely with 0.4.0.

### Changed

- The pre-read freshness probe reads the per-author signed heads (a few small
  objects) instead of listing every op key, and syncs only when a head moved.
  The full op-key count still runs when a head moved or cannot be read, and at
  least every 5 minutes as the backstop for a head that failed to publish.
  Measured on a 4.6k-note team: a quiet refresh 2.0-3.1s to 0.4-0.7s, and the
  first request after warmup no longer lists the op log at all. Tradeoff: a
  write whose head reads back unchanged (a failed head publish, a stale read of
  the overwritten head, or two machines racing under one identity) now appears
  within 5 minutes rather than on the next probe; a normal write still appears
  on the next probe.
  `hippius-mem profile` shows both probes and reports any op-log author that
  publishes no head.

## [0.4.0] - 2026-09-28

Faster recall: a new session's first sync drops from ~36s to ~5s and a
refresh re-sync from ~19s to ~3.5s on a 4.6k-note team, by running the cold
sync once, caching the index checkpoint, and writing it ~5x smaller. Upgrade a
team together (see Changed).

### Added

- `hippius-mem profile`: times each cold-start phase (store build, refresh probe,
  op-log read + verify, checkpoint load, cold sync and re-sync, recall) against the
  bound team's real bucket, splitting wall time from S3 time with LIST/GET counts
  and bytes. The gateway is wrapped read-only, so it never writes to the bucket.
- `InstrumentedBlobStore` (core): a `BlobStore` decorator counting calls, S3 time
  and bytes per operation, with an optional read-only mode.
- `sync_phases` criterion bench: per-phase CPU cost over a 5,000-note corpus plus
  a round-trip census, run nightly beside `store_benches`.
- `llms.txt`: a short agent index that points at FOR-AGENTS.md and the README.

### Changed

- Index checkpoints are written about 5x smaller (94 MiB to 19 MiB measured on a
  4.6k-note team): sealed records and embedding vectors are stored as base64
  instead of JSON number arrays. Checkpoints written by older releases still
  load. **Upgrade a team together:** a release before this one downloads each
  new-format checkpoint (up to three are retained) before skipping it as
  unreadable, then full-replays and writes a legacy-format checkpoint that this
  release must download again. Every result stays correct; a mixed-version team
  just moves large checkpoints back and forth until everyone upgrades.
- The newest index checkpoint is cached (in memory, and beside the blob cache for
  S3 profiles) and reused while the bucket still lists it, instead of being
  downloaded on every sync. A new session and every refresh re-sync skip the
  download (90 MiB for a 4.6k-note team); measured cold sync 16s to 4.4s,
  re-sync ~19s to ~4s.

### Fixed

- A sync whose op-log listing lagged behind this machine's own just-acknowledged
  write no longer drops that note from the local index (or rolls an edit back)
  until the next sync. Such a view is detected (this author's head is missing
  from it), installed monotonically with the unseen own notes kept, and never
  written as a checkpoint.
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

[Unreleased]: https://github.com/thenervelab/hippius-mem/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/thenervelab/hippius-mem/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/thenervelab/hippius-mem/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/thenervelab/hippius-mem/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/thenervelab/hippius-mem/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/thenervelab/hippius-mem/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/thenervelab/hippius-mem/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/thenervelab/hippius-mem/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/thenervelab/hippius-mem/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/thenervelab/hippius-mem/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/thenervelab/hippius-mem/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/thenervelab/hippius-mem/releases/tag/v0.1.0
