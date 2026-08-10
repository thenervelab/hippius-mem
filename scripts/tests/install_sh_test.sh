#!/usr/bin/env sh
# Tests scripts/install.sh WITHOUT network access, by putting stub `curl` and
# `uname` earlier on PATH than the real ones. The installer is the first thing
# a new user runs, so a wrong target triple or a swallowed download failure is
# a first-impression bug with no other test guarding it.
#
# --dry-run must resolve the target triple, build the download URL, print it,
# and exit before touching the network. So the assertions here are: (1) the
# printed URL names the expected target triple, and (2) curl is never
# actually invoked. Asserting against a file curl writes would be wrong here
# on purpose — if --dry-run correctly exits before downloading, curl never
# runs and never writes anything, so that assertion could only pass by
# accident. Assert against the script's stdout instead; the curl stub stays
# in place as a tripwire in case a future change starts calling curl under
# --dry-run.
#
# --dry-run only resolves a URL on the default prebuilt-binary path.
# --from-source and --update always build for real, and --add-team always
# mutates the config for real, so combining any of the three with --dry-run
# must be refused outright (exit non-zero, no download attempted), not
# silently fall through to the real action. That refusal is covered below
# for all three.
set -eu

# shellcheck disable=SC1007 # intentional: CDPATH= prefixes `cd` (empties it
# for this command only), it is not a mistyped "VAR = value" assignment.
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

STUBS="$WORK/stubs"
mkdir -p "$STUBS"

# Stub uname so the script believes it is on Linux x86_64.
cat > "$STUBS/uname" <<'STUB'
#!/usr/bin/env sh
case "$1" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *)  echo Linux ;;
esac
STUB
chmod +x "$STUBS/uname"

# Stub curl as a tripwire only: none of the cases below should ever reach a
# download, so this stub should never actually run. If it does, record the
# call so the assertions below notice.
cat > "$STUBS/curl" <<STUB
#!/usr/bin/env sh
echo "\$@" >> "$WORK/curl-calls"
exit 0
STUB
chmod +x "$STUBS/curl"

PATH="$STUBS:$PATH"
export PATH

# Defense in depth, not required by any passing case below: redirect the
# per-user config path into the sandbox so that IF a future regression ever
# let a case reach Step 3 (it should not — every case here is expected to
# stop before it), any prompt/write would land on a throwaway file cleaned
# up with $WORK, never on this machine's real
# ~/.config/hippius-mem/hippius-mem.toml.
HIPPIUS_MEM_CONFIG="$WORK/unused-config.toml"
export HIPPIUS_MEM_CONFIG

# Runs install.sh with the given args, writing combined stdout+stderr to $1
# and leaving its exit status in $status — without letting `set -e` abort
# this test script on a non-zero installer exit (some of the cases below
# expect exactly that).
run_installer() {
  _out=$1
  shift
  if sh "$REPO_ROOT/scripts/install.sh" "$@" >"$_out" 2>&1; then
    status=0
  else
    status=$?
  fi
}

# --- Case 1: plain --dry-run resolves the expected target triple -----------
run_installer "$WORK/out-plain" --dry-run

if [ "$status" -ne 0 ]; then
  echo "FAIL: install.sh --dry-run exited $status"
  cat "$WORK/out-plain"
  exit 1
fi

if ! grep -q "x86_64-unknown-linux-gnu" "$WORK/out-plain"; then
  echo "FAIL: installer did not resolve the x86_64-unknown-linux-gnu artifact"
  cat "$WORK/out-plain"
  exit 1
fi

echo "PASS: install.sh --dry-run resolves the expected target triple"

# --- Case 2: --dry-run refuses to combine with --from-source ---------------
# --from-source always skips the prebuilt-binary path, so there is no URL for
# --dry-run to resolve; the combination must be refused, not silently ignored
# by falling through to a real source build.
run_installer "$WORK/out-from-source" --dry-run --from-source

if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run --from-source exited 0 (expected a refusal)"
  cat "$WORK/out-from-source"
  exit 1
fi

if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run --from-source invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi

echo "PASS: install.sh --dry-run --from-source refuses the combination"

# --- Case 3: --dry-run refuses to combine with --update --------------------
# --update always rebuilds from source too, for the same reason as Case 2.
run_installer "$WORK/out-update" --dry-run --update

if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run --update exited 0 (expected a refusal)"
  cat "$WORK/out-update"
  exit 1
fi

if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run --update invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi

echo "PASS: install.sh --dry-run --update refuses the combination"

# --- Case 4: --dry-run refuses to combine with --add-team ------------------
# --add-team always mutates the config for real (a different kind of "real
# thing" than a build, but still not a no-op), for the same reason as Cases
# 2 and 3.
run_installer "$WORK/out-add-team" --dry-run --add-team

if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run --add-team exited 0 (expected a refusal)"
  cat "$WORK/out-add-team"
  exit 1
fi

if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run --add-team invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi

echo "PASS: install.sh --dry-run --add-team refuses the combination"

# --- Case 5: plain --dry-run on a platform with no prebuilt binary ---------
# try_binary_install()'s three early `return 1` paths (unresolvable target
# triple, missing curl, missing sha256sum/shasum) all happen BEFORE its own
# DRY_RUN check, which needs the constructed URL and so cannot run any
# earlier. Without a guard at the CALL SITE, plain --dry-run (no other flag)
# on a platform lacking a release artifact would silently fall through to a
# REAL Rust bootstrap + `cargo install` — the same bug class as Cases 2-4,
# just triggered by an environment condition instead of a flag.
#
# This case uses its own stub set, prepended ahead of the ones above, so
# that even if the bug under test reproduces, nothing real ever runs:
# `cargo` is a tripwire (records the call instead of building — this is the
# assertion that actually proves no build started, not just that the
# process exited), and `hippius-mem` is a harmless no-op stub so
# `command -v hippius-mem` can never resolve to a real, already-installed
# binary elsewhere on PATH and invoke it for real.
STUBS_UNSUPPORTED="$WORK/stubs-unsupported"
mkdir -p "$STUBS_UNSUPPORTED"

cat > "$STUBS_UNSUPPORTED/uname" <<'STUB'
#!/usr/bin/env sh
case "$1" in
  -s) echo SunOS ;;
  -m) echo sparc64 ;;
  *)  echo SunOS ;;
esac
STUB
chmod +x "$STUBS_UNSUPPORTED/uname"

cat > "$STUBS_UNSUPPORTED/curl" <<STUB
#!/usr/bin/env sh
echo "\$@" >> "$WORK/curl-calls"
exit 0
STUB
chmod +x "$STUBS_UNSUPPORTED/curl"

# Tripwire: if the installer ever reaches a real build attempt, this stub
# intercepts `cargo install` and records it instead of a real build running.
cat > "$STUBS_UNSUPPORTED/cargo" <<STUB
#!/usr/bin/env sh
echo "\$@" >> "$WORK/cargo-calls"
exit 0
STUB
chmod +x "$STUBS_UNSUPPORTED/cargo"

# Defensive no-op: prevents `command -v hippius-mem` from resolving to a
# real, already-installed binary elsewhere on PATH if the bug reproduces.
cat > "$STUBS_UNSUPPORTED/hippius-mem" <<'STUB'
#!/usr/bin/env sh
exit 0
STUB
chmod +x "$STUBS_UNSUPPORTED/hippius-mem"

_orig_path=$PATH
PATH="$STUBS_UNSUPPORTED:$PATH"
export PATH

run_installer "$WORK/out-unsupported" --dry-run

PATH=$_orig_path
export PATH

if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run exited 0 on an unsupported platform (expected a refusal)"
  cat "$WORK/out-unsupported"
  exit 1
fi

if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run invoked curl on an unsupported platform (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi

if [ -f "$WORK/cargo-calls" ]; then
  echo "FAIL: install.sh --dry-run fell through to a real build on an unsupported platform"
  cat "$WORK/cargo-calls"
  exit 1
fi

echo "PASS: install.sh --dry-run refuses when no prebuilt binary exists for this platform"

# Tripwire, checked once more covering all five runs above: none of them
# should ever have invoked curl, and none should have started a build.
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh invoked curl during a --dry-run test (it must never download)"
  cat "$WORK/curl-calls"
  exit 1
fi

if [ -f "$WORK/cargo-calls" ]; then
  echo "FAIL: install.sh invoked cargo during a --dry-run test (it must never build)"
  cat "$WORK/cargo-calls"
  exit 1
fi

echo "PASS: install.sh resolves the expected target triple and refuses invalid --dry-run combinations"
