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
# Restored after cases that shrink PATH to a stubs-only directory.
_orig_path=$PATH

# Redirect the per-user config path into the sandbox. Every case but the last
# is expected to stop before Step 3; Case 14 reaches it on purpose, in a
# session with no controlling terminal, and asserts nothing is written. If a
# regression ever let another case reach a prompt, the write would land on
# this throwaway file cleaned up with $WORK, never on this machine's real
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
  # Absolute /bin/sh so cases that shrink PATH to a stubs-only dir (missing
  # curl / missing sha256 tool) still have a shell to run the installer.
  if /bin/sh "$REPO_ROOT/scripts/install.sh" "$@" >"$_out" 2>&1; then
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

# --- Case 6: --dry-run with curl missing must refuse, not build ------------
# Same call-site guard as Case 5, triggered by try_binary_install's missing-curl
# early-out instead of an unknown uname. PATH is stubs-only so the real curl
# later on the machine cannot satisfy `command -v curl`.
STUBS_NO_CURL="$WORK/stubs-no-curl"
mkdir -p "$STUBS_NO_CURL"

# Shebangs are /bin/sh (not `env sh`): these cases shrink PATH to this
# directory so the real curl/sha256 tools cannot be found, which also
# hides `sh` itself.
cat > "$STUBS_NO_CURL/uname" <<'STUB'
#!/bin/sh
case "$1" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *)  echo Linux ;;
esac
STUB
chmod +x "$STUBS_NO_CURL/uname"

cat > "$STUBS_NO_CURL/cargo" <<STUB
#!/bin/sh
echo "\$@" >> "$WORK/cargo-calls"
exit 0
STUB
chmod +x "$STUBS_NO_CURL/cargo"

cat > "$STUBS_NO_CURL/hippius-mem" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$STUBS_NO_CURL/hippius-mem"

PATH="$STUBS_NO_CURL"
export PATH

run_installer "$WORK/out-no-curl" --dry-run

PATH=$_orig_path
export PATH

if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run exited 0 when curl is missing (expected a refusal)"
  cat "$WORK/out-no-curl"
  exit 1
fi

if ! grep -q "curl not found" "$WORK/out-no-curl"; then
  echo "FAIL: missing-curl --dry-run did not explain that curl is missing"
  cat "$WORK/out-no-curl"
  exit 1
fi

if [ -f "$WORK/cargo-calls" ]; then
  echo "FAIL: install.sh --dry-run fell through to a real build when curl is missing"
  cat "$WORK/cargo-calls"
  exit 1
fi

echo "PASS: install.sh --dry-run refuses when curl is missing"

# --- Case 7: --dry-run with no sha256 tool must refuse, not build ----------
STUBS_NO_SHA="$WORK/stubs-no-sha"
mkdir -p "$STUBS_NO_SHA"

cat > "$STUBS_NO_SHA/uname" <<'STUB'
#!/bin/sh
case "$1" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *)  echo Linux ;;
esac
STUB
chmod +x "$STUBS_NO_SHA/uname"

cat > "$STUBS_NO_SHA/curl" <<STUB
#!/bin/sh
echo "\$@" >> "$WORK/curl-calls"
exit 0
STUB
chmod +x "$STUBS_NO_SHA/curl"

cat > "$STUBS_NO_SHA/cargo" <<STUB
#!/bin/sh
echo "\$@" >> "$WORK/cargo-calls"
exit 0
STUB
chmod +x "$STUBS_NO_SHA/cargo"

cat > "$STUBS_NO_SHA/hippius-mem" <<'STUB'
#!/bin/sh
exit 0
STUB
chmod +x "$STUBS_NO_SHA/hippius-mem"

PATH="$STUBS_NO_SHA"
export PATH

run_installer "$WORK/out-no-sha" --dry-run

PATH=$_orig_path
export PATH

if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run exited 0 when no sha256 tool is present (expected a refusal)"
  cat "$WORK/out-no-sha"
  exit 1
fi

if ! grep -q "neither sha256sum nor shasum" "$WORK/out-no-sha"; then
  echo "FAIL: missing-sha --dry-run did not explain that no checksum tool is present"
  cat "$WORK/out-no-sha"
  exit 1
fi

if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run invoked curl when no sha256 tool is present"
  cat "$WORK/curl-calls"
  exit 1
fi

if [ -f "$WORK/cargo-calls" ]; then
  echo "FAIL: install.sh --dry-run fell through to a real build when no sha256 tool is present"
  cat "$WORK/cargo-calls"
  exit 1
fi

echo "PASS: install.sh --dry-run refuses when no sha256 tool is present"

# --- Cases 8-13: the --solo / --bundle onboarding flags ---------------------
# Every case here refuses (or errors) at argument-validation time — BEFORE the
# binary is ever acquired — so, exactly like the --dry-run cases above, none of
# them may invoke curl or start a build. They run under the default stub PATH
# (Linux x86_64, curl tripwire present), which is what is in effect after Case 7
# restored $_orig_path. Testing a *bare* --solo / --bundle is deliberately NOT
# done: that would run quickstart / join for real, which these offline tests
# must never do. The refusal cases give full coverage of the new argument gates.

# --- Case 8: --dry-run --solo refuses --------------------------------------
# --solo runs `hippius-mem quickstart` for real, so there is no download URL for
# --dry-run to resolve; the combination must be refused (same class as Cases 2-4).
run_installer "$WORK/out-dry-solo" --dry-run --solo
if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run --solo exited 0 (expected a refusal)"
  cat "$WORK/out-dry-solo"
  exit 1
fi
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run --solo invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi
echo "PASS: install.sh --dry-run --solo refuses the combination"

# --- Case 9: --dry-run --bundle refuses ------------------------------------
# --bundle runs `hippius-mem join --bundle` for real, same reasoning as Case 8.
run_installer "$WORK/out-dry-bundle" --dry-run --bundle "$WORK/whatever.toml"
if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --dry-run --bundle exited 0 (expected a refusal)"
  cat "$WORK/out-dry-bundle"
  exit 1
fi
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run --bundle invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi
echo "PASS: install.sh --dry-run --bundle refuses the combination"

# --- Case 10: --solo and --bundle are mutually exclusive -------------------
# One starts a solo trial vault, the other joins an existing team; asking for both
# is contradictory and must be refused before any acquisition.
run_installer "$WORK/out-solo-bundle" --solo --bundle "$WORK/whatever.toml"
if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --solo --bundle exited 0 (expected a refusal)"
  cat "$WORK/out-solo-bundle"
  exit 1
fi
if ! grep -q "mutually exclusive" "$WORK/out-solo-bundle"; then
  echo "FAIL: install.sh --solo --bundle did not explain the mutual exclusion"
  cat "$WORK/out-solo-bundle"
  exit 1
fi
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --solo --bundle invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi
echo "PASS: install.sh --solo --bundle refuses the combination"

# --- Case 11: --solo and --update are mutually exclusive -------------------
# --solo is a fresh onboarding flow; --update rebuilds an existing install.
run_installer "$WORK/out-solo-update" --solo --update
if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --solo --update exited 0 (expected a refusal)"
  cat "$WORK/out-solo-update"
  exit 1
fi
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --solo --update invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi
echo "PASS: install.sh --solo --update refuses the combination"

# --- Case 12: --bundle with no value errors --------------------------------
run_installer "$WORK/out-bundle-noval" --bundle
if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --bundle (no value) exited 0 (expected an error)"
  cat "$WORK/out-bundle-noval"
  exit 1
fi
if ! grep -q "requires a value" "$WORK/out-bundle-noval"; then
  echo "FAIL: install.sh --bundle (no value) did not explain the missing value"
  cat "$WORK/out-bundle-noval"
  exit 1
fi
echo "PASS: install.sh --bundle with no value errors out"

# --- Case 13: --bundle <missing file> refuses before acquisition -----------
# A typo'd bundle path must fail fast — before any download or build — not after.
run_installer "$WORK/out-bundle-missing" --bundle "$WORK/no-such-bundle.toml"
if [ "$status" -eq 0 ]; then
  echo "FAIL: install.sh --bundle <missing> exited 0 (expected a refusal)"
  cat "$WORK/out-bundle-missing"
  exit 1
fi
if ! grep -q "invite bundle not found" "$WORK/out-bundle-missing"; then
  echo "FAIL: install.sh --bundle <missing> did not explain the missing bundle file"
  cat "$WORK/out-bundle-missing"
  exit 1
fi
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --bundle <missing> invoked curl (should refuse before doing anything)"
  cat "$WORK/curl-calls"
  exit 1
fi
echo "PASS: install.sh --bundle refuses a missing bundle file before acquiring anything"

# Tripwire, checked once more covering every run above: none of them
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

# --- Case 14: a headless run takes the no-TTY branch and exits 0 -----------
# `[ -e /dev/tty ]` used to gate Step 3. The device node exists on every
# Linux/macOS box even when the process has no controlling terminal (a CI
# runner, an agent's detached subprocess), so the installer entered the
# interactive branch and died at the first `printf >/dev/tty` under set -e.
# This case drives the script all the way to Step 3 in a session with no
# controlling terminal and expects the warning branch, not the prompt.
#
# Reaching Step 3 needs a binary. The curl stub above makes the prebuilt path
# fall through (it writes no archive, so the checksum check fails) and a
# `cargo` stub stands in for the source build by planting a do-nothing
# `hippius-mem` where the installer looks for it. HOME and CARGO_HOME point
# into $WORK so nothing on this machine is touched, and cwd is $WORK (not a
# git repo) so Step 4 skips `init`. Runs LAST: it is the one case that
# legitimately trips the curl tripwire.
cat > "$STUBS/cargo" <<'STUB'
#!/usr/bin/env sh
mkdir -p "$CARGO_HOME/bin"
printf '#!/bin/sh\nexit 0\n' > "$CARGO_HOME/bin/hippius-mem"
chmod +x "$CARGO_HOME/bin/hippius-mem"
STUB
chmod +x "$STUBS/cargo"
mkdir -p "$WORK/home"

# Runs install.sh detached from the controlling terminal: `setsid -w`
# (util-linux, present on the Linux CI runner) or, where that is missing
# (macOS), python3's start_new_session. Leaves $status empty when neither
# exists so the case reports SKIP rather than a false PASS or FAIL.
run_headless() {
  _out=$1
  shift
  set -- env HOME="$WORK/home" CARGO_HOME="$WORK/cargo" /bin/sh "$REPO_ROOT/scripts/install.sh" "$@"
  if command -v setsid >/dev/null 2>&1; then
    set -- setsid -w "$@"
  elif command -v python3 >/dev/null 2>&1; then
    set -- python3 -c 'import subprocess, sys; sys.exit(subprocess.run(sys.argv[1:], start_new_session=True).returncode)' "$@"
  else
    status=""
    return 0
  fi
  if (cd "$WORK" && "$@") >"$_out" 2>&1; then
    status=0
  else
    status=$?
  fi
}

run_headless "$WORK/out-headless"
if [ -z "$status" ]; then
  echo "SKIP: neither setsid nor python3 available to detach from the terminal; headless case not run"
else
  if [ "$status" -ne 0 ]; then
    echo "FAIL: headless install.sh exited $status (expected 0 through the no-TTY branch)"
    cat "$WORK/out-headless"
    exit 1
  fi
  if ! grep -q "no TTY available" "$WORK/out-headless"; then
    echo "FAIL: headless install.sh did not take the no-TTY branch"
    cat "$WORK/out-headless"
    exit 1
  fi
  if grep -q "primary team" "$WORK/out-headless"; then
    echo "FAIL: headless install.sh entered the interactive prompt branch"
    cat "$WORK/out-headless"
    exit 1
  fi
  if ! grep -q "NOT WRITTEN" "$WORK/out-headless"; then
    echo "FAIL: headless install.sh did not flag the missing config in its Done block"
    cat "$WORK/out-headless"
    exit 1
  fi
  if [ -e "$HIPPIUS_MEM_CONFIG" ]; then
    echo "FAIL: headless install.sh wrote a config without a prompt"
    exit 1
  fi
  echo "PASS: install.sh with no controlling terminal takes the no-TTY branch and exits 0"
fi
