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

# Stub curl as a tripwire only: --dry-run must exit before any download, so
# this stub should never actually run. If it does, record the call so the
# assertion below notices.
cat > "$STUBS/curl" <<STUB
#!/usr/bin/env sh
echo "\$@" >> "$WORK/curl-calls"
exit 0
STUB
chmod +x "$STUBS/curl"

PATH="$STUBS:$PATH"
export PATH

# Run install.sh --dry-run, capturing stdout+stderr and the exit status
# without letting `set -e` abort this script on a non-zero exit.
if sh "$REPO_ROOT/scripts/install.sh" --dry-run > "$WORK/out" 2>&1; then
  status=0
else
  status=$?
fi

if [ "$status" -ne 0 ]; then
  echo "FAIL: install.sh --dry-run exited $status"
  cat "$WORK/out"
  exit 1
fi

# Assertion 1: the resolved download URL, printed to stdout, names the Linux
# x86_64 target triple.
if ! grep -q "x86_64-unknown-linux-gnu" "$WORK/out"; then
  echo "FAIL: installer did not resolve the x86_64-unknown-linux-gnu artifact"
  cat "$WORK/out"
  exit 1
fi

# Assertion 2 (tripwire): --dry-run must never invoke curl, since it exits
# before any download happens.
if [ -f "$WORK/curl-calls" ]; then
  echo "FAIL: install.sh --dry-run invoked curl (it must exit before downloading)"
  cat "$WORK/curl-calls"
  exit 1
fi

echo "PASS: install.sh resolves the expected target triple"
