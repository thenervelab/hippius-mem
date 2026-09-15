#!/bin/sh
# Stdlib-only tests for integrations/hermes (no pytest required).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
python3 -m unittest discover -s integrations/hermes/tests -v
