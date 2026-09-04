#!/usr/bin/env bash
# Prove the zero-tests guard fires.
#
# A guard that has never failed has not been tested. This removes the Caddy the
# lifecycle suite depends on, so the suite skips itself entirely and exits 0
# with no tests run -- the exact situation that reported the Stage 2 gate as
# passing on Linux when it had not run at all.
set -uo pipefail
export PATH="$HOME/node/bin:$PATH"
cd "$HOME/nlh-full" || exit 1

rm -rf .notlocalhost/caddy

out=$(node --test test/lifecycle.test.js 2>&1)
code=$?
echo "$out" | grep -E "^# (tests|pass|fail|skipped)" | sed 's/^/  /'
echo "  suite exit code: $code   <- exits 0 while proving nothing"

ran=$(echo "$out" | grep -E "^# tests " | grep -oE "[0-9]+" | head -1)
ran=${ran:-0}

if [ "$ran" -eq 0 ]; then
  echo
  echo "  GUARD FIRES: 0 tests ran, so the suite is reported as FAIL"
  exit 0
fi
echo
echo "  GUARD DID NOT FIRE (ran=$ran) - the hole is still open"
exit 1
