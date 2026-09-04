#!/usr/bin/env bash
# Full Linux verification: every suite, the packed artefact, and the claims.
#
# The Stage 2 gate names three operating systems. This is the Linux half, run
# end to end rather than in pieces, so a pass here means the same thing a pass
# on Windows means.
set -uo pipefail

export PATH="$HOME/node/bin:$PATH"
export NOTLOCALHOST_BROWSER_PATH="$HOME/chrome/chrome-linux64/chrome"
[ -f "$HOME/chrome-deps/libpath" ] && export LD_LIBRARY_PATH="$(cat "$HOME/chrome-deps/libpath")"

WORK="$HOME/nlh-full"
FAILED=0
step() { printf '\n=== %s ===\n' "$1"; }
check() { if [ "$1" -eq 0 ]; then echo "  PASS  $2"; else echo "  FAIL  $2"; FAILED=$((FAILED+1)); fi; }

step "environment"
echo "  node   $(node --version)"
echo "  distro $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
"$NOTLOCALHOST_BROWSER_PATH" --version 2>/dev/null | sed 's/^/  browser /' || echo "  browser (none)"

step "copy the repo off the 9p mount"
rm -rf "$WORK"; mkdir -p "$WORK"
tar -C /mnt/c/xampp/htdocs/notlocalhost \
  --exclude=node_modules --exclude=.git --exclude='*.tgz' --exclude=.notlocalhost \
  -cf - . | tar -C "$WORK" -xf -
cd "$WORK"
npm install --no-audit --no-fund > /dev/null 2>&1
check $? "install"

step "lint and invariants"
npm run lint 2>&1 | tail -1
check ${PIPESTATUS[0]} "lint"

step "fetch a Linux Caddy so the gate can actually run"
node --input-type=module -e '
  const { resolveCaddy } = await import("./src/harness/caddy.js");
  const r = await resolveCaddy({ log: (m) => console.log("  " + m) });
  console.log("  " + r.path + "  (" + r.source + ")");
'
check $? "caddy"

step "every suite"
for suite in compat unit harness lifecycle report e2e; do
  case "$suite" in
    compat)    f=test/compat.test.js ;;
    unit)      f=test/unit.test.js ;;
    harness)   f=test/harness.test.js ;;
    lifecycle) f=test/lifecycle.test.js ;;
    report)    f=test/report.test.js ;;
    e2e)       f=test/e2e.test.js ;;
  esac
  out=$(node --test "$f" 2>&1)
  code=$?
  line=$(echo "$out" | grep -E "^# (tests|pass|fail|skipped)" | tr '\n' ' ')
  echo "  $(printf '%-10s' "$suite") $line"

  # A suite that ran nothing has proven nothing, and exits 0 while doing it.
  # Node reports a wholly-skipped describe as "# tests 0" rather than as a
  # skip, so counting what actually ran is the only reliable signal. This
  # exact hole reported the Stage 2 gate as passing on Linux when it had not
  # run at all.
  ran=$(echo "$out" | grep -E "^# tests " | grep -oE "[0-9]+" | head -1)
  ran=${ran:-0}
  if [ "$ran" -eq 0 ]; then
    echo "             ^ NO TESTS RAN - this suite proved nothing"
    code=1
  fi
  if echo "$out" | grep -q "^# skipped [1-9]"; then
    echo "             ^ some tests were skipped"
    code=1
  fi
  check $code "$suite"
done

step "the packed artefact, end to end"
npm run smoke 2>&1 | grep -E "checks passed|FAIL|do not publish"
check ${PIPESTATUS[0]} "smoke"

step "the RFC claims, against this Linux browser"
npm run evidence 2>&1 | grep -E "claims confirmed|REFUTED"
check ${PIPESTATUS[0]} "evidence"

step "doctor"
node bin/notlocalhost.js doctor 2>&1 | grep -E "^  \[|Nothing is blocking|blocking issue"
check ${PIPESTATUS[0]} "doctor"

step "result"
if [ "$FAILED" -eq 0 ]; then
  echo "  LINUX: everything passed"
else
  echo "  LINUX: $FAILED step(s) failed"
fi
exit "$FAILED"
