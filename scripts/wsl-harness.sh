#!/usr/bin/env bash
# Run the Stage 2 gate on Linux, from a Windows host, via WSL.
#
# The gate requires init, up, an HTTPS request and down leaving the machine
# byte-identical -- on every supported platform. This proves the Linux half
# without needing a Linux machine to hand.
set -euo pipefail

export PATH="$HOME/node/bin:$PATH"
WORK="$HOME/nlh-harness"

echo "=== node ==="
node --version

echo
echo "=== copy the repo off the 9p mount ==="
rm -rf "$WORK"; mkdir -p "$WORK"
tar -C /mnt/c/xampp/htdocs/notlocalhost \
  --exclude=node_modules --exclude=.git --exclude='*.tgz' --exclude=.notlocalhost \
  -cf - . | tar -C "$WORK" -xf -
cd "$WORK"

echo
echo "=== install ==="
npm install --no-audit --no-fund > /dev/null

echo
echo "=== fetch a Linux Caddy, verified against its published digest ==="
node --input-type=module -e '
  const { resolveCaddy } = await import("./src/harness/caddy.js");
  const r = await resolveCaddy({ log: (m) => console.log("  " + m) });
  console.log("  resolved:", r.path, "|", r.source, "|", r.version);
'

echo
echo "=== the Stage 2 gate on Linux ==="
npm run test:lifecycle 2>&1 | grep -E "^    (not )?ok|^# (tests|pass|fail|skip)"

echo
echo "=== the rest of the harness suite ==="
npm run test:harness 2>&1 | grep -E "^# (tests|pass|fail|skip)"

echo
echo "=== the published CLI contract still holds on Linux ==="
npm run test:compat 2>&1 | grep -E "^# (tests|pass|fail)"

echo
echo "=== doctor, on Linux, changing nothing ==="
node bin/notlocalhost.js doctor 2>&1 | head -28

echo
echo "LINUX HARNESS VERIFICATION COMPLETE"
