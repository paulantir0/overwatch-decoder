#!/usr/bin/env bash
# Portable verification gate: no game, no Windows, no privileges.
#   scripts/check.sh            Python + Node tests and a private-data guard
# Windows-only checks (native observer self-test, recorder tests) run in CI's
# manual windows job or on a Windows host; see windows/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."
py="${PYTHON:-python3}"

echo "== private-data guard"
if git ls-files 2>/dev/null | grep -E '^(\.runs|artifacts|private)/|\.(dmp|exe|dll|pak|casc|mkv|mp4|wav)$'; then
  echo "tracked private or binary artifacts found" >&2
  exit 1
fi

echo "== python syntax"
"$py" -m compileall -q overwatch_decoder tests tools scripts

echo "== python tests"
"$py" -m pytest -q

echo "== node tests"
node --check tools/entity-replay/app.js
node --check tools/field-replay/app.js
node --test tools/entity-replay/*.test.js tools/field-replay/*.test.js

echo "== ok"
