#!/bin/sh
# Run every gate CI's `test` job runs, in CI's order, so a local pass means a CI pass.
#
# `pytest -q` alone collects only `tests/` (pyproject.toml testpaths), which silently skips the
# Python SDK, the browser JavaScript tests, and the whole TypeScript SDK chain. A fixture that
# expired reached main that way. Run this before pushing:
#
#   sh scripts/test_all.sh              # every gate
#   sh scripts/test_all.sh --offline    # skip the two gates that need the network
#
# Exits non-zero on the first failing gate and names it.

set -eu

offline=0
for arg in "$@"; do
  case "$arg" in
    --offline) offline=1 ;;
    *) echo "usage: sh scripts/test_all.sh [--offline]" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."

passed=""

gate() {
  name="$1"
  shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    passed="$passed $name"
  else
    printf '\nFAILED GATE: %s\n' "$name" >&2
    printf 'passed before it:%s\n' "$passed" >&2
    exit 1
  fi
}

# site/agents/ and the other generated pages are NOT tracked; CI builds them before it tests, and
# tests/test_site.py, test_preview.py and test_r3_deploy_parity.py assert the built files exist. A
# fresh clone or worktree fails those seven tests until this runs, which looks like a regression and
# is not one.
gate "generate-site" python scripts/build_site.py
gate "generate-marketplace-index" python scripts/build_index.py --no-provider-fetch

if [ "$offline" -eq 0 ]; then
  gate "python-dependency-audit" \
    python -m pip_audit --require-hashes -r requirements.lock --disable-pip
else
  echo "skipping python-dependency-audit (--offline)"
fi

gate "apa-reference-implementation" python spec/verify_apa.py --selftest
gate "apa-conformance-vectors" python spec/run_conformance.py
gate "variant-pack-determinism" python scripts/verify_variant_packs.py
gate "ruff" python -m ruff check .
gate "warden-tests" python -m pytest -q
gate "python-sdk-tests" python -m pytest -q sdk/python/tests
gate "browser-javascript-tests" sh -c 'node --test tests/js/*.test.js'

if [ "$offline" -eq 0 ]; then
  gate "typescript-sdk-install" sh -c 'cd sdk/ts && npm ci'
  gate "typescript-sdk-audit" sh -c 'cd sdk/ts && npm audit --audit-level=high'
fi

# vitest and tsc live in sdk/ts/node_modules, which only `npm ci` creates. Skipping the install and
# then running these would report a failure that says nothing about the code.
if [ -d sdk/ts/node_modules ]; then
  gate "typescript-sdk-tests" sh -c 'cd sdk/ts && npm test'
  gate "typescript-sdk-build" sh -c 'cd sdk/ts && npm run build'
  gate "typescript-sdk-package" sh -c 'cd sdk/ts && npm pack --dry-run'
else
  echo "skipping the typescript gates: sdk/ts/node_modules is absent (run without --offline)"
fi

printf '\nALL GATES PASSED:%s\n' "$passed"
