#!/usr/bin/env bash
# kalappai-cert — loop-engineering verification gate.
#
# One command that decides whether a change to this service may be committed,
# pushed, or deployed. Every stage is a claim about the service that something
# other than a human has to be able to check:
#
#   1. contract artifact  — the committed surface matches src/contract.ts
#   2. docs               — README documents exactly the contract, no more, no less
#   3. typecheck          — tsc, including the scripts that run these gates
#   4. lint               — biome (lint only; the formatter is deliberately off)
#   5. tests              — contract conformance + server + cognizance
#   6. live smoke         — boots the real entrypoint and drives it end to end
#   7. demo               — the demo seeds a spawned instance and every seeded
#                           certificate verifies (page, QR, VC-JWT vs JWKS)
#   8. hygiene            — no secrets, no committed database, no stray artifacts
#
# Usage:  bun run verify          (all stages)
#         bun run verify --full   (also drive the documented public demo entrypoint)
#         bun run verify --fast   (skip lint + smoke + demo; the tight inner loop)
#
# Exits non-zero on the first failing stage, so it can gate a commit hook, CI,
# or a loop iteration. Nothing here reaches the network.

set -uo pipefail

FAST=0
FULL=0
for a in "$@"; do
  [ "$a" = "--fast" ] && FAST=1
  [ "$a" = "--full" ] && FULL=1
done

BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; DIM='\033[2m'; NC='\033[0m'

cd "$(dirname "$0")/.."
LOG_DIR="$(mktemp -d)"
fail=0
ran=0

step() { echo ""; echo -e "${BOLD}$1${NC}"; }

run_stage() {
  local name="$1"; shift
  ran=$((ran + 1))
  if "$@" > "$LOG_DIR/$name.log" 2>&1; then
    echo -e "  ${GREEN}✓${NC} ${name}"
  else
    echo -e "  ${RED}✗${NC} ${name} — output below:"
    echo ""
    sed 's/^/    /' "$LOG_DIR/$name.log" | tail -40
    fail=1
    summary
    exit 1
  fi
}

summary() {
  echo ""
  if [ "$fail" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ Verification passed${NC} ${DIM}(${ran} stages)${NC}"
  else
    echo -e "${RED}${BOLD}✗ Verification failed${NC}"
  fi
}

if ! command -v bun >/dev/null 2>&1; then
  echo -e "${RED}✗ bun not found — this repo runs on bun${NC}"
  exit 1
fi

echo -e "${BOLD}kalappai-cert — verification gate${NC} ${DIM}$([ "$FAST" -eq 1 ] && echo '(fast: lint + smoke + demo skipped)')${NC}"

step "1/8  Contract artifact matches the declared surface"
run_stage "contract" bun run contract:check

step "2/8  README documents exactly the contract"
run_stage "docs" bun run docs:check

step "3/8  Typecheck"
run_stage "typecheck" bun run typecheck

if [ "$FAST" -eq 0 ]; then
  step "4/8  Lint"
  run_stage "lint" bun run lint
else
  echo ""
  echo -e "${YELLOW}–${NC} 4/8  Lint ${DIM}(skipped)${NC}"
fi

step "5/8  Tests (contract conformance + server + cognizance)"
run_stage "tests" bun test ./test/

if [ "$FAST" -eq 0 ]; then
  step "6/8  Live smoke (spawns the documented entrypoint, drives it end to end)"
  run_stage "smoke" bun run smoke
else
  echo ""
  echo -e "${YELLOW}–${NC} 6/8  Live smoke ${DIM}(skipped)${NC}"
fi

# The demo is a claim about the service too: a documented path that no longer
# runs is worse than an undocumented one. Check mode uses the seed script
# directly; --full exercises the documented public entrypoint (demo/run.sh).
if [ "$FAST" -eq 0 ]; then
  if [ "$FULL" -eq 1 ]; then
    step "7/8  Demo (the public demo path: demo/run.sh --check)"
    run_stage "demo" bash demo/run.sh --check
  else
    step "7/8  Demo (seeds a spawned instance; every seeded certificate verifies)"
    run_stage "demo" bun run demo:seed --check
  fi
else
  echo ""
  echo -e "${YELLOW}–${NC} 7/8  Demo ${DIM}(skipped)${NC}"
fi

step "8/8  Hygiene (no secrets, no committed database, no stray artifacts)"
hygiene_fail=0

# The issuer key and the certificate database must never be committed.
if git ls-files --error-unmatch data/issuer-key.json >/dev/null 2>&1; then
  echo -e "  ${RED}✗${NC} data/issuer-key.json is tracked — the issuer private key must not be in git"
  hygiene_fail=1
elif git ls-files | grep -qE '^data/.*\.(db|sqlite)$'; then
  echo -e "  ${RED}✗${NC} a database file is tracked — runtime state belongs outside git"
  hygiene_fail=1
elif ! git check-ignore -q data/certs.db 2>/dev/null; then
  echo -e "  ${RED}✗${NC} data/certs.db is not gitignored"
  hygiene_fail=1
else
  echo -e "  ${GREEN}✓${NC} issuer key and database are outside version control"
fi

# No long hex strings that look like a live secret in tracked source.
if git grep -nIE '(KALAPPAI_CERT_SECRET|SECRET|TOKEN|API_KEY)\s*[:=]\s*"[0-9a-fA-F]{16,}"' -- src scripts test >/dev/null 2>&1; then
  echo -e "  ${RED}✗${NC} a hardcoded secret-shaped literal appears in tracked source"
  git grep -nIE '(KALAPPAI_CERT_SECRET|SECRET|TOKEN|API_KEY)\s*[:=]\s*"[0-9a-fA-F]{16,}"' -- src scripts test | sed 's/^/      /'
  hygiene_fail=1
else
  echo -e "  ${GREEN}✓${NC} no hardcoded secret-shaped literals in tracked source"
fi

# The gate must not be able to pass by having been edited into a no-op.
if ! grep -q "bun run contract:check" scripts/verify.sh || ! grep -q "bun run docs:check" scripts/verify.sh \
   || ! grep -q "bun run demo:seed --check" scripts/verify.sh; then
  echo -e "  ${RED}✗${NC} this gate no longer runs the contract, docs and demo checks"
  hygiene_fail=1
fi
if [ ! -f contract/cert-service.v1.json ]; then
  echo -e "  ${RED}✗${NC} contract/cert-service.v1.json is missing"
  hygiene_fail=1
fi
if [ -n "$(git status --porcelain -- . ':!data' | grep -vE '^\?\? ' || true)" ]; then
  echo -e "  ${YELLOW}!${NC} tracked files are modified — the gate runs on the working tree, not on a commit"
fi

[ "$hygiene_fail" -eq 0 ] || { fail=1; summary; exit 1; }
echo -e "  ${GREEN}✓${NC} hygiene"

summary
exit 0
