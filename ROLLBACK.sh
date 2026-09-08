#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BASELINE="${1:-/tmp/Antigravity-gateway-baseline-copy}"
mkdir -p "$BASELINE"
git -C "$ROOT" restore --source=HEAD --staged --worktree .
rm -rf "$ROOT/internal/adminui"
rm -f "$ROOT/DIFF_FILE" "$ROOT/VERIFICATION.txt" "$ROOT/ROLLBACK.sh"
printf 'restored source tree from HEAD; runtime container was not changed\n'
