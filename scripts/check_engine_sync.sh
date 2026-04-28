#!/usr/bin/env bash
# Check that classifinder/app/engine/ and classifinder-engine/ are in sync.
# Exits 0 if identical, 1 if diverged.
# Used by pre-commit hook and CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MONOREPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENGINE_API="$MONOREPO_ROOT/classifinder/app/engine"
ENGINE_OSS="$MONOREPO_ROOT/classifinder-engine/classifinder_engine"

if [ ! -d "$ENGINE_OSS" ]; then
    echo "WARNING: classifinder-engine/classifinder_engine/ not found at $ENGINE_OSS — skipping sync check"
    exit 0
fi

FAILED=0

# Compare pattern files
if ! diff -rq --exclude='__pycache__' --exclude='__init__.py' \
    "$ENGINE_API/patterns" "$ENGINE_OSS/patterns" > /dev/null 2>&1; then
    echo "ENGINE SYNC FAILURE: pattern files differ"
    diff -rq --exclude='__pycache__' --exclude='__init__.py' \
        "$ENGINE_API/patterns" "$ENGINE_OSS/patterns" || true
    FAILED=1
fi

# Compare core engine files
for file in scanner.py entropy.py redactor.py decoders.py false_positives.py; do
    if [ -f "$ENGINE_API/$file" ] && [ -f "$ENGINE_OSS/$file" ]; then
        if ! diff -q "$ENGINE_API/$file" "$ENGINE_OSS/$file" > /dev/null 2>&1; then
            echo "ENGINE SYNC FAILURE: $file differs"
            FAILED=1
        fi
    fi
done

if [ "$FAILED" -eq 1 ]; then
    echo ""
    echo "The API engine (classifinder/app/engine/) and the open-source engine"
    echo "(classifinder-engine/) are out of sync. Copy your changes to both"
    echo "before committing."
    exit 1
fi

echo "Engine sync check passed"
