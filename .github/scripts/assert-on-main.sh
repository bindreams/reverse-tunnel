#!/usr/bin/env bash
# Succeed only when commit `$1` is an ancestor of `origin/main`. Needs a checkout with enough history.
set -euo pipefail

sha="${1:?commit required}"

git fetch --quiet origin main

status=0
bash "$(dirname "$0")/git-is-ancestor.sh" "$sha" origin/main || status=$?

case "$status" in
    0) echo "$sha is an ancestor of origin/main" ;;
    1)
        echo "::error::$sha is not an ancestor of origin/main. Only merged commits."
        exit 1
        ;;
    *) exit 1 ;;
esac
