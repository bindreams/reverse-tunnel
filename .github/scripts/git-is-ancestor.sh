#!/usr/bin/env bash
# Whether commit `$1` is an ancestor of `$2`: exit 0 if it is, 1 if it is not, 2 (with an error on stderr) when git
# fails, so that a failure is never read as "not an ancestor" or as "is".
set -euo pipefail

status=0
git merge-base --is-ancestor "${1:?commit required}" "${2:?ref required}" || status=$?

case "$status" in
    0 | 1) exit "$status" ;;
    *)
        echo "::error::git merge-base failed (exit ${status})" >&2
        exit 2
        ;;
esac
