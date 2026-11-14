#!/usr/bin/env bash
# Succeed only when `origin` provably has no tag `$1`.
#
# `git ls-remote --exit-code` returns 0 when the ref exists, 2 when it does not, anything else on transport/auth
# failure. Reading a failure as "absent" would let an outage green-light a release.
set -euo pipefail

tag="${1:?tag required}"

status=0
err="$(git ls-remote --exit-code --tags origin "refs/tags/${tag}" 2>&1 >/dev/null)" || status=$?

case "$status" in
    0)
        echo "::error::Tag ${tag} already exists on origin. GitHub would bind the release to that tag's existing commit instead of the intended one. Delete the tag if GitHub allows it; a tag an immutable release has used cannot be, so then bump the version in Cargo.toml on main and draft that version."
        exit 1
        ;;
    2)
        echo "no existing tag ${tag}"
        ;;
    *)
        echo "::error::git ls-remote failed (exit ${status}): ${err}; cannot confirm ${tag} is absent"
        exit 1
        ;;
esac
