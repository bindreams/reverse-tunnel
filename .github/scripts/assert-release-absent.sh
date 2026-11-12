#!/usr/bin/env bash
# Succeed only when the repository provably has no release (draft or published) for tag `$1`. Needs GH_TOKEN and
# GH_REPO.
#
# `gh release view` exits non-zero for a missing release and for every transient failure. Reading the failure as
# "absent" would let an outage or a rate limit through, and GitHub does not enforce tag_name uniqueness across drafts,
# so the run would create a second draft for the same tag.
set -euo pipefail

tag="${1:?tag required}"

status=0
output="$(gh release view "$tag" --json tagName 2>&1)" || status=$?

if [[ "$status" -eq 0 ]]; then
    echo "::error::Release ${tag} already exists (draft or published). Delete it or pick a new version."
    exit 1
fi
if ! grep -qi 'release not found' <<<"$output"; then
    echo "::error::Cannot confirm whether ${tag} exists: ${output}"
    exit 1
fi
echo "no existing release ${tag}"
