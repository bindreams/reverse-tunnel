#!/usr/bin/env bash
# Splits `server/` out of the current checkout, with the history that touched it, and pushes the result to the mirror
# repository `$1`, never forced.
#
#   mirror.sh REMOTE        push the split to REMOTE's `main`
#   mirror.sh REMOTE TAG    push a new annotated tag TAG on the split of the checked-out commit
#
# Needs a full-history checkout.
set -euo pipefail

remote="${1:?remote required}"
tag="${2-}"

# The split is deterministic: the same history always gives the same commits.
split="$(git subtree split --prefix=server)"

# Whether the mirror's `main` already holds the split commit.
mirror_main_has_split() {
    local status=0
    git fetch --quiet "$remote" main || exit 1
    bash "$(dirname "$0")/git-is-ancestor.sh" "$split" FETCH_HEAD || status=$?
    case "$status" in
        0) return 0 ;;
        1) return 1 ;;
        *) exit 1 ;;
    esac
}

push_main() {
    local main_sha
    main_sha="$(git ls-remote "$remote" refs/heads/main)"

    # A later run may have pushed already; an older one then has nothing to add, and a push would be refused.
    if [[ -n "$main_sha" ]] && mirror_main_has_split; then
        echo "the mirror's main already holds ${split}"
        return
    fi

    if git push "$remote" "${split}:refs/heads/main"; then
        return
    fi

    # Refused: another run pushed in between. That is fine if its push holds this commit.
    if mirror_main_has_split; then
        echo "the mirror's main holds ${split} after another run's push"
        return
    fi
    echo "::error::the mirror's main is not an ancestor of ${split}; refusing to force" >&2
    exit 1
}

push_tag() {
    # `ls-remote` lists an annotated tag twice, the tag object and, as `^{}`, the commit it points to.
    local peeled
    peeled="$(git ls-remote "$remote" "refs/tags/${tag}" "refs/tags/${tag}^{}" | awk '{ sha = $1 } END { print sha }')"
    if [[ -n "$peeled" ]]; then
        if [[ "$peeled" != "$split" ]]; then
            echo "::error::the mirror's ${tag} points at ${peeled}, not at ${split}; refusing to move it" >&2
            exit 1
        fi
        echo "the mirror already has ${tag} on ${split}"
        return
    fi

    # Not named `$tag`: this repository has its own tag of that name, on another commit.
    git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
        tag -a -m "$tag" "mirror/${tag}" "$split"
    git push "$remote" "refs/tags/mirror/${tag}:refs/tags/${tag}"
}

if [[ -n "$tag" ]]; then
    push_tag
else
    push_main
fi
