#!/usr/bin/env bash
# Normalize the dispatch input `$1` and write `version` (`0.1.0`) and `tag` (`v0.1.0`) to $GITHUB_OUTPUT.
set -euo pipefail

version="$(bash "$(dirname "$0")/normalize-version.sh" "${1-}")"
{
    echo "version=${version}"
    echo "tag=v${version}"
} >> "$GITHUB_OUTPUT"
