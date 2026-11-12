#!/usr/bin/env bash
# Succeed only when the checked-out `Cargo.toml` declares version `$1`.
set -euo pipefail

version="${1:?version required}"

manifest="$(cargo metadata --no-deps --locked --format-version 1 | jq -r '.packages[] | select(.name == "reverse-tunnel") | .version')"
if [[ "$manifest" != "$version" ]]; then
    echo "::error::Cargo.toml declares '${manifest}' but the release is ${version}"
    exit 1
fi
