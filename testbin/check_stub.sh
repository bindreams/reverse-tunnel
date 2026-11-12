#!/bin/sh
# Stands for the installed binary's `run --check` in `src/ops_tests.rs`, reached through a link in the bin directory.
# Passes only if its last argument is `--check` and its environment is what `expected-env` there lists; fails, with
# a line on each stream, if `fail` exists there.
dir=${0%/*}
for last; do :; done
[ "$last" = --check ] || exit 1
# The shell adds some variables of its own.
[ "$(env | grep -v '^\(PWD\|OLDPWD\|SHLVL\|_\)=')" = "$(cat "$dir/expected-env")" ] || exit 1
if [ -e "$dir/fail" ]; then
    echo "stub stdout line"
    echo "stub stderr line" >&2
    exit 1
fi
