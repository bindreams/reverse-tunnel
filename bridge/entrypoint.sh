#!/bin/sh
# Starts frps only when the token, the admin password and every variable frps.toml references are sound, then records
# what frps loaded. The checks live here so they hold for a bare `docker compose up` as well as for `ctl`.
set -eu

EXAMPLE_TOKEN=0000000000000000000000000000000000000000000000000000000000000000
EXAMPLE_ADMIN_PASSWORD=example-admin-password

MOUNTED_TOKEN=/rt/secrets/token
MOUNTED_CONFIG=/rt/bridge/frps.toml
STATE=/run/rt
# frps runs in a private copy of the two files: the bytes validated and hashed here are the bytes it loads, even if
# the host files change in between.
WORK=$STATE/work

fail() {
	printf 'bridge: %s\n' "$*" >&2
	exit 1
}

# Succeeds when $1 is a regular file; otherwise exits naming $1 and the remedy in $2.
require_regular_file() {
	if [ -d "$1" ]; then
		fail "$1 is a directory (Docker creates one when a bind-mount source is missing); $2"
	elif [ ! -e "$1" ]; then
		fail "$1 is missing; $2"
	elif [ ! -f "$1" ]; then
		fail "$1 is not a regular file; $2"
	fi
}

# Prints the variable of each `{{ .Envs.NAME }}` reference in $1. It applies ctl.env's rules, so the two cannot
# drift (tests/go_template.corpus): every `{{` must begin a strict reference, and `Envs` may appear only inside one.
scan_template() {
	awk -v file="$MOUNTED_CONFIG" '
	function fail(offset,   head) {
		head = substr(text, 1, offset - 1)
		printf "bridge: %s:%d: unsupported template syntax; only `{{ .Envs.NAME }}` is supported\n", \
			file, gsub(/\n/, "\n", head) + 1 > "/dev/stderr"
		exit 1
	}
	function inside_reference(offset,   i) {
		for (i = 1; i <= references; i++)
			if (starts[i] <= offset && offset + 3 <= ends[i])
				return 1
		return 0
	}
	BEGIN {
		space = "[[:space:]]*"
		pattern = "^\\{\\{-?" space "\\$?\\.Envs\\.[A-Z][A-Z0-9_]*" space "-?\\}\\}"
	}
	{ text = text $0 "\n" }
	END {
		position = 1
		while ((found = index(substr(text, position), "{{")) > 0) {
			start = position + found - 1
			if (match(substr(text, start), pattern) != 1)
				fail(start)
			name = substr(text, start, RLENGTH)
			sub(/^.*\.Envs\./, "", name)
			sub(/[[:space:]]*-?\}\}$/, "", name)
			print name
			references++
			starts[references] = start
			ends[references] = start + RLENGTH - 1
			position = start + RLENGTH
		}
		position = 1
		while ((found = index(substr(text, position), "Envs")) > 0) {
			start = position + found - 1
			if (substr(text, start - 1, 1) !~ /[A-Za-z0-9_]/ && substr(text, start + 4, 1) !~ /[A-Za-z0-9_]/ \
				&& !inside_reference(start))
				fail(start)
			position = start + 1
		}
	}' "$1"
}

check_token() {
	require_regular_file "$MOUNTED_TOKEN" "run \`uv run -m ctl install\` before \`docker compose up\`; if \`./secrets\` is a directory Docker made, remove it first with \`sudo rm -rf ./secrets\`"
	cat "$MOUNTED_TOKEN" > "$WORK/secrets/token"

	# `$(...)` drops trailing newlines; the two expansions trim the remaining surrounding whitespace.
	token=$(cat "$WORK/secrets/token")
	token=${token#"${token%%[![:space:]]*}"}
	token=${token%"${token##*[![:space:]]}"}
	# A NUL byte is dropped by the shell, so compare byte counts to see one.
	size=$(wc -c < "$WORK/secrets/token")
	size_without_nul=$(tr -d '\000' < "$WORK/secrets/token" | wc -c)
	if [ "$size" -ne "$size_without_nul" ]; then
		token=
	fi
	case $token in
	*[!0-9a-f]*) token= ;;
	esac
	if [ "${#token}" -ne 64 ]; then
		fail "$MOUNTED_TOKEN must hold 64 lowercase hexadecimal characters (surrounding whitespace is ignored); regenerate it with \`uv run -m ctl install\`"
	fi
	if [ "$token" = "$EXAMPLE_TOKEN" ]; then
		fail "$MOUNTED_TOKEN is the example token from example.env; set your own RT_TOKEN and run \`uv run -m ctl install\`"
	fi
}

check_admin_password() {
	if [ -z "${RT_ADMIN_PASSWORD:-}" ]; then
		fail "RT_ADMIN_PASSWORD is empty; set it in .env"
	fi
	if [ "$RT_ADMIN_PASSWORD" = "$EXAMPLE_ADMIN_PASSWORD" ]; then
		fail "RT_ADMIN_PASSWORD is the example password from example.env; choose your own in .env"
	fi
}

# An unset variable renders as the text `<no value>` and frps starts healthy, so every reference is checked up front.
check_config() {
	require_regular_file "$MOUNTED_CONFIG" "restore it with \`git restore bridge/frps.toml\`"
	cat "$MOUNTED_CONFIG" > "$WORK/bridge/frps.toml"

	names=$(scan_template "$WORK/bridge/frps.toml")
	while IFS= read -r name; do
		if [ -z "$name" ]; then
			continue
		fi
		if ! value=$(printenv "$name") || [ -z "$value" ]; then
			fail "$name is unset or empty, but $MOUNTED_CONFIG references it; set it in .env and pass it through compose.yaml"
		fi
	done <<-EOF
	$names
	EOF
}

if [ "$#" -eq 0 ]; then
	fail "no command given"
fi

umask 077
rm -rf "$STATE"
mkdir -p "$WORK/secrets" "$WORK/bridge"

check_token
check_admin_password
check_config

# frps reads the token once at startup and has no reload, so a digest that no longer matches the host file means the
# running server holds an outdated token or config.
sha256sum "$WORK/secrets/token" > "$STATE/token.sha256"
sha256sum "$WORK/bridge/frps.toml" > "$STATE/config.sha256"

cd "$WORK"
exec "$@"
