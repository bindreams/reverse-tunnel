#!/bin/sh
# Starts frps only when the token, the admin password, the domain and every variable frps.toml references are sound,
# then records what frps loaded. The checks live here so they hold for a bare `docker compose up` as well as for `ctl`.
set -eu

# Byte-wise matching: the patterns below are ASCII rules.
LC_ALL=C
export LC_ALL

EXAMPLE_TOKEN=0000000000000000000000000000000000000000000000000000000000000000
EXAMPLE_ADMIN_PASSWORD=example-admin-password

# These mirror ctl/config.py (ADMIN_PASSWORD, DNS_LABEL, NUMERIC_LABEL, MAX_DNS_NAME_LENGTH); a unit test pins them.
ADMIN_PASSWORD_PATTERN='^[A-Za-z0-9_-]{16,}$'
DNS_LABEL_PATTERN='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
NUMERIC_LABEL_PATTERN='^([0-9]+$|0[xX])'
MAX_DNS_NAME_LENGTH=253

MOUNTED_TOKEN=/rt/secrets/token
MOUNTED_CONFIG=/rt/bridge/frps.toml
# A tmpfs, so the token copy never reaches the container's writable layer.
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

# Copies $1 to $2, or exits: the container drops every capability but the one that reads the operator's 0600 files.
copy_file() {
	if ! cat "$1" > "$2"; then
		fail "cannot read $1; run the container through compose.yaml, which grants the capability that reading it needs"
	fi
}

# Sets unsafe_found to 1 when $1 holds a character that would break out of a TOML basic string: a double quote, a
# backslash or a control character (a newline included). A statement, not a condition, so `set -e` stays in force.
unsafe_found=0
find_unsafe_characters() {
	case $1 in
	*'"'* | *\\* | *[[:cntrl:]]*) unsafe_found=1 ;;
	*) unsafe_found=0 ;;
	esac
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
		pattern = "^\\{\\{(-[ \t\r\n])?[ \t\r\n]*\\$?\\.Envs\\.([A-Z][A-Z0-9_]*)([ \t\r\n]+-|[ \t\r\n]*)\\}\\}"
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
			sub(/[^A-Z0-9_]*\}\}$/, "", name)
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

check_state_directory() {
	filesystem=
	while read -r _ mount_point fs_type _; do
		# The last entry for a mount point is the one in effect.
		if [ "$mount_point" = "$STATE" ]; then
			filesystem=$fs_type
		fi
	done < /proc/mounts
	if [ "$filesystem" != tmpfs ]; then
		fail "$STATE is not a tmpfs; the token copy would land in the container's writable layer. Run the container through compose.yaml, or pass --tmpfs $STATE:mode=0700"
	fi
	# Clear the contents, not the mount point itself.
	find "$STATE" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
	chmod 0700 "$STATE"
	mkdir -p "$WORK/secrets" "$WORK/bridge"
}

check_token() {
	require_regular_file "$MOUNTED_TOKEN" "run \`uv run -m ctl install\` before \`docker compose up\`; if \`./secrets\` is a directory Docker made, remove it first with \`sudo rm -rf ./secrets\`"
	copy_file "$MOUNTED_TOKEN" "$WORK/secrets/token"

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
	find_unsafe_characters "$RT_ADMIN_PASSWORD"
	if [ "$unsafe_found" -eq 1 ] || ! printf '%s\n' "$RT_ADMIN_PASSWORD" | grep -Eq "$ADMIN_PASSWORD_PATTERN"; then
		fail "RT_ADMIN_PASSWORD must be at least 16 characters from A-Z, a-z, 0-9, \`_\` and \`-\`; choose another in .env"
	fi
	if [ "$RT_ADMIN_PASSWORD" = "$EXAMPLE_ADMIN_PASSWORD" ]; then
		fail "RT_ADMIN_PASSWORD is the example password from example.env; choose your own in .env"
	fi
}

# The rule of ctl.config.is_dns_name: dot-separated labels, and a last label that is neither all digits nor `0x…`.
check_domain() {
	if [ -z "${RT_DOMAIN:-}" ]; then
		fail "RT_DOMAIN is unset or empty; set it in .env"
	fi
	message="RT_DOMAIN must be a DNS name (not an IP address) of letters, digits and inner hyphens, such as tunnel.example.com"
	find_unsafe_characters "$RT_DOMAIN"
	if [ "$unsafe_found" -eq 1 ] || [ "${#RT_DOMAIN}" -gt "$MAX_DNS_NAME_LENGTH" ]; then
		fail "$message"
	fi
	if ! printf '%s\n' "$RT_DOMAIN" | grep -Eq "^($DNS_LABEL_PATTERN)(\\.($DNS_LABEL_PATTERN))*\$"; then
		fail "$message"
	fi
	if printf '%s\n' "${RT_DOMAIN##*.}" | grep -Eq "$NUMERIC_LABEL_PATTERN"; then
		fail "$message"
	fi
}

# An unset variable renders as the text `<no value>` and frps starts healthy, so every reference is checked up front.
# The values are written into TOML basic strings, so each must be free of quotes, backslashes and control characters.
check_config() {
	require_regular_file "$MOUNTED_CONFIG" "restore it with \`git restore bridge/frps.toml\`"
	copy_file "$MOUNTED_CONFIG" "$WORK/bridge/frps.toml"

	names=$(scan_template "$WORK/bridge/frps.toml")
	while IFS= read -r name; do
		if [ -z "$name" ]; then
			continue
		fi
		# `name` is a scanned `[A-Z][A-Z0-9_]*`, so the eval can reach nothing but that variable. Unlike `$(printenv)`,
		# it keeps trailing newlines.
		eval "value=\${$name-}"
		if [ -z "$value" ]; then
			fail "$name is unset or empty, but $MOUNTED_CONFIG references it; set it in .env and pass it through compose.yaml"
		fi
		find_unsafe_characters "$value"
		if [ "$unsafe_found" -eq 1 ]; then
			fail "$name contains a double quote, a backslash or a control character, which would break the TOML string it is written into"
		fi
	done <<-EOF
	$names
	EOF
}

if [ "$#" -eq 0 ]; then
	fail "no command given"
fi

umask 077
check_state_directory
check_token
check_admin_password
check_domain
check_config

# frps reads the token once at startup and has no reload, so a digest that no longer matches the host file means the
# running server holds an outdated token or config.
sha256sum "$WORK/secrets/token" > "$STATE/token.sha256"
sha256sum "$WORK/bridge/frps.toml" > "$STATE/config.sha256"

cd "$WORK"
exec "$@"
