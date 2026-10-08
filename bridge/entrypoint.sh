#!/bin/sh
# Starts frps only when the token, the admin password, the domain and every variable frps.toml references are sound,
# then records what frps loaded. The checks live here so they hold for a bare `docker compose up` as well as for `ctl`.
set -eu

# Every name this script defines is lowercase and nothing is exported, so frps receives every variable it was given
# unchanged (the `RT_*` ones are what its config can reference); the shell itself adds PWD, OLDPWD and SHLVL.
newline='
'

example_token=0000000000000000000000000000000000000000000000000000000000000000
example_admin_password=example-admin-password

# These mirror ctl/config.py (ADMIN_PASSWORD, DNS_LABEL, NUMERIC_LABEL, max_dns_name_length); a unit test pins them.
admin_password_pattern='^[A-Za-z0-9_-]{16,}$'
dns_label_pattern='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
numeric_label_pattern='^([0-9]+$|0[xX])'
max_dns_name_length=253

mounted_token=/rt/secrets/token
mounted_config=/rt/bridge/frps.toml
# A tmpfs, so the token copy never reaches the container's writable layer.
state_dir=/run/rt
# frps runs in a private copy of the two files: the bytes validated and hashed here are the bytes it loads, even if
# the host files change in between.
work_dir=$state_dir/work

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

# Sets environment_value to the value of the environment variable $1 (trailing newlines included), or to nothing when it
# is not in the environment. A shell variable of that name does not count, which is why this reads through `printenv`.
# The `x` keeps `$(...)` from dropping trailing newlines; the newline `printenv` adds goes with it. A statement, not a
# condition, so `set -e` stays in force.
environment_value=
read_environment() {
	environment_value=
	if raw=$(printenv "$1" && printf x); then
		environment_value=${raw%"$newline"x}
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

# Prints the variable of each `{{ .Envs.RT_NAME }}` reference in $1. It applies ctl.env's rules, so the two cannot
# drift (tests/go_template.corpus): every `{{` must begin a strict reference, and `Envs` may appear only inside one.
scan_template() {
	LC_ALL=C awk -v file="$mounted_config" '
	function fail(offset,   head) {
		head = substr(text, 1, offset - 1)
		printf "bridge: %s:%d: unsupported template syntax; only `{{ .Envs.RT_NAME }}` is supported\n", \
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
		pattern = "^\\{\\{(-[ \t\r\n])?[ \t\r\n]*\\$?\\.Envs\\.(RT_[A-Z0-9_]*)([ \t\r\n]+-|[ \t\r\n]*)\\}\\}"
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
		if [ "$mount_point" = "$state_dir" ]; then
			filesystem=$fs_type
		fi
		case $mount_point in
		"$state_dir"/*) fail "$mount_point is a mount inside $state_dir; clearing $state_dir would reach into it" ;;
		esac
	done < /proc/mounts
	if [ "$filesystem" != tmpfs ]; then
		fail "$state_dir is not a tmpfs; the token copy would land in the container's writable layer. Run the container through compose.yaml, or pass --tmpfs $state_dir:mode=0700"
	fi
	# Clear the contents, not the mount point itself.
	find "$state_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
	chmod 0700 "$state_dir"
	mkdir -p "$work_dir/secrets" "$work_dir/bridge"
}

check_token() {
	require_regular_file "$mounted_token" "run \`uv run -m ctl install\` before \`docker compose up\`; if \`./secrets\` is a directory Docker made, remove it first with \`sudo rm -rf ./secrets\`"
	copy_file "$mounted_token" "$work_dir/secrets/token"

	# `$(...)` drops trailing newlines; the two expansions trim the remaining surrounding whitespace.
	token=$(cat "$work_dir/secrets/token")
	token=${token#"${token%%[![:space:]]*}"}
	token=${token%"${token##*[![:space:]]}"}
	# A NUL byte is dropped by the shell, so compare byte counts to see one.
	size=$(wc -c < "$work_dir/secrets/token")
	size_without_nul=$(tr -d '\000' < "$work_dir/secrets/token" | wc -c)
	if [ "$size" -ne "$size_without_nul" ]; then
		token=
	fi
	case $token in
	*[!0-9a-f]*) token= ;;
	esac
	if [ "${#token}" -ne 64 ]; then
		fail "$mounted_token must hold 64 lowercase hexadecimal characters (surrounding whitespace is ignored); regenerate it with \`uv run -m ctl install\`"
	fi
	if [ "$token" = "$example_token" ]; then
		fail "$mounted_token is the example token from example.env; set your own RT_TOKEN and run \`uv run -m ctl install\`"
	fi
}

check_admin_password() {
	read_environment RT_ADMIN_PASSWORD
	if [ -z "$environment_value" ]; then
		fail "RT_ADMIN_PASSWORD is empty; set it in .env"
	fi
	find_unsafe_characters "$environment_value"
	if [ "$unsafe_found" -eq 1 ] || ! printf '%s\n' "$environment_value" | LC_ALL=C grep -Eq "$admin_password_pattern"; then
		fail "RT_ADMIN_PASSWORD must be at least 16 characters from A-Z, a-z, 0-9, \`_\` and \`-\`; choose another in .env"
	fi
	if [ "$environment_value" = "$example_admin_password" ]; then
		fail "RT_ADMIN_PASSWORD is the example password from example.env; choose your own in .env"
	fi
}

# The rule of ctl.config.is_dns_name: dot-separated labels, and a last label that is neither all digits nor `0x…`.
check_domain() {
	read_environment RT_DOMAIN
	if [ -z "$environment_value" ]; then
		fail "RT_DOMAIN is unset or empty; set it in .env"
	fi
	message="RT_DOMAIN must be a DNS name (not an IP address) of letters, digits and inner hyphens, such as tunnel.example.com"
	find_unsafe_characters "$environment_value"
	if [ "$unsafe_found" -eq 1 ] || [ "${#environment_value}" -gt "$max_dns_name_length" ]; then
		fail "$message"
	fi
	if ! printf '%s\n' "$environment_value" | LC_ALL=C grep -Eq "^($dns_label_pattern)(\\.($dns_label_pattern))*\$"; then
		fail "$message"
	fi
	if printf '%s\n' "${environment_value##*.}" | LC_ALL=C grep -Eq "$numeric_label_pattern"; then
		fail "$message"
	fi
}

# An unset variable renders as the text `<no value>` and frps starts healthy, so every reference is checked up front.
# The values are written into TOML basic strings, so each must be free of quotes, backslashes and control characters.
check_config() {
	require_regular_file "$mounted_config" "restore it with \`git restore bridge/frps.toml\`"
	copy_file "$mounted_config" "$work_dir/bridge/frps.toml"

	names=$(scan_template "$work_dir/bridge/frps.toml")
	while IFS= read -r name; do
		if [ -z "$name" ]; then
			continue
		fi
		read_environment "$name"
		if [ -z "$environment_value" ]; then
			fail "$name is unset or empty, but $mounted_config references it; set it in .env and pass it through compose.yaml"
		fi
		find_unsafe_characters "$environment_value"
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
sha256sum "$work_dir/secrets/token" > "$state_dir/token.sha256"
sha256sum "$work_dir/bridge/frps.toml" > "$state_dir/config.sha256"

cd "$work_dir"
exec "$@"
