import hashlib
import json
from pathlib import Path

import pytest
from bridge_support import GOOD_TOKEN, REPO_ROOT, Entrypoint, assert_refused

EXAMPLE_TOKEN = "0" * 64
EXAMPLE_PASSWORD = "example-admin-password"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# The token ============================================================================================================


def test_refuses_to_start_without_a_token_file(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(token=None, config=tracked_config)
    assert_refused(result, "/rt/secrets/token is missing")
    assert "ctl install" in result.stderr


def test_refuses_a_directory_at_the_token_path(entrypoint: Entrypoint, tracked_config: str, tmp_path: Path):
    directory = tmp_path / "made-by-docker"
    directory.mkdir()
    config = tmp_path / "frps.toml"
    config.write_text(tracked_config)
    result = entrypoint.run_with_mounts([(directory, "/rt/secrets/token"), (config, "/rt/bridge/frps.toml")])
    assert_refused(result, "/rt/secrets/token is a directory")
    assert "sudo rm -rf ./secrets" in result.stderr


def test_refuses_the_example_token(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(token=EXAMPLE_TOKEN + "\n", config=tracked_config)
    assert_refused(result, "/rt/secrets/token is the example token")


MALFORMED_TOKENS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\n \t\r\n", id="only-whitespace"),
    pytest.param(b"0123456789abcdef" * 4 + b"0", id="65-characters"),
    pytest.param(b"0123456789abcdef" * 3 + b"0123456789abcde", id="63-characters"),
    pytest.param(b"0123456789ABCDEF" * 4, id="uppercase"),
    pytest.param(b"0123456789abcdeg" * 4, id="not-hexadecimal"),
    pytest.param(b"0123456789abcdef" * 2 + b"\n" + b"0123456789abcdef" * 2, id="split-over-two-lines"),
    pytest.param(b"0123456789abcdef" * 2 + b" " + b"0123456789abcdef" * 2, id="inner-space"),
    pytest.param((b"0123456789abcdef" * 4) + b"\n" + (b"0123456789abcdef" * 4), id="valid-line-then-another"),
    pytest.param((b"0123456789abcdef" * 4) + b"\x00", id="trailing-nul"),
    pytest.param(b"\x000123456789abcdef" * 4, id="nul-inside"),
    pytest.param("0123456789abcdef".encode() * 4 + "é".encode(), id="non-ascii"),
]


@pytest.mark.parametrize("token", MALFORMED_TOKENS)
def test_refuses_a_token_that_is_not_64_hex(entrypoint: Entrypoint, tracked_config: str, token: bytes):
    result = entrypoint.run(token=token, config=tracked_config)
    assert_refused(result, "/rt/secrets/token must hold 64 lowercase hexadecimal characters")


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(GOOD_TOKEN, id="no-newline"),
        pytest.param(GOOD_TOKEN + "\n", id="newline"),
        pytest.param(GOOD_TOKEN + "\r\n", id="crlf"),
        pytest.param("  \t" + GOOD_TOKEN + " \n\n", id="surrounding-whitespace"),
    ],
)
def test_accepts_a_token_with_surrounding_whitespace(entrypoint: Entrypoint, tracked_config: str, token: str):
    result = entrypoint.run(token=token, config=tracked_config)
    assert result.returncode == 0, result.stderr
    assert "STARTED" in result.stdout


def test_reports_the_token_before_the_admin_password(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(token=EXAMPLE_TOKEN, config=tracked_config, environment={"RT_ADMIN_PASSWORD": ""})
    assert_refused(result, "/rt/secrets/token is the example token")


# The state directory ==================================================================================================


def test_refuses_to_start_when_run_rt_is_not_a_tmpfs(entrypoint: Entrypoint, tracked_config: str):
    """The private copy of the token must not reach the container's writable layer."""
    result = entrypoint.run(config=tracked_config, tmpfs=False, extra=("--volume", "/run/rt"))
    assert_refused(result, "/run/rt is not a tmpfs")


def test_refuses_to_start_when_run_rt_is_just_a_directory(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(config=tracked_config, tmpfs=False)
    assert_refused(result, "/run/rt is not a tmpfs")


def test_refuses_to_clear_a_state_directory_with_a_mount_inside_it(entrypoint: Entrypoint, tracked_config: str):
    """Clearing would otherwise reach through the nested mount into whatever it holds."""
    result = entrypoint.run(config=tracked_config, extra=("--tmpfs", "/run/rt/inner"))
    assert_refused(result, "/run/rt/inner is a mount inside /run/rt")


def test_run_rt_is_private_to_root(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(config=tracked_config, command=("stat", "-c", "%a %U", "/run/rt"))
    assert result.stdout.strip() == "700 root", result.stderr


def test_the_token_copy_is_on_the_tmpfs_and_the_root_filesystem_is_read_only(
    entrypoint: Entrypoint, tracked_config: str
):
    script = "grep -c ' /run/rt tmpfs ' /proc/mounts; touch /x 2>&1; cat /run/rt/work/secrets/token > /dev/null"
    result = entrypoint.run(config=tracked_config, command=("sh", "-c", script))
    assert result.stdout.splitlines()[0] == "1", result.stdout
    assert "Read-only file system" in result.stdout


def test_names_a_token_the_container_cannot_read(entrypoint: Entrypoint, tracked_config: str):
    """The container keeps only the capabilities it needs; reading the operator's 0600 file is one of them."""
    result = entrypoint.run(config=tracked_config, add_capabilities=False)
    assert_refused(result, "cannot read /rt/secrets/token")


# The admin password ===================================================================================================


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_refuses_a_missing_admin_password(entrypoint: Entrypoint, tracked_config: str, value: str | None):
    result = entrypoint.run(config=tracked_config, environment={"RT_ADMIN_PASSWORD": value})
    assert_refused(result, "RT_ADMIN_PASSWORD is empty")


def test_refuses_the_example_admin_password(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(config=tracked_config, environment={"RT_ADMIN_PASSWORD": EXAMPLE_PASSWORD})
    assert_refused(result, "RT_ADMIN_PASSWORD is the example password")


# Values shaped like ctl.config's ======================================================================================

VALUE_RULES = json.loads((REPO_ROOT / "tests" / "value_rules.corpus").read_text(encoding="utf-8"))


def passable(values: list[str]) -> list[str]:
    """An environment variable cannot hold a NUL byte, so those corpus entries only apply to `ctl.config`."""
    return [value for value in values if "\x00" not in value]


@pytest.mark.parametrize("value", VALUE_RULES["domain"]["accepted"])
def test_accepts_every_domain_ctl_accepts(entrypoint: Entrypoint, tracked_config: str, value: str):
    result = entrypoint.run(config=tracked_config, environment={"RT_DOMAIN": value})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("value", passable(VALUE_RULES["domain"]["rejected"]))
def test_refuses_every_domain_ctl_refuses(entrypoint: Entrypoint, tracked_config: str, value: str):
    result = entrypoint.run(config=tracked_config, environment={"RT_DOMAIN": value})
    assert_refused(result, "RT_DOMAIN must be a DNS name")


@pytest.mark.parametrize("value", VALUE_RULES["admin_password"]["accepted"])
def test_accepts_every_admin_password_ctl_accepts(entrypoint: Entrypoint, tracked_config: str, value: str):
    result = entrypoint.run(config=tracked_config, environment={"RT_ADMIN_PASSWORD": value})
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("value", passable(VALUE_RULES["admin_password"]["rejected"]))
def test_refuses_every_admin_password_ctl_refuses(entrypoint: Entrypoint, tracked_config: str, value: str):
    result = entrypoint.run(config=tracked_config, environment={"RT_ADMIN_PASSWORD": value})
    assert_refused(result, "RT_ADMIN_PASSWORD must be at least 16 characters")


# The config ===========================================================================================================


def test_refuses_a_missing_config_file(entrypoint: Entrypoint):
    result = entrypoint.run(config=None)
    assert_refused(result, "/rt/bridge/frps.toml is missing")


def test_refuses_a_directory_at_the_config_path(entrypoint: Entrypoint, tmp_path: Path):
    directory = tmp_path / "made-by-docker"
    directory.mkdir()
    token = tmp_path / "token"
    token.write_text(GOOD_TOKEN)
    result = entrypoint.run_with_mounts([(token, "/rt/secrets/token"), (directory, "/rt/bridge/frps.toml")])
    assert_refused(result, "/rt/bridge/frps.toml is a directory")


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_refuses_a_missing_rt_domain(entrypoint: Entrypoint, tracked_config: str, value: str | None):
    result = entrypoint.run(config=tracked_config, environment={"RT_DOMAIN": value})
    assert_refused(result, "RT_DOMAIN is unset or empty")


@pytest.mark.parametrize("reference", ["{{ .Envs.RT_NOTE }}", "{{.Envs.RT_NOTE}}", "{{- $.Envs.RT_NOTE -}}"])
def test_refuses_a_missing_variable_whatever_the_template_spacing(entrypoint: Entrypoint, reference: str):
    result = entrypoint.run(config=f'note = "{reference}"\n', environment={"RT_NOTE": None})
    assert_refused(result, "RT_NOTE is unset or empty")


UNSAFE_VALUES = [
    pytest.param('a"b', id="double-quote"),
    pytest.param("a\\b", id="backslash"),
    pytest.param("a\nb", id="newline"),
    pytest.param("\n", id="only-a-newline"),
    pytest.param("a\tb", id="tab"),
    pytest.param("a\x01b", id="control-character"),
    pytest.param("a\x7fb", id="delete"),
    pytest.param("a\rb", id="carriage-return"),
]


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_refuses_a_referenced_value_that_would_break_the_toml_string(entrypoint: Entrypoint, value: str):
    result = entrypoint.run(config='note = "{{ .Envs.RT_NOTE }}"\n', environment={"RT_NOTE": value})
    assert_refused(result, "RT_NOTE contains a double quote, a backslash or a control character")


# The script's own names and the operator's ============================================================================

# Shell variables, special parameters and names the script used to define; none is an environment variable.
SHELL_NAMES = ["STATE", "WORK", "PPID", "IFS", "OPTIND", "LC_ALL", "MOUNTED_TOKEN", "EXAMPLE_TOKEN", "PS1", "LINENO"]


@pytest.mark.parametrize("name", SHELL_NAMES)
def test_refuses_a_reference_to_a_shell_variable_that_is_not_in_the_environment(entrypoint: Entrypoint, name: str):
    result = entrypoint.run(config=f'note = "{{{{ .Envs.{name} }}}}"\n')
    assert_refused(result, f"{name} is unset or empty")


@pytest.mark.parametrize(
    "name", ["STATE", "WORK", "LC_ALL", "MOUNTED_TOKEN", "ADMIN_PASSWORD_PATTERN", "EXAMPLE_TOKEN"]
)
def test_an_operator_variable_survives_with_its_own_value(entrypoint: Entrypoint, name: str):
    config = f'note = "{{{{ .Envs.{name} }}}}"\n'
    result = entrypoint.run(config=config, environment={name: "operator-value"}, command=("printenv", name))
    assert result.returncode == 0, result.stderr
    assert result.stdout == "operator-value\n"


def test_frps_starts_with_only_the_environment_it_was_given(entrypoint: Entrypoint, tracked_config: str):
    plain = entrypoint.docker_run([], None, ("env", ), True, True, ("--entrypoint", "env"))
    started = entrypoint.run(config=tracked_config, command=("env", ))
    assert started.returncode == 0, started.stderr

    def names(output: str) -> set[str]:
        return {line.split("=")[0] for line in output.splitlines() if "=" in line}

    leaked = names(started.stdout) - names(plain.stdout)
    assert leaked <= {"PWD", "OLDPWD", "SHLVL"}, leaked  # the shell exports these itself


def test_a_trailing_newline_in_a_referenced_value_is_seen(entrypoint: Entrypoint):
    result = entrypoint.run(config='note = "{{ .Envs.RT_NOTE }}"\n', environment={"RT_NOTE": "value\n"})
    assert_refused(result, "RT_NOTE contains a double quote, a backslash or a control character")


def test_accepts_a_referenced_value_with_spaces_braces_and_non_ascii(entrypoint: Entrypoint):
    result = entrypoint.run(config='note = "{{ .Envs.RT_NOTE }}"\n', environment={"RT_NOTE": "a {b} \u00e9 'c' $d"})
    assert result.returncode == 0, result.stderr


def test_starts_with_the_tracked_config_and_valid_inputs(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(config=tracked_config)
    assert result.returncode == 0, result.stderr
    assert "STARTED" in result.stdout


# The recorded digests =================================================================================================


def recorded_digest(entrypoint: Entrypoint, name: str, *, token: str, config: str) -> str:
    result = entrypoint.run(token=token, config=config, command=("cat", f"/run/rt/{name}"))
    assert result.returncode == 0, result.stderr
    return result.stdout.split()[0]


def test_records_the_loaded_token_digest(entrypoint: Entrypoint, tracked_config: str):
    token = "  " + GOOD_TOKEN + "\n"
    digest = recorded_digest(entrypoint, "token.sha256", token=token, config=tracked_config)
    assert digest == hashlib.sha256(token.encode()).hexdigest()


def test_records_the_loaded_config_digest(entrypoint: Entrypoint, tracked_config: str):
    digest = recorded_digest(entrypoint, "config.sha256", token=GOOD_TOKEN, config=tracked_config)
    assert digest == hashlib.sha256(tracked_config.encode()).hexdigest()


def test_the_digests_describe_the_files_frps_will_read(entrypoint: Entrypoint, tracked_config: str):
    """`frps -c bridge/frps.toml` resolves `secrets/token` against the working directory the command starts in."""
    result = entrypoint.run(
        token=GOOD_TOKEN + "\n",
        config=tracked_config,
        command=(
            "sh", "-c", "sha256sum secrets/token bridge/frps.toml; cat /run/rt/token.sha256 /run/rt/config.sha256"
        ),
    )
    assert result.returncode == 0, result.stderr
    fields = [line.split()[0] for line in result.stdout.splitlines()]
    assert fields[0] == fields[2], "the token frps reads is not the token that was hashed"
    assert fields[1] == fields[3], "the config frps reads is not the config that was hashed"


def test_frps_starts_in_a_private_copy_not_in_the_mounts(entrypoint: Entrypoint, tracked_config: str):
    """A copy, so the bytes that were validated are the bytes frps loads even if the host file changes meanwhile."""
    script = """
        for file in secrets/token bridge/frps.toml; do
            [ -f "$file" ] && [ ! -L "$file" ] || exit 1
            [ "$(stat -c %d:%i "$file")" != "$(stat -c %d:%i "/rt/$file")" ] || exit 2
        done
    """
    result = entrypoint.run(config=tracked_config, command=("sh", "-c", script))
    assert result.returncode == 0, f"exit {result.returncode}: {result.stderr}"
