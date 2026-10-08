import hashlib
from pathlib import Path

import pytest
from bridge_support import GOOD_TOKEN, Entrypoint, assert_refused

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


# The admin password ===================================================================================================


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_refuses_a_missing_admin_password(entrypoint: Entrypoint, tracked_config: str, value: str | None):
    result = entrypoint.run(config=tracked_config, environment={"RT_ADMIN_PASSWORD": value})
    assert_refused(result, "RT_ADMIN_PASSWORD is empty")


def test_refuses_the_example_admin_password(entrypoint: Entrypoint, tracked_config: str):
    result = entrypoint.run(config=tracked_config, environment={"RT_ADMIN_PASSWORD": EXAMPLE_PASSWORD})
    assert_refused(result, "RT_ADMIN_PASSWORD is the example password")


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


def test_refuses_a_missing_variable_written_without_template_spaces(entrypoint: Entrypoint, tracked_config: str):
    config = tracked_config.replace("{{ .Envs.RT_DOMAIN }}", "{{.Envs.RT_DOMAIN}}")
    assert config != tracked_config
    result = entrypoint.run(config=config, environment={"RT_DOMAIN": None})
    assert_refused(result, "RT_DOMAIN is unset or empty")


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
