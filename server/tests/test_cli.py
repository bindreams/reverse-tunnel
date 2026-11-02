import base64
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dotenv import dotenv_values

from ctl import certs, cli, compose
from ctl.registry import RegistryError, locked, read_aliases, read_hosts, write_hosts

T = "t.test"
H = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
GENERATED = Path("compose.generated.yaml")

# The commands in a child process, with Docker and DNS faked as the fixture fakes them.
CHILD = """
import sys
from ctl import cli, compose
compose.compose_up_plugin = lambda folder: None
compose.network_exists = lambda name: True
cli.resolve = lambda name: True
sys.exit(cli.main(sys.argv[1:]))
"""


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    """A bridge folder (the cwd) holding `.env`; Docker and DNS are faked. Returns the list of plugin reloads."""
    (tmp_path / ".env").write_text(f"TUNNEL_DOMAIN={T}\n")
    monkeypatch.chdir(tmp_path)
    reloads = []
    monkeypatch.setattr(compose, "compose_up_plugin", reloads.append)
    monkeypatch.setattr(compose, "network_exists", lambda name: True)
    monkeypatch.setattr(cli, "resolve", lambda name: True)
    return reloads


@pytest.fixture
def inited(bridge):
    assert cli.main(["init"]) == 0
    bridge.clear()
    return bridge


def docker_down(folder):
    raise subprocess.CalledProcessError(1, "docker")


@pytest.fixture
def docker(tmp_path, monkeypatch):
    """A fake `docker`, alone on PATH: logs its arguments, prints $FAKE_STDERR, exits with $FAKE_EXIT."""
    exe = tmp_path / "bin" / "docker"
    exe.parent.mkdir()
    exe.write_text('#!/bin/sh\necho "$@" >> "$0.log"\necho "$FAKE_STDERR" >&2\nexit "${FAKE_EXIT:-0}"\n')
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(exe.parent))
    return exe


def start(*argv):
    return subprocess.Popen([sys.executable, "-c", CHILD, *argv], stdout=subprocess.PIPE, text=True)


def wait_blocked(proc, lock):
    """Return once `proc` is queued on `lock`, as the kernel reports it."""
    inode = str(lock.stat().st_ino)
    while True:
        for line in Path("/proc/locks").read_text().splitlines():
            fields = line.split()
            if fields[1] == "->" and fields[5] == str(proc.pid) and fields[6].split(":")[-1] == inode:
                return
        assert proc.poll() is None, "exited without waiting for the lock"
        time.sleep(0.01)  # a poll interval; the condition is the lock queue


def test_init_idempotent(bridge, capsys):
    assert cli.main(["init"]) == 0
    code = capsys.readouterr().out
    files = {p: p.read_bytes() for p in Path().rglob("*") if p.is_file()}
    created = ["tls/frps.crt", "tls/frps.key", "tls/trust.pem", "state/hosts.yaml", "state/aliases.yaml", str(GENERATED)]
    for name in created:
        assert Path(name) in files
    assert Path("tls/frps.key").stat().st_mode & 0o777 == 0o600
    assert cli.main(["init"]) == 0
    assert capsys.readouterr().out == code
    assert files == {p: p.read_bytes() for p in Path().rglob("*") if p.is_file()}


@pytest.mark.parametrize(
    "env, network, unresolvable, message",
    [
        ("", True, None, "TUNNEL_DOMAIN is not set"),
        ("TUNNEL_DOMAIN=bad_domain\n", True, None, "TUNNEL_DOMAIN 'bad_domain'"),
        (f"TUNNEL_DOMAIN={T}\nCOMPOSE_FILE=other.yaml\n", True, None, "COMPOSE_FILE"),
        (f"TUNNEL_DOMAIN={T}\n", False, None, "network 'gateway'"),
        (f"TUNNEL_DOMAIN={T}\n", True, T, f"cannot resolve {T}"),
        (f"TUNNEL_DOMAIN={T}\n", True, f"rt-dns-check.rt-dns-check.{T}", "cannot resolve rt-dns-check"),
    ],
)
def test_init_checks(bridge, monkeypatch, capsys, env, network, unresolvable, message):
    Path(".env").write_text(env)
    monkeypatch.setattr(compose, "network_exists", lambda name: network)
    monkeypatch.setattr(cli, "resolve", lambda name: name != unresolvable)
    assert cli.main(["init"]) == 1
    assert message in capsys.readouterr().err
    assert not Path("tls").exists()


def test_add_then_revoke(inited):
    assert cli.main(["add", "web", H]) == 0
    assert read_hosts(Path("state/hosts.yaml")) == {"web": H}
    assert f"*.web.{T}" in GENERATED.read_text()
    assert cli.main(["add", "web", H2]) == 1  # a typo'd name must not replace another host's token
    assert read_hosts(Path("state/hosts.yaml")) == {"web": H}
    assert cli.main(["revoke", "web"]) == 0
    assert read_hosts(Path("state/hosts.yaml")) == {}
    assert f"*.web.{T}" not in GENERATED.read_text()
    assert cli.main(["revoke", "web"]) == 1
    assert len(inited) == 2


def test_comments_survive_add_and_revoke(inited):
    Path("state/hosts.yaml").write_text(f"a: {H}  # one\nc: {H}  # two\ne: {H}  # three\n")
    assert cli.main(["add", "d", H2]) == 0
    assert cli.main(["revoke", "c"]) == 0
    assert Path("state/hosts.yaml").read_text() == f"a: {H}  # one\nd: {H2}\ne: {H}  # three\n"


@pytest.mark.parametrize("host", ["22", "null"])
def test_quoted_numeric_host_round_trips(inited, host):
    assert cli.main(["add", host, H]) == 0
    assert read_hosts(Path("state/hosts.yaml")) == {host: H}


@pytest.mark.parametrize("host, digest", [("Bad_Name", H), ("web", "sha256:abc")])
def test_add_rejects_bad_name_and_bad_hash(inited, host, digest):
    assert cli.main(["add", host, digest]) == 1
    assert read_hosts(Path("state/hosts.yaml")) == {}
    assert inited == []


def test_concurrent_add(inited):
    state = Path("state")
    with locked(state):
        proc = start("add", "b", H2)
        wait_blocked(proc, state / "lock")
        write_hosts(state / "hosts.yaml", {"a": H})  # an add that finished first
    assert proc.wait() == 0
    assert set(read_hosts(state / "hosts.yaml")) == {"a", "b"}
    assert f"*.a.{T}" in GENERATED.read_text() and f"*.b.{T}" in GENERATED.read_text()


@pytest.mark.parametrize("public", ["nodots", f"x.{T}", "a b.binarydreams.me", "a`b.binarydreams.me"])
def test_alias_rejects_bad_public_name(inited, public):
    assert cli.main(["alias", public, f"svc.web.{T}"]) == 1
    assert read_aliases(Path("state/aliases.yaml"), T) == {}
    assert inited == []


def test_alias_requires_backend_under_T(inited):
    assert cli.main(["alias", "media.binarydreams.me", f"svc.web.{T}"]) == 0
    assert read_aliases(Path("state/aliases.yaml"), T) == {"media.binarydreams.me": f"svc.web.{T}"}
    assert "Host(`media.binarydreams.me`)" in GENERATED.read_text()
    assert cli.main(["alias", "other.binarydreams.me", "svc.web.binarydreams.me"]) == 1
    assert cli.main(["unalias", "media.binarydreams.me"]) == 0
    assert read_aliases(Path("state/aliases.yaml"), T) == {}


def test_revoke_prints_restart_hint(inited, monkeypatch, capsys):
    cli.main(["add", "web", H])
    monkeypatch.setattr(compose, "compose_up_plugin", docker_down)
    capsys.readouterr()
    assert cli.main(["revoke", "web"]) == 1  # the hint must not depend on the reload
    assert "docker compose restart reverse-tunnel-frps" in capsys.readouterr().out


def test_join_code_uses_trust_bundle(inited, capsys):
    trust = Path("tls/trust.pem")
    trust.write_text(trust.read_text() + certs.make_cert(T)[0])  # a rotation appends the new certificate
    capsys.readouterr()
    assert cli.main(["join-code"]) == 0
    payload = capsys.readouterr().out.strip().removeprefix("rt1:")
    joined = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert joined == {"domain": T, "token": dotenv_values(".env")["FRPS_TOKEN"], "cert": trust.read_text()}


def test_cert_never_expires():
    cert_pem, key_pem = certs.make_cert(T)
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    assert cert.not_valid_after_utc.isoformat() == "9999-12-31T23:59:59+00:00"
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == [T]
    key = load_pem_private_key(key_pem.encode(), None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


def test_init_concurrent(bridge):
    state = Path("state")
    state.mkdir()
    with locked(state):
        procs = [start("init"), start("init")]
        for proc in procs:
            wait_blocked(proc, state / "lock")
    codes = [proc.communicate()[0] for proc in procs]
    assert [proc.returncode for proc in procs] == [0, 0]
    assert codes[0] == codes[1]
    assert Path(".env").read_text().count("FRPS_TOKEN=") == 1
    cert = x509.load_pem_x509_certificate(Path("tls/frps.crt").read_bytes())
    key = load_pem_private_key(Path("tls/frps.key").read_bytes(), None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


def test_init_domain_change_fails(inited, capsys):
    key = Path("tls/frps.key").read_bytes()
    Path(".env").write_text(Path(".env").read_text().replace(T, "other.test"))
    capsys.readouterr()
    assert cli.main(["init"]) == 1
    assert "rotation" in capsys.readouterr().err
    assert Path("tls/frps.key").read_bytes() == key


def test_docker_failure_after_write_is_reported(inited, monkeypatch, capsys):
    monkeypatch.setattr(compose, "compose_up_plugin", docker_down)
    assert cli.main(["add", "web", H]) == 1
    err = capsys.readouterr().err
    assert "registry is updated" in err and "plugin was not reloaded" in err and "rerun any ctl command" in err
    assert "web" in read_hosts(Path("state/hosts.yaml"))
    assert cli.main(["list"]) == 1
    err = capsys.readouterr().err
    assert "plugin was not reloaded" in err and "registry is updated" not in err
    monkeypatch.setattr(compose, "compose_up_plugin", inited.append)
    assert cli.main(["list"]) == 0
    assert inited == [Path.cwd()]


def test_list_regenerates(inited, capsys):
    hand_edit = f"# mine\r\nweb: {H}\r\n".encode()
    Path("state/hosts.yaml").write_bytes(hand_edit)
    assert cli.main(["list"]) == 0
    assert f"*.web.{T}" in GENERATED.read_text()
    assert "web" in capsys.readouterr().out
    assert Path("state/hosts.yaml").read_bytes() == hand_edit


def test_init_edits_env_in_place(bridge):
    original = f"# mine\nTUNNEL_DOMAIN={T}\nOTHER=1 # no newline at the end"
    Path(".env").write_text(original)
    assert cli.main(["init"]) == 0
    env = dotenv_values(".env")
    assert Path(".env").read_text().startswith(original + "\n")
    assert re.fullmatch("[0-9a-f]{64}", env.pop("FRPS_TOKEN"))
    assert env == {"TUNNEL_DOMAIN": T, "OTHER": "1", "COMPOSE_FILE": "compose.yaml:compose.generated.yaml"}
    assert Path(".env").stat().st_mode & 0o777 == 0o600  # it holds the frps token


def _swap_pair():
    cert, key = certs.make_cert(T)
    Path("tls/frps.crt").write_text(cert)
    Path("tls/frps.key").write_text(key)


BREAKS = {
    "key missing": lambda: Path("tls/frps.key").unlink(),
    "key not the certificate's": lambda: Path("tls/frps.key").write_text(certs.make_cert(T)[1]),
    "certificate missing": lambda: Path("tls/frps.crt").unlink(),
    "certificate not in trust.pem": _swap_pair,
}


@pytest.mark.parametrize("break_it", BREAKS.values(), ids=BREAKS)
def test_init_never_replaces_trusted_certificate(inited, capsys, break_it):
    break_it()
    broken = {path: path.read_bytes() for path in Path("tls").iterdir()}
    capsys.readouterr()
    assert cli.main(["init"]) == 1
    assert "rotation" in capsys.readouterr().err
    assert broken == {path: path.read_bytes() for path in Path("tls").iterdir()}


def test_init_recovers_before_any_host_trusts(inited):
    Path("tls/frps.crt").unlink()  # as after init was killed between the key and the certificate
    Path("tls/trust.pem").unlink()
    assert cli.main(["init"]) == 0
    cert = x509.load_pem_x509_certificate(Path("tls/frps.crt").read_bytes())
    assert load_pem_private_key(Path("tls/frps.key").read_bytes(), None).public_key() == cert.public_key()
    assert Path("tls/trust.pem").read_bytes() == Path("tls/frps.crt").read_bytes()


@pytest.mark.parametrize("name", ["frps.crt", "frps.key", "trust.pem"])
def test_init_reports_unusable_certificate_files(inited, capsys, name):
    Path("tls", name).write_text("not a pem")
    capsys.readouterr()
    assert cli.main(["init"]) == 1
    assert "tls" in capsys.readouterr().err


def test_init_state_dir_is_readable_by_the_plugin(bridge):
    old = os.umask(0o077)
    try:
        assert cli.main(["init"]) == 0
    finally:
        os.umask(old)
    assert Path("state").stat().st_mode & 0o777 == 0o755


def test_init_in_wrong_folder_leaves_nothing(bridge, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    os.chdir(elsewhere)
    assert cli.main(["init"]) == 1
    assert list(elsewhere.iterdir()) == []


def test_network_exists_reports_docker_failure(docker, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_EXIT", "1")
    monkeypatch.setenv("FAKE_STDERR", "Error response from daemon: network gateway not found")
    assert compose.network_exists("gateway") is False
    monkeypatch.setenv("FAKE_STDERR", "permission denied while trying to connect to the docker API")
    with pytest.raises(OSError, match="permission denied"):
        compose.network_exists("gateway")
    monkeypatch.setenv("FAKE_STDERR", "")
    monkeypatch.setenv("FAKE_EXIT", "3")
    with pytest.raises(OSError, match="docker exited with 3"):
        compose.network_exists("gateway")
    monkeypatch.setenv("PATH", str(tmp_path / "nowhere"))
    with pytest.raises(OSError, match="docker is not installed"):
        compose.network_exists("gateway")


def test_plugin_reload_uses_only_the_bridge_compose_files(docker, tmp_path):
    compose.compose_up_plugin(tmp_path)  # COMPOSE_FILE, COMPOSE_PROJECT_NAME and the like must not redirect it
    assert Path(f"{docker}.log").read_text() == (
        "compose -p reverse-tunnel -f compose.yaml -f compose.generated.yaml up -d --no-deps reverse-tunnel-plugin\n"
    )


def test_failed_registry_write_prints_nothing(inited, monkeypatch, capsys):
    cli.main(["add", "web", H])

    def refuse(path, hosts):
        raise RegistryError(1, "refused")

    monkeypatch.setattr(cli, "write_hosts", refuse)
    capsys.readouterr()
    assert cli.main(["revoke", "web"]) == 1  # the hint would claim a revocation that did not happen
    out, err = capsys.readouterr()
    assert out == "" and "state/hosts.yaml" in err


def test_cert_is_valid_from_yesterday():
    cert = x509.load_pem_x509_certificate(certs.make_cert(T)[0].encode())
    assert cert.not_valid_before_utc < datetime.now(UTC) - timedelta(hours=23)
