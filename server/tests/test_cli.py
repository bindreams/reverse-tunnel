import base64
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dotenv import dotenv_values

from ctl import certs, cli, compose
from ctl.registry import locked, read_aliases, read_hosts, write_hosts

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
    for name in ["tls/frps.crt", "tls/frps.key", "tls/trust.pem", "state/hosts", "state/aliases", str(GENERATED)]:
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
    assert read_hosts(Path("state/hosts")) == {"web": H}
    assert f"*.web.{T}" in GENERATED.read_text()
    assert cli.main(["revoke", "web"]) == 0
    assert read_hosts(Path("state/hosts")) == {}
    assert f"*.web.{T}" not in GENERATED.read_text()
    assert cli.main(["revoke", "web"]) == 1
    assert len(inited) == 2


@pytest.mark.parametrize("host, digest", [("Bad_Name", H), ("web", "sha256:abc")])
def test_add_rejects_bad_name_and_bad_hash(inited, host, digest):
    assert cli.main(["add", host, digest]) == 1
    assert read_hosts(Path("state/hosts")) == {}
    assert inited == []


def test_concurrent_add(inited):
    state = Path("state")
    with locked(state):
        proc = start("add", "b", H2)
        wait_blocked(proc, state / "lock")
        write_hosts(state / "hosts", {"a": H})  # an add that finished first
    assert proc.wait() == 0
    assert set(read_hosts(state / "hosts")) == {"a", "b"}
    assert f"*.a.{T}" in GENERATED.read_text() and f"*.b.{T}" in GENERATED.read_text()


@pytest.mark.parametrize("public", ["nodots", f"x.{T}", "a b.binarydreams.me", "a`b.binarydreams.me"])
def test_alias_rejects_bad_public_name(inited, public):
    assert cli.main(["alias", public, f"svc.web.{T}"]) == 1
    assert read_aliases(Path("state/aliases"), T) == {}
    assert inited == []


def test_alias_requires_backend_under_T(inited):
    assert cli.main(["alias", "media.binarydreams.me", f"svc.web.{T}"]) == 0
    assert read_aliases(Path("state/aliases"), T) == {"media.binarydreams.me": f"svc.web.{T}"}
    assert "Host(`media.binarydreams.me`)" in GENERATED.read_text()
    assert cli.main(["alias", "other.binarydreams.me", "svc.web.binarydreams.me"]) == 1
    assert cli.main(["unalias", "media.binarydreams.me"]) == 0
    assert read_aliases(Path("state/aliases"), T) == {}


def test_revoke_prints_restart_hint(inited, capsys):
    cli.main(["add", "web", H])
    capsys.readouterr()
    assert cli.main(["revoke", "web"]) == 0
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
    def fail(folder):
        raise subprocess.CalledProcessError(1, "docker")

    monkeypatch.setattr(compose, "compose_up_plugin", fail)
    assert cli.main(["add", "web", H]) == 1
    err = capsys.readouterr().err
    assert "plugin was not reloaded" in err and "rerun any ctl command" in err
    assert "web" in read_hosts(Path("state/hosts"))
    monkeypatch.setattr(compose, "compose_up_plugin", inited.append)
    assert cli.main(["list"]) == 0
    assert inited == [Path.cwd()]


def test_list_regenerates(inited, capsys):
    hand_edit = f"# mine\r\nweb {H}\r\n".encode()
    Path("state/hosts").write_bytes(hand_edit)
    assert cli.main(["list"]) == 0
    assert f"*.web.{T}" in GENERATED.read_text()
    assert "web" in capsys.readouterr().out
    assert Path("state/hosts").read_bytes() == hand_edit
