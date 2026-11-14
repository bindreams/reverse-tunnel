import base64
import fcntl
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
compose.compose_up = lambda folder, build=False: None
compose.network_exists = lambda name: True
cli.resolve = lambda name: True
sys.exit(cli.main(sys.argv[1:]))
"""


@pytest.fixture
def bridge(tmp_path, monkeypatch):
    """A bridge folder (the cwd) holding `.env`; Docker and DNS are faked. Returns the list of `compose_up` calls."""
    (tmp_path / ".env").write_text(f"TUNNEL_DOMAIN={T}\n")
    monkeypatch.chdir(tmp_path)
    reloads = []
    monkeypatch.setattr(compose, "compose_up", lambda folder, build=False: reloads.append((folder, build)))
    monkeypatch.setattr(compose, "network_exists", lambda name: True)
    monkeypatch.setattr(cli, "resolve", lambda name: True)
    return reloads


@pytest.fixture
def inited(bridge):
    assert cli.main(["init"]) == 0
    bridge.clear()
    return bridge


def docker_down(folder, build=False):
    raise subprocess.CalledProcessError(1, "docker")


@pytest.fixture
def docker(tmp_path, monkeypatch):
    """A fake `docker`, alone on PATH: logs its arguments, prints $FAKE_STDOUT and $FAKE_STDERR, exits $FAKE_EXIT."""
    exe = tmp_path / "bin" / "docker"
    exe.parent.mkdir()
    exe.write_text('#!/bin/sh\necho "$@" >> "$0.log"\necho "$FAKE_STDOUT"\necho "$FAKE_STDERR" >&2\nexit "${FAKE_EXIT:-0}"\n')
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
    created = ["tls/frps.crt", "tls/frps.key", "tls/trust.pem", "state/hosts.yaml", "state/aliases.yaml"]
    created.append(str(GENERATED))
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


def test_ctl_rewrites_keep_long_entries_on_one_line(inited):
    host_line = "myhost: sha256:60e05bd1b195af2f94112fa7197a5c88289058840ce7c6df9693756bc6250f55  # office laptop\n"
    alias_line = f"{'a' * 63}.{'b' * 63}.yourdomain.tld: {'s' * 63}.{'h' * 63}.{T}\n"
    Path("state/hosts.yaml").write_text(host_line)
    Path("state/aliases.yaml").write_text(alias_line)
    assert cli.main(["add", "web", H]) == 0
    assert cli.main(["alias", "media.yourdomain.tld", f"svc.web.{T}"]) == 0
    assert Path("state/hosts.yaml").read_text().startswith(host_line)
    assert Path("state/aliases.yaml").read_text().startswith(alias_line)


@pytest.mark.parametrize("host", ["22", "null", "true", "1e3", "0x1f"])
def test_quoted_numeric_host_round_trips(inited, host):
    assert cli.main(["add", host, H]) == 0
    assert f"'{host}': " in Path("state/hosts.yaml").read_text()
    assert read_hosts(Path("state/hosts.yaml")) == {host: H}


def test_a_syntax_error_in_the_registry_stops_ctl_before_any_change(inited, capsys):
    broken = f"a: {H}\nb: [1, 2}}\n"
    Path("state/hosts.yaml").write_text(broken)
    generated = GENERATED.read_text()
    assert cli.main(["add", "web", H]) == 1
    assert "state/hosts.yaml: line 2" in capsys.readouterr().err
    assert Path("state/hosts.yaml").read_text() == broken
    assert GENERATED.read_text() == generated
    assert inited == []


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


@pytest.mark.parametrize("public", ["nodots", f"x.{T}", "a b.yourdomain.tld", "a`b.yourdomain.tld"])
def test_alias_rejects_bad_public_name(inited, public):
    assert cli.main(["alias", public, f"svc.web.{T}"]) == 1
    assert read_aliases(Path("state/aliases.yaml"), T) == {}
    assert inited == []


def test_alias_requires_backend_under_T(inited):
    assert cli.main(["alias", "media.yourdomain.tld", f"svc.web.{T}"]) == 0
    assert read_aliases(Path("state/aliases.yaml"), T) == {"media.yourdomain.tld": f"svc.web.{T}"}
    assert "Host(`media.yourdomain.tld`)" in GENERATED.read_text()
    assert cli.main(["alias", "other.yourdomain.tld", "svc.web.yourdomain.tld"]) == 1
    assert cli.main(["unalias", "media.yourdomain.tld"]) == 0
    assert read_aliases(Path("state/aliases.yaml"), T) == {}


def test_revoke_prints_restart_hint(inited, monkeypatch, capsys):
    cli.main(["add", "web", H])
    monkeypatch.setattr(compose, "compose_up", docker_down)
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
    monkeypatch.setattr(compose, "compose_up", docker_down)
    assert cli.main(["add", "web", H]) == 1
    err = capsys.readouterr().err
    assert "registry is updated" in err and "the bridge was not brought up" in err and "rerun any ctl command" in err
    assert "web" in read_hosts(Path("state/hosts.yaml"))
    assert cli.main(["list"]) == 1
    err = capsys.readouterr().err
    assert "the bridge was not brought up" in err and "registry is updated" not in err
    monkeypatch.setattr(compose, "compose_up", lambda folder, build=False: inited.append((folder, build)))
    assert cli.main(["list"]) == 0
    assert inited == [(Path.cwd(), False)]


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


def test_compose_up_never_recreates_a_running_frps(docker, tmp_path, monkeypatch):
    base = "compose -p reverse-tunnel -f compose.yaml -f compose.generated.yaml"
    plugin = "--no-deps reverse-tunnel-plugin"
    probe = "ps -q --status running reverse-tunnel-frps"
    log = Path(f"{docker}.log")

    def calls(*lines):
        return "".join(f"{base} {line}\n" for line in lines)

    # Not `init`: no probe and no build; a running frps is kept, a stopped or absent one is started as it is.
    # COMPOSE_FILE, COMPOSE_PROJECT_NAME and the like must not redirect it.
    assert not compose.compose_up(tmp_path)
    assert log.read_text() == calls(f"up -d {plugin}", "up -d --no-recreate reverse-tunnel-frps")

    # `init`, frps absent or stopped (nothing running to drop): both images are built and frps comes up as built.
    log.unlink()
    assert not compose.compose_up(tmp_path, build=True)
    assert log.read_text() == calls(probe, f"up -d --build {plugin}", "up -d --build reverse-tunnel-frps")

    # `init`, frps running: only the plugin is built; frps is not recreated, and the caller is told.
    log.unlink()
    monkeypatch.setenv("FAKE_STDOUT", "0123abcd")
    assert compose.compose_up(tmp_path, build=True)
    assert log.read_text() == calls(probe, f"up -d --build {plugin}", "up -d --no-recreate reverse-tunnel-frps")


def test_a_failed_frps_probe_shows_dockers_stderr_and_brings_nothing_up(docker, tmp_path, monkeypatch, capfd):
    monkeypatch.setenv("FAKE_EXIT", "1")
    monkeypatch.setenv("FAKE_STDERR", "Cannot connect to the Docker daemon")
    with pytest.raises(subprocess.CalledProcessError):
        compose.compose_up(tmp_path, build=True)
    assert "Cannot connect to the Docker daemon" in capfd.readouterr().err
    assert " up " not in Path(f"{docker}.log").read_text()


def test_init_starts_the_bridge_and_prints_the_join_code_last_under_a_label(bridge, monkeypatch, capsys):
    def up(folder, build=False):
        assert build, "init builds both images"
        print("docker's build output")

    monkeypatch.setattr(compose, "compose_up", up)
    assert cli.main(["init"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "docker's build output"
    assert lines[-1].startswith("rt1:")
    label = " ".join(lines[1:-1])
    assert "Join code" in label and "reverse-tunnel install" in label and "ctl join-code" in label


def test_init_says_how_to_apply_a_change_to_a_frps_it_left_running(bridge, monkeypatch, capsys):
    monkeypatch.setattr(compose, "compose_up", lambda folder, build=False: True)
    assert cli.main(["init"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[-1].startswith("rt1:"), "the join code stays last, for copying"
    note = [line for line in lines if "left running" in line]
    assert len(note) == 1 and "docker compose up -d --build reverse-tunnel-frps" in note[0]
    assert "tunnel" in note[0] and "restart" not in note[0]


def test_init_prints_no_blank_line_when_its_handler_has_no_text(bridge, monkeypatch, capsys):
    monkeypatch.setitem(cli.COMMANDS, "init", cli.COMMANDS["init"]._replace(handler=lambda *args: ""))
    assert cli.main(["init"]) == 0
    assert capsys.readouterr().out == ""


def test_init_says_nothing_of_frps_when_it_started_it(bridge, capsys):
    assert cli.main(["init"]) == 0
    assert "left running" not in capsys.readouterr().out


def test_a_command_other_than_init_brings_the_whole_bridge_up_without_a_build(inited):
    assert cli.main(["list"]) == 0
    assert inited == [(Path.cwd(), False)]


@pytest.mark.parametrize("name", list(cli.COMMANDS))
def test_every_command_and_argument_has_help(name, capsys):
    def squeeze(text):  # argparse wraps lines, at hyphens too
        return "".join(text.split())

    command = cli.COMMANDS[name]
    with pytest.raises(SystemExit):
        cli.main([name, "--help"])
    shown = squeeze(capsys.readouterr().out)
    assert command.help and squeeze(command.help) in shown
    for argument, text in command.arguments.items():
        assert text and squeeze(text) in shown, f"{name} {argument} has no help"


def test_bring_up_holds_the_state_lock(inited, monkeypatch):
    ran = []

    def up(folder, build=False):
        ran.append(folder)
        fd = os.open("state/lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):  # another ctl would wait here
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)

    monkeypatch.setattr(compose, "compose_up", up)
    assert cli.main(["list"]) == 0
    assert ran, "the bring-up did not run, so the lock was never checked"


def test_a_failed_first_bring_up_says_to_rerun_init_which_prints_the_join_code(bridge, monkeypatch, capsys):
    monkeypatch.setattr(compose, "compose_up", docker_down)
    assert cli.main(["init"]) == 1
    captured = capsys.readouterr()
    assert "rerun `uv run ctl init`" in captured.err and "join code" in captured.err
    assert "rt1:" not in captured.out


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
