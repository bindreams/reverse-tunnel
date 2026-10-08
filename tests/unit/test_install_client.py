import dataclasses
import hashlib

import pytest
from binaries_support import VERSIONS, Upstream

from ctl import binaries
from ctl.config import Config, Role
from ctl.download import DIGESTS, Fetcher, Installed, TrustLevel, describe_install, read_digests
from ctl.errors import BinariesError, InstallError
from ctl.install import Services, install, uninstall
from deployment_support import tree, write_env

PLATFORM = "linux-x86_64"
CLIENT_ENV = "ROLE=client\nRT_DOMAIN=tunnel.example.com\nRT_SCHEME=wss\nRT_PUBLIC_PORT=443\n"


@pytest.fixture
def services(published, generated_lock_path) -> Services:
    return Services(
        lock_path=generated_lock_path,
        platform=PLATFORM,
        fetcher=lambda: Fetcher(transport=published.transport),
        run=lambda args, *, cwd: pytest.fail("the client runs no commands", pytrace=False),
    )


@pytest.fixture
def served(published):
    """The requests the asset host and the API have received since the test began."""
    mark = len(published.requests)
    return lambda: published.requests[mark:]


@pytest.fixture
def config(tmp_path) -> Config:
    return write_env(tmp_path, Role.CLIENT)


@pytest.fixture
def pin(generated_lock_path) -> binaries.Pin:
    (pin, ) = binaries.pins_for(binaries.load_lock(generated_lock_path), "websocat", PLATFORM)
    return pin


# Install ==============================================================================================================


def test_client_install_fetches_only_websocat(config, services, served, tmp_path):
    before = tree(tmp_path)
    assert install(config, services=services) == 0
    requested = [request.path for request in served()]
    assert len(requested) == 1 and "/vi/websocat/" in requested[0]
    assert {path for path in tree(tmp_path) if path not in before} == {"bin", "bin/websocat", f"bin/{DIGESTS}"}


def test_client_install_records_what_it_installed(config, services, pin, tmp_path):
    assert install(config, services=services) == 0
    assert read_digests(tmp_path / "bin") == {"websocat": pin.member_sha256}


def test_client_install_asks_for_no_token_service_account_or_label(tmp_path, services):
    (tmp_path / ".env").write_bytes(CLIENT_ENV.encode())
    assert install(Config.load(tmp_path), services=services) == 0


def test_client_install_prints_which_binary_got_which_trust_level(config, services, capsys):
    assert install(config, services=services) == 0
    out = capsys.readouterr().out
    (line, ) = [line for line in out.splitlines() if "bin/websocat" in line]
    assert "websocat 1.14.1" in line and "digest-only" in line
    assert "no Sigstore attestation" in line


def test_the_trust_line_says_attested_for_an_attested_binary(pin, tmp_path):
    line = describe_install(
        dataclasses.replace(pin, tool="goetia", install_name="goetia"),
        Installed(tmp_path / "goetia", TrustLevel.ATTESTED)
    )
    assert "bin/goetia" in line and "attested" in line and "Sigstore attestation verified" in line
    assert "digest-only" not in line


def test_client_install_is_idempotent_and_restores_a_replaced_binary(config, services, pin, tmp_path):
    assert install(config, services=services) == 0
    (tmp_path / "bin" / "websocat").write_bytes(b"tampered")
    assert install(config, services=services) == 0
    assert hashlib.sha256((tmp_path / "bin" / "websocat").read_bytes()).hexdigest() == pin.member_sha256
    assert sorted(path.name for path in (tmp_path / "bin").iterdir()) == [DIGESTS, "websocat"]


def test_a_wrong_download_installs_nothing_and_records_nothing(config, generated_lock_path, tmp_path):
    bad = Upstream()
    for tool, version in VERSIONS.items():
        bad.add_tool(tool, version, generation="b")
    services = Services(
        lock_path=generated_lock_path, platform=PLATFORM, fetcher=lambda: Fetcher(transport=bad.transport)
    )
    with pytest.raises(BinariesError):
        install(config, services=services)
    assert list((tmp_path / "bin").iterdir()) == []


def test_host_install_is_not_available_yet(tmp_path, services):
    config = write_env(tmp_path, Role.HOST)
    with pytest.raises(InstallError, match="host"):
        install(config, services=services)


# Uninstall ============================================================================================================


def test_client_uninstall_removes_bin_and_tolerates_its_absence(config, services, tmp_path):
    assert install(config, services=services) == 0
    assert uninstall(config, services=services) == 0
    assert not (tmp_path / "bin").exists()
    assert (tmp_path / ".env").exists()
    assert uninstall(config, services=services) == 0


def test_host_uninstall_is_not_available_yet(tmp_path, services):
    with pytest.raises(InstallError, match="host"):
        uninstall(write_env(tmp_path, Role.HOST), services=services)
