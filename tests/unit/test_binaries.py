import enum
import re
from pathlib import Path

import pytest
import tomlkit
from binaries_support import (
    BINARIES,
    FRP_TARGETS,
    GOETIA_TRIPLES,
    PLATFORMS,
    archive_format,
    install_name,
    is_windows,
    member_path,
)

from ctl import binaries
from ctl.archive import ArchiveFormat
from ctl.binaries import Pin, bundle_for, current_platform, load_lock, pins_for, tools_for_role
from ctl.config import Role
from ctl.errors import BinariesError

HEX64 = re.compile(r"[0-9a-f]{64}")


@pytest.fixture(params=["generated", "committed"])
def lock(request, generated_lock_path: Path) -> dict[str, dict[str, list[Pin]]]:
    """The lock refresh produces from fixture releases, and the lock this repository ships."""
    return load_lock(generated_lock_path if request.param == "generated" else binaries.LOCK_PATH)


def edited(path: Path, edit) -> Path:
    """Copy of the lock at `path` after `edit(document)`."""
    document = tomlkit.parse(path.read_text())
    edit(document)
    out = path.with_name("edited.lock.toml")
    out.write_text(tomlkit.dumps(document))
    return out


# Platform =============================================================================================================


@pytest.mark.parametrize(
    ("system", "machine", "expected"),
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "aarch64", "linux-aarch64"),
        ("Linux", "arm64", "linux-aarch64"),
        ("Darwin", "x86_64", "macos-x86_64"),
        ("Darwin", "arm64", "macos-aarch64"),
        ("Windows", "AMD64", "windows-x86_64"),
    ],
)
def test_current_platform_maps_uname_to_lock_keys(system, machine, expected):
    assert current_platform(system, machine) == expected


@pytest.mark.parametrize(("system", "machine"), [("Linux", "armv7l"), ("FreeBSD", "amd64"), ("Windows", "ARM64"),
                                                 ("Darwin", "ppc64")])
def test_an_unsupported_platform_raises_naming_the_machine_and_system(system, machine):
    with pytest.raises(BinariesError) as raised:
        current_platform(system, machine)
    assert system in str(raised.value)
    assert machine in str(raised.value)


def test_this_host_is_a_supported_platform():
    assert current_platform() in PLATFORMS


# Reading the lock =====================================================================================================


def test_load_lock_parses_every_tool_and_platform(lock):
    assert set(lock) == {"frp", "websocat", "goetia"}
    for tool, by_platform in lock.items():
        assert tuple(by_platform) == (*PLATFORMS, *(("bundle", ) if tool == "goetia" else ()))
        for platform in PLATFORMS:
            assert len(by_platform[platform]) == len(BINARIES[tool])
            for pin in by_platform[platform]:
                assert pin.tool == tool
                assert HEX64.fullmatch(pin.asset_sha256)
                assert HEX64.fullmatch(pin.member_sha256)


@pytest.mark.parametrize("field", ["asset_sha256", "member_sha256"])
@pytest.mark.parametrize("bad", ["", "abc", "A" * 64, "g" * 64, "sha256:" + "a" * 64])
def test_load_lock_rejects_a_pin_with_an_empty_or_malformed_digest(generated_lock_path, field, bad):

    def corrupt(document):
        document["frp"]["linux-x86_64"][0][field] = bad

    with pytest.raises(BinariesError) as raised:
        load_lock(edited(generated_lock_path, corrupt))
    assert field in str(raised.value)
    assert "frp" in str(raised.value)
    assert "linux-x86_64" in str(raised.value)


@pytest.mark.parametrize("field", ["url", "asset_sha256", "member_sha256", "archive_format", "install_name"])
def test_load_lock_rejects_a_pin_missing_a_field(generated_lock_path, field):

    def remove(document):
        del document["websocat"]["macos-aarch64"][0][field]

    with pytest.raises(BinariesError) as raised:
        load_lock(edited(generated_lock_path, remove))
    assert field in str(raised.value)


def test_load_lock_rejects_an_unknown_archive_format(generated_lock_path):

    def corrupt(document):
        document["frp"]["linux-x86_64"][0]["archive_format"] = "tar.bz2"

    with pytest.raises(BinariesError, match="tar.bz2"):
        load_lock(edited(generated_lock_path, corrupt))


@pytest.mark.parametrize(
    ("tool", "platform", "corrupt"),
    [
        ("frp", "linux-x86_64", lambda pin: pin.pop("archive_member")),
        ("websocat", "linux-x86_64", lambda pin: pin.update(archive_member="websocat")),
    ],
    ids=["archive-without-member", "bare-with-member"],
)
def test_load_lock_rejects_a_member_that_contradicts_the_format(generated_lock_path, tool, platform, corrupt):

    def edit(document):
        corrupt(document[tool][platform][0])

    with pytest.raises(BinariesError, match="archive_member"):
        load_lock(edited(generated_lock_path, edit))


@pytest.mark.parametrize(
    "edit",
    [
        lambda d: d["frp"].pop("macos-x86_64"),
        lambda d: d["frp"].update({"linux-riscv64": d["frp"]["linux-x86_64"]}),
        lambda d: d["frp"]["linux-x86_64"].pop(1),
        lambda d: d["goetia"].pop("bundle"),
        lambda d: d["frp"].update(bundle=d["goetia"]["bundle"]),
        lambda d: d.update(extra=d["frp"]),
        lambda d: d["frp"].pop("version"),
        lambda d: d.pop("websocat"),
    ],
    ids=[
        "missing-platform", "unknown-platform", "missing-binary", "goetia-without-bundle", "frp-with-bundle",
        "unknown-tool", "no-version", "missing-tool"
    ],
)
def test_load_lock_rejects_a_lock_that_does_not_match_the_tool_table(generated_lock_path, edit):
    with pytest.raises(BinariesError):
        load_lock(edited(generated_lock_path, edit))


def test_load_lock_rejects_the_seed_with_no_pins(lock_path):
    with pytest.raises(BinariesError):
        load_lock(lock_path)


def test_load_lock_rejects_invalid_toml(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("[frp\n")
    with pytest.raises(BinariesError, match="bad.toml"):
        load_lock(path)


# Resolving pins =======================================================================================================


def test_pins_for_unknown_platform_raises(lock):
    for platform in ("plan9-mips", "bundle", ""):
        with pytest.raises(BinariesError, match="platform"):
            pins_for(lock, "frp", platform)


def test_pins_for_unknown_tool_raises(lock):
    with pytest.raises(BinariesError, match="nosuch"):
        pins_for(lock, "nosuch", "linux-x86_64")
    with pytest.raises(BinariesError, match="nosuch"):
        bundle_for(lock, "nosuch")


@pytest.mark.parametrize("platform", PLATFORMS)
def test_frp_contributes_both_frpc_and_frps_on_every_platform(lock, platform):
    first, second = pins_for(lock, "frp", platform)
    assert [first.install_name, second.install_name] == [install_name("frpc", platform), install_name("frps", platform)]
    assert first.url == second.url
    assert first.asset_sha256 == second.asset_sha256
    assert first.member_sha256 != second.member_sha256
    assert first.archive_member != second.archive_member


@pytest.mark.parametrize("platform", PLATFORMS)
def test_goetia_contributes_goetia_and_goetia_shim_on_every_platform(lock, platform):
    first, second = pins_for(lock, "goetia", platform)
    assert [first.install_name,
            second.install_name] == [install_name("goetia", platform),
                                     install_name("goetia-shim", platform)]
    assert first.url == second.url
    assert first.asset_sha256 == second.asset_sha256
    assert first.member_sha256 != second.member_sha256


def test_websocat_contributes_one_binary_on_every_platform(lock):
    for platform in PLATFORMS:
        (pin, ) = pins_for(lock, "websocat", platform)
        assert pin.install_name == install_name("websocat", platform)


def test_windows_pins_use_exe_install_names(lock):
    for tool in lock:
        for platform in PLATFORMS:
            for pin in pins_for(lock, tool, platform):
                assert pin.install_name.endswith(".exe") == is_windows(platform), (tool, platform)
                if pin.archive_member is not None:
                    assert pin.archive_member.endswith(pin.install_name)


def test_each_tool_records_its_own_archive_format(lock):
    for tool in lock:
        for platform in PLATFORMS:
            for pin in pins_for(lock, tool, platform):
                assert pin.archive_format == archive_format(tool, platform), (tool, platform)
    assert {pins_for(lock, "frp", "linux-x86_64")[0].archive_format} == {ArchiveFormat.TAR_GZ}
    assert {pins_for(lock, "goetia", "macos-aarch64")[0].archive_format} == {ArchiveFormat.TAR_XZ}
    assert {pins_for(lock, "websocat", "linux-x86_64")[0].archive_format} == {ArchiveFormat.BARE}


def test_a_bare_binary_has_no_member_and_equal_digests(lock):
    for platform in PLATFORMS:
        (pin, ) = pins_for(lock, "websocat", platform)
        assert pin.archive_member is None
        assert pin.asset_sha256 == pin.member_sha256


def test_goetia_archive_members_carry_the_top_level_directory(lock):
    for platform in PLATFORMS:
        for pin, binary in zip(pins_for(lock, "goetia", platform), BINARIES["goetia"], strict=True):
            assert pin.archive_member == member_path("goetia", pin.version, platform, binary)
            assert pin.archive_member.startswith(f"goetia-{GOETIA_TRIPLES[platform]}/")


def test_frp_archive_members_carry_the_top_level_directory(lock):
    for platform in PLATFORMS:
        for pin in pins_for(lock, "frp", platform):
            assert pin.archive_member is not None
            assert pin.archive_member.startswith(f"frp_{pin.version}_{FRP_TARGETS[platform]}/")


def test_every_pin_of_a_tool_shares_its_version(lock):
    for tool, by_platform in lock.items():
        assert len({pin.version for pins in by_platform.values() for pin in pins}) == 1, tool


def test_the_sigstore_bundle_is_pinned_like_any_other_asset(lock):
    bundle = bundle_for(lock, "goetia")
    assert bundle is not None
    assert bundle.url.endswith("/goetia.sigstore.json")
    assert HEX64.fullmatch(bundle.asset_sha256)
    assert bundle.archive_member is None
    assert bundle.archive_format == ArchiveFormat.BARE
    assert bundle.version == pins_for(lock, "goetia", "linux-x86_64")[0].version


def test_tools_without_a_bundle_have_none(lock):
    assert bundle_for(lock, "frp") is None
    assert bundle_for(lock, "websocat") is None


def test_the_bundle_is_not_a_platform(lock):
    assert "bundle" not in PLATFORMS
    assert all(
        pin.install_name != "goetia.sigstore.json" for platform in PLATFORMS
        for pin in pins_for(lock, "goetia", platform)
    )


# Roles ================================================================================================================


def test_tools_for_role_lists_what_a_host_installs():
    assert tools_for_role(Role.HOST) == ("frp", "websocat", "goetia")


def test_tools_for_role_excludes_frp_and_goetia_for_a_client():
    assert tools_for_role(Role.CLIENT) == ("websocat", )


def test_tools_for_role_is_empty_for_a_bridge():
    assert tools_for_role(Role.BRIDGE) == ()


# Types ================================================================================================================


def test_archive_format_is_a_string_enum_with_the_four_recorded_values():
    assert issubclass(ArchiveFormat, enum.StrEnum)
    assert [f.value for f in ArchiveFormat] == ["tar.gz", "tar.xz", "zip", "bare"]
    assert binaries.ArchiveFormat is ArchiveFormat
