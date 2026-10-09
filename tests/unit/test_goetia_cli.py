"""`ctl.goetia`, the one module that runs goetia, against a scripted stand-in executable."""

import pytest
from tests.unit.goetia_support import ERROR_KINDS, FakeGoetia, daemon, envelope, error

from ctl import goetia
from ctl.errors import InstallError
from ctl.goetia import DaemonState, GoetiaError

ID = "reverse-tunnel-frpc"
OTHER = "reverse-tunnel-websocat"


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeGoetia:
    fake = FakeGoetia(tmp_path / "fake")
    monkeypatch.setattr(goetia, "command", lambda root: fake.command)
    return fake


@pytest.fixture
def root(tmp_path):
    path = tmp_path / "deployment"
    path.mkdir()
    return path


# list and status ======================================================================================================


def test_daemon_list_parses_the_document(fake, root):
    fake.on("list", stdout=envelope([daemon(ID), daemon(OTHER, "stopped", False, None)]))
    assert goetia.daemon_list(root) == [
        DaemonState(ID, "running", True, 4242),
        DaemonState(OTHER, "stopped", False, None)
    ]
    assert fake.calls == [["daemon", "list", "--json"]]


def test_daemon_list_parses_a_document_printed_with_a_nonzero_exit(fake, root):
    """goetia exits 1 when a blob will not decode, while still printing a complete, valid document."""
    fake.on("list", stdout=envelope([daemon(ID)], [error("foreign", OTHER)]), exit=1)
    report = goetia.daemon_report(root, "list")
    assert [state.id for state in report.daemons] == [ID]
    assert [(problem.kind, problem.id) for problem in report.errors] == [("foreign", OTHER)]


@pytest.mark.parametrize("kind", ERROR_KINDS)
def test_daemon_list_surfaces_each_error_kind(fake, root, kind):
    fake.on("list", stdout=envelope([daemon(ID)], [error(kind, OTHER, "scripted detail")]), exit=1)
    with pytest.raises(GoetiaError) as raised:
        goetia.daemon_list(root)
    assert kind in str(raised.value) and "scripted detail" in str(raised.value) and OTHER in str(raised.value)
    assert [problem.kind for problem in raised.value.problems] == [kind]


def test_daemon_list_refuses_a_document_with_undetermined_entries(fake, root):
    fake.on("list", stdout=envelope([], [], [{"name": "x", "reason": "cannot read the unit"}]), exit=4)
    with pytest.raises(GoetiaError, match="cannot read the unit"):
        goetia.daemon_list(root)


def test_a_manager_level_failure_with_no_id_is_surfaced(fake, root):
    fake.on("list", stdout=envelope([], [error("unavailable", None, "no systemd")]), exit=1)
    with pytest.raises(GoetiaError, match="unavailable.*no systemd"):
        goetia.daemon_list(root)


def test_daemon_list_rejects_text_output(fake, root):
    fake.on("list", stdout=f"{ID}  running  enabled\n")
    with pytest.raises(GoetiaError, match="not the JSON"):
        goetia.daemon_list(root)


@pytest.mark.parametrize(
    "stdout", [
        "[]",
        "{}",
        '{"daemons": []}',
        '{"daemons": [], "errors": []}',
        '{"daemons": [{"id": "x", "state": "running", "enabled": true}], "errors": [], "undetermined": []}',
        '{"daemons": [{"id": "x", "state": "dancing", "enabled": true, "pid": null}], "errors": [], "undetermined": []}',
        '{"daemons": [{"id": "x", "state": "running", "enabled": 1, "pid": null}], "errors": [], "undetermined": []}',
        '{"daemons": [{"id": "x", "state": "running", "enabled": true, "pid": true}], "errors": [], "undetermined": []}',
        '{"daemons": [], "errors": [{"id": null, "kind": "novel", "message": "m"}], "undetermined": []}',
    ]
)
def test_a_document_that_is_not_the_envelope_is_rejected(fake, root, stdout):
    fake.on("list", stdout=stdout)
    with pytest.raises(GoetiaError):
        goetia.daemon_list(root)


def test_daemon_list_ignores_stderr(fake, root):
    """The Windows service backend prints a library message the CLI cannot suppress."""
    fake.on("list", stdout=envelope([daemon(ID)]), stderr="WARN scm: something unrelated\nnot json {\n")
    assert [state.id for state in goetia.daemon_list(root)] == [ID]


def test_daemon_status_asks_for_the_ids_and_returns_them(fake, root):
    fake.status(daemon(ID), daemon(OTHER, "failed", True, None))
    states = goetia.daemon_status(root, [ID, OTHER])
    assert [(state.id, state.state, state.pid) for state in states] == [(ID, "running", 4242), (OTHER, "failed", None)]
    assert fake.calls == [["daemon", "status", "--json", ID, OTHER]]


def test_daemon_status_leaves_out_an_id_that_is_not_installed(fake, root):
    fake.status(daemon(OTHER), errors=[error("not-installed", ID)], exit=1)
    assert [state.id for state in goetia.daemon_status(root, [ID, OTHER])] == [OTHER]


@pytest.mark.parametrize("kind", [kind for kind in ERROR_KINDS if kind != "not-installed"])
def test_daemon_status_raises_for_every_other_error_kind(fake, root, kind):
    fake.status(errors=[error(kind, ID)], exit=1)
    with pytest.raises(GoetiaError, match=kind):
        goetia.daemon_status(root, [ID])


def test_daemon_status_raises_when_the_state_could_not_be_determined(fake, root):
    fake.status(undetermined=[{"name": ID, "reason": "unit unreadable"}], exit=4)
    with pytest.raises(GoetiaError, match="unit unreadable"):
        goetia.daemon_status(root, [ID])


def test_a_missing_executable_is_an_install_error_naming_it(root, monkeypatch):
    monkeypatch.setattr(goetia, "command", lambda root: [str(root / "bin" / "goetia")])
    with pytest.raises(InstallError, match="goetia"):
        goetia.daemon_list(root)


# Changing things ======================================================================================================


def test_daemon_install_names_the_tracked_manifest_one_id_and_enable(fake, root):
    goetia.daemon_install(root, ID, enable=True)
    (call, ) = fake.calls
    assert call[:2] == ["daemon", "install"]
    assert call[call.index("-f") + 1] == str(root / "goetia.yaml")
    assert "--enable" in call and call[-1] == ID
    assert not {"--start", "--timeout", "--no-timeout", "--force", "--dry-run", "--json"} & set(call)


def test_daemon_install_without_enable_omits_the_flag(fake, root):
    goetia.daemon_install(root, ID, enable=False)
    assert "--enable" not in fake.calls[0]


@pytest.mark.parametrize("function", [goetia.daemon_start, goetia.daemon_restart, goetia.daemon_stop])
def test_start_restart_and_stop_pass_no_timeout(fake, root, function):
    function(root, ID)
    (call, ) = fake.calls
    assert call[-1] == ID and len(call) == 3
    assert call[1] == function.__name__.removeprefix("daemon_")


def test_a_failed_mutation_names_the_verb_the_exit_status_and_goetia_s_message(fake, root):
    fake.on("restart", stderr="error: unit failed to start\n", exit=4)
    with pytest.raises(GoetiaError) as raised:
        goetia.daemon_restart(root, ID)
    message = str(raised.value)
    assert "restart" in message and ID in message and "exit status 4" in message and "unit failed to start" in message


def test_a_conflict_is_explained(fake, root):
    fake.on("install", stderr="error: reverse-tunnel-frpc: hand-edited\n", exit=5)
    with pytest.raises(GoetiaError, match="hand-edited"):
        goetia.daemon_install(root, ID, enable=True)


# Uninstall ============================================================================================================


def test_daemon_uninstall_uses_no_json_and_names_each_id(fake, root):
    goetia.daemon_uninstall(root, [ID, OTHER])
    assert [call[-1] for call in fake.calls] == [ID, OTHER]
    assert all("--json" not in call for call in fake.calls)


def test_daemon_uninstall_tolerates_a_not_installed_id(fake, root):
    """goetia answers exit 0, `not installed (nothing to do)`: success, and nothing is scraped from it."""
    fake.on("uninstall", ID, stdout=f"{ID}: not installed (nothing to do)\n")
    goetia.daemon_uninstall(root, [ID])


@pytest.mark.parametrize(("kind", "code"), [("unreadable", 4), ("foreign", 1), ("unavailable", 1)])
def test_daemon_uninstall_reraises_every_other_failure(fake, root, kind, code):
    fake.on("uninstall", ID, stderr=f"error: {ID}: {kind} detail\n", exit=code)
    with pytest.raises(GoetiaError) as raised:
        goetia.daemon_uninstall(root, [ID])
    assert f"exit status {code}" in str(raised.value) and f"{kind} detail" in str(raised.value)


def test_daemon_uninstall_still_tries_the_other_id_after_a_failure_and_then_raises(fake, root):
    fake.on("uninstall", ID, stderr="error: locked\n", exit=1)
    with pytest.raises(GoetiaError, match="locked"):
        goetia.daemon_uninstall(root, [ID, OTHER])
    assert [call[-1] for call in fake.calls] == [ID, OTHER]


# Drift ================================================================================================================


def test_spec_is_current_compares_show_against_show_from_the_manifest(fake, root):
    fake.spec(ID, installed="command: [a]\n")
    assert goetia.spec_is_current(root, ID) is True
    installed, manifest = fake.calls
    assert installed == ["daemon", "show", ID]
    assert manifest[:2] == ["daemon", "show"] and manifest[manifest.index("-f") + 1] == str(root / "goetia.yaml")
    assert manifest[-1] == ID


def test_spec_is_current_is_false_when_the_two_renderings_differ_by_one_byte(fake, root):
    fake.spec(ID, installed="command: [a]\n", manifest="command: [b]\n")
    assert goetia.spec_is_current(root, ID) is False


def test_spec_is_current_never_invokes_diff(fake, root):
    fake.spec(ID, installed="x\n")
    goetia.spec_is_current(root, ID)
    assert "diff" not in fake.verbs()


def test_spec_is_current_raises_rather_than_guess_when_show_fails(fake, root):
    fake.on("show", "-f", ID, stdout="x\n")
    fake.on("show", ID, stderr="error: cannot determine\n", exit=4)
    with pytest.raises(GoetiaError, match="cannot determine"):
        goetia.spec_is_current(root, ID)
