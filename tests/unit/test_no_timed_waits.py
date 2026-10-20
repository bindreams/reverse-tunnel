"""No code in this project waits on the clock; the one exemption is a marked bound on a genuinely external event."""

import subprocess
import sys

import pytest
from timed_waits_support import (
    BAD_MARKERS,
    EXEMPT,
    MUST_FLAG,
    MUST_PASS,
    NOT_EXEMPTED,
    REPO_ROOT,
    SCRIPT,
    load_script,
)

script = load_script()


def check(source: str):
    return script.check_source("snippet.py", source)


def rules_of(source: str) -> set[str]:
    findings, _ = check(source)
    return {finding.rule for finding in findings}


def case(source: str, *rest):
    last = [line for line in source.splitlines() if line.strip()][-1].strip()
    return pytest.param(source, *rest, id=f"{rest[-1] if rest and isinstance(rest[-1], str) else 'ok'}: {last[:70]}")


# Detection ============================================================================================================


@pytest.mark.parametrize(("source", "rule"), [case(source, rule) for source, rule in MUST_FLAG])
def test_a_wait_on_the_clock_is_flagged(source, rule):
    assert rule in rules_of(source), check(source)


@pytest.mark.parametrize("source", [case(source) for source in MUST_PASS])
def test_code_that_waits_on_an_event_or_not_at_all_is_left_alone(source):
    assert check(source) == ([], [])


# Markers ==============================================================================================================


@pytest.mark.parametrize(("source", "line", "event"), [case(source, line, event) for source, line, event in EXEMPT])
def test_a_marked_timeout_is_exempt_and_the_marker_is_accounted_for(source, line, event):
    findings, used = check(source)
    assert findings == []
    assert [(marker.line, marker.event) for marker in used] == [(line, event)]


@pytest.mark.parametrize(("source", "rule"), [case(source, rule) for source, rule in NOT_EXEMPTED])
def test_a_marker_that_does_not_apply_exempts_nothing(source, rule):
    assert rule in rules_of(source), check(source)


@pytest.mark.parametrize(("source", "text"), [case(source, text) for source, text in BAD_MARKERS])
def test_a_marker_that_marks_nothing_or_names_no_event_is_itself_a_finding(source, text):
    findings, _ = check(source)
    assert any(finding.rule == "marker" and text in finding.message for finding in findings), findings


def test_a_finding_names_the_file_the_line_and_the_rule():
    findings, _ = script.check_source("ctl/x.py", "import time\n\ntime.sleep(1)\n")
    assert [str(finding) for finding in findings] == ["ctl/x.py:3: [banned-reference] time.sleep waits on the clock"]


# Command line =========================================================================================================


def run_script(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True, check=False)


def test_the_command_fails_on_a_timed_wait_and_names_it(tmp_path):
    (tmp_path / "bad.py").write_text("import time\ntime.sleep(1)\n")
    result = run_script(str(tmp_path))
    assert result.returncode == 1
    assert "bad.py:2: [banned-reference]" in result.stdout


def test_the_command_passes_clean_code_and_lists_the_markers_it_used_on_request(tmp_path):
    (tmp_path /
     "ok.py").write_text("import socket\n# external-bound: sshd answering\nsocket.create_connection(h, timeout=5)\n")
    quiet = run_script(str(tmp_path))
    assert (quiet.returncode, quiet.stdout) == (0, "")
    listed = run_script("--markers", str(tmp_path))
    assert listed.returncode == 0
    assert listed.stdout.endswith("ok.py:2: sshd answering\n") and listed.stdout.startswith("external-bound ")


def test_the_command_reads_directories_recursively_and_skips_a_virtualenv(tmp_path):
    (tmp_path / "deep" / "er").mkdir(parents=True)
    (tmp_path / "deep" / "er" / "bad.py").write_text("import time\ntime.sleep(1)\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("import time\ntime.sleep(1)\n")
    result = run_script(str(tmp_path))
    assert "bad.py" in result.stdout and "ignored.py" not in result.stdout


def test_the_command_refuses_a_path_it_cannot_check(tmp_path):
    (tmp_path / "notes.txt").write_text("sleep")
    result = run_script(str(tmp_path / "notes.txt"))
    assert result.returncode != 0 and "not a directory or a .py file" in result.stderr


# The project ==========================================================================================================

# Every exemption in the tree. Adding one is a decision to review: it must be an external event that fails to a human.
MARKERS = {
    ("ctl/doctor/frps_api.py", "frps's admin API answering on the bridge's own loopback; a human reads the failure."),
    ("ctl/doctor/probes.py", "docker answering."),
    ("ctl/doctor/probes.py", "a local port accepting a connection and sshd sending its banner."),
    ("ctl/doctor/probes.py", "the public front answering the data-path probe."),
    ("ctl/doctor/tls.py", "the public front answering a TLS handshake; a human reads the failure."),
    ("tests/platform/windows/test_service_token_windows.py", "the service writing its result"),
    (
        "ctl/github.py",
        "GitHub, or the host serving a release asset, answering a request. Per socket operation, not total."
    ),
}


def test_the_project_has_no_timed_waits_and_every_marker_in_it_is_accounted_for():
    findings, used = script.check_paths([REPO_ROOT / name for name in script.TARGETS], REPO_ROOT)
    assert [str(finding) for finding in findings] == []
    assert {(marker.path, marker.event) for marker in used} == MARKERS


def test_the_gate_covers_the_library_the_tests_and_the_scripts():
    covered = {
        path.relative_to(REPO_ROOT).as_posix()
        for path in script.python_files([REPO_ROOT / n for n in script.TARGETS])
    }
    assert {
        "ctl/github.py",
        "ctl/doctor/probes.py",
        "tests/e2e/logwait.py",
        "tests/unit/test_no_timed_waits.py",
        "tests/platform/posix/test_lock_posix.py",
        "scripts/no-timed-waits.py",
        "conftest.py",
    } <= covered
