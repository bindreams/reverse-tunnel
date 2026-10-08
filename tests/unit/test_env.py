import os
import stat
import subprocess
from pathlib import Path

import pytest

from ctl import env
from ctl.env import EnvError, parse, read, referenced_variables, tracked_config_files
from scanner_support import GIT_ENV, REPO_ROOT

SECRET = "0123456789abcdef"

# The dialect ==========================================================================================================


def test_accepts_the_documented_subset():
    text = "# a comment\n\nROLE=host\nRT_EMPTY=\nRT_PORT=8080\nRT_URL=ws://a.b:1/c?d=e&f\n"
    assert parse(text, source=".env") == {
        "ROLE": "host",
        "RT_EMPTY": "",
        "RT_PORT": "8080",
        "RT_URL": "ws://a.b:1/c?d=e&f",
    }


def test_a_missing_final_newline_is_accepted():
    assert parse("A=1", source=".env") == {"A": "1"}


def test_empty_text_is_an_empty_mapping():
    assert parse("", source=".env") == {}


BANNED = [
    pytest.param("export K=v\n", id="export"),
    pytest.param("K = v\n", id="spaces-around-equals"),
    pytest.param("K =v\n", id="space-before-equals"),
    pytest.param("K= v\n", id="space-after-equals"),
    pytest.param("k=v\n", id="lowercase-key"),
    pytest.param("1K=v\n", id="digit-first-key"),
    pytest.param("K-X=v\n", id="dash-in-key"),
    pytest.param("=v\n", id="empty-key"),
    pytest.param("K\n", id="no-equals"),
    pytest.param(" K=v\n", id="indented-assignment"),
    pytest.param(" # note\n", id="indented-comment"),
    pytest.param(" \n", id="whitespace-only-line"),
    pytest.param("\t\n", id="tab-only-line"),
    pytest.param('K="v"\n', id="double-quote"),
    pytest.param("K='v'\n", id="single-quote"),
    pytest.param("K=`v`\n", id="backtick"),
    pytest.param("K=a\\b\n", id="backslash"),
    pytest.param("K=a$B\n", id="dollar"),
    pytest.param("K=${B}\n", id="interpolation"),
    pytest.param("K=v # note\n", id="inline-comment"),
    pytest.param("K=v#note\n", id="hash-without-space"),
    pytest.param("K=a b\n", id="inner-space"),
    pytest.param("K=a\tb\n", id="inner-tab"),
    pytest.param("K=v \n", id="trailing-space"),
    pytest.param("K=café\n", id="non-ascii-value"),
    pytest.param("K=a\x7fb\n", id="del"),
    pytest.param("K=a\x00b\n", id="nul"),
    pytest.param("K=v\r\n", id="crlf"),
    pytest.param("K=v\rL=w\n", id="bare-cr"),
    pytest.param("# note\r\nK=v\n", id="crlf-after-comment"),
    pytest.param("﻿K=v\n", id="bom"),
    pytest.param("K=v\nK=w\n", id="duplicate-key"),
    pytest.param("K=v\n\n# c\nK=\n", id="duplicate-key-with-empty-value"),
]


@pytest.mark.parametrize("text", BANNED)
def test_rejects_each_banned_construct(text):
    with pytest.raises(EnvError) as raised:
        parse(text, source="deploy.env")
    assert "deploy.env" in str(raised.value)


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("# c\n\nK=v\nexport L=w\n", 4),
        ("A=1\nB=2\nc=3\n", 3),
        ("A=1\nB=\"2\"\n", 2),
        ("A=1\nB=2\nA=3\n", 3),
        ("A=1\n# c\r\nB=2\n", 2),
        ("A=1\nB=2\rC=3\n", 2),
        ("﻿A=1\n", 1),
    ],
)
def test_the_error_names_the_one_based_line(text, line):
    with pytest.raises(EnvError) as raised:
        parse(text, source="deploy.env")
    assert f"deploy.env:{line}" in str(raised.value)


def test_a_duplicate_names_the_key_and_the_first_line():
    with pytest.raises(EnvError) as raised:
        parse("# c\nRT_X=1\nRT_X=2\n", source=".env")
    message = str(raised.value)
    assert "RT_X" in message
    assert ".env:3" in message
    assert "line 2" in message


@pytest.mark.parametrize(
    "text",
    [
        f'RT_TOKEN="{SECRET}"\n',
        f"RT_TOKEN={SECRET} \n",
        f"RT_TOKEN = {SECRET}\n",
        f"RT_TOKEN={SECRET}$x\n",
        f"RT_TOKEN={SECRET}#x\n",
        f"{SECRET}\n",
        f"export {SECRET}\n",
        f"RT_TOKEN={SECRET}\nRT_TOKEN={SECRET}\n",
        f"rt_token={SECRET}\n",
        f"RT_TOKEN={SECRET}\r\n",
        f"RT_TOKEN={SECRET}é\n",
    ],
)
def test_an_error_never_echoes_a_value(text):
    with pytest.raises(EnvError) as raised:
        parse(text, source=".env")
    assert SECRET not in str(raised.value)


def test_a_value_error_names_the_key():
    with pytest.raises(EnvError) as raised:
        parse('RT_TOKEN="x"\n', source=".env")
    assert "RT_TOKEN" in str(raised.value)


# Reading ==============================================================================================================


def test_read_returns_the_parsed_file(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\nB=2\n")
    assert read(path) == {"A": "1", "B": "2"}


def test_read_names_the_file_in_a_parse_error(tmp_path):
    path = tmp_path / "x.env"
    path.write_bytes(b"A=1\nbad\n")
    with pytest.raises(EnvError) as raised:
        read(path)
    assert str(path) in str(raised.value)
    assert ":2" in str(raised.value)


def test_read_refuses_invalid_utf8(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"A=\xff\n")
    with pytest.raises(EnvError) as raised:
        read(path)
    assert str(path) in str(raised.value)


def test_read_refuses_a_bom(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"\xef\xbb\xbfA=1\n")
    with pytest.raises(EnvError):
        read(path)


def test_read_does_not_translate_line_endings(tmp_path):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\r\n")
    with pytest.raises(EnvError):
        read(path)


def test_read_names_a_missing_file(tmp_path):
    path = tmp_path / ".env"
    with pytest.raises(EnvError) as raised:
        read(path)
    assert str(path) in str(raised.value)


def test_read_refuses_a_symlink_without_reading_its_target(tmp_path):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)
    with pytest.raises(EnvError) as raised:
        read(link)
    assert str(link) in str(raised.value)
    assert "symlink" in str(raised.value)


def test_read_refuses_a_dangling_symlink(tmp_path):
    link = tmp_path / ".env"
    link.symlink_to(tmp_path / "absent")
    with pytest.raises(EnvError) as raised:
        read(link)
    assert "symlink" in str(raised.value)


def test_read_refuses_a_directory(tmp_path):
    with pytest.raises(EnvError) as raised:
        read(tmp_path)
    assert str(tmp_path) in str(raised.value)


def test_read_refuses_a_fifo_without_blocking(tmp_path):
    fifo = tmp_path / ".env"
    os.mkfifo(fifo)
    with pytest.raises(EnvError) as raised:
        read(fifo)
    assert "regular file" in str(raised.value)


def test_read_opens_with_nofollow_where_the_platform_has_it():
    assert env.OPEN_FLAGS & os.O_RDONLY == os.O_RDONLY
    assert env.OPEN_FLAGS & os.O_NOFOLLOW


class _Stat:

    def __init__(self, *, mode=stat.S_IFREG, attributes=0, ino=1, dev=1):
        self.st_mode = mode
        self.st_file_attributes = attributes
        self.st_ino = ino
        self.st_dev = dev


def test_without_nofollow_a_reparse_point_is_refused(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\n")
    monkeypatch.setattr(env, "OPEN_FLAGS", os.O_RDONLY)
    monkeypatch.setattr(os, "lstat", lambda p: _Stat(attributes=env.FILE_ATTRIBUTE_REPARSE_POINT))
    with pytest.raises(EnvError) as raised:
        read(path)
    assert "symlink" in str(raised.value)


def test_without_nofollow_a_symlink_is_refused(tmp_path, monkeypatch):
    target = tmp_path / "target.env"
    target.write_bytes(b"A=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)
    monkeypatch.setattr(env, "OPEN_FLAGS", os.O_RDONLY)
    with pytest.raises(EnvError) as raised:
        read(link)
    assert "symlink" in str(raised.value)


def test_without_nofollow_a_path_swapped_after_open_is_refused(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\n")
    real = path.stat()
    monkeypatch.setattr(env, "OPEN_FLAGS", os.O_RDONLY)
    monkeypatch.setattr(os, "lstat", lambda p: _Stat(ino=real.st_ino + 1, dev=real.st_dev))
    with pytest.raises(EnvError):
        read(path)


def test_without_nofollow_a_regular_file_is_read(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\n")
    monkeypatch.setattr(env, "OPEN_FLAGS", os.O_RDONLY)
    assert read(path) == {"A": "1"}


# Referenced variables =================================================================================================


@pytest.mark.parametrize(
    "template",
    [
        "{{.Envs.X}}",
        "{{ .Envs.X }}",
        "{{  .Envs.X  }}",
        "{{ $.Envs.X }}",
        "{{- .Envs.X -}}",
        "{{-.Envs.X}}",
        "{{\t.Envs.X\n}}",
        'x = "{{ .Envs.X }}"',
    ],
)
def test_referenced_variables_tolerates_go_template_whitespace(template):
    assert referenced_variables(template) == {"X"}


def test_referenced_variables_finds_compose_syntax():
    assert referenced_variables("a: ${A}\nb: ${B:?msg}\nc: ${C:-d}\n") == {"A", "B", "C"}


def test_referenced_variables_unions_both_syntaxes_across_a_file():
    text = '{{ .Envs.RT_DOMAIN }} ${RT_ADMIN_PORT} {{ .Envs.RT_DOMAIN }} ${GITHUB_OUTPUT:?}'
    assert referenced_variables(text) == {"RT_DOMAIN", "RT_ADMIN_PORT", "GITHUB_OUTPUT"}


@pytest.mark.parametrize(
    "text",
    [
        "no variables here",
        "${{ runner.os }}",
        "{{ .Values.X }}",
        "{{ .Envs.lower }}",
        "$X",
        "${lower}",
    ],
)
def test_referenced_variables_ignores_non_references(text):
    assert referenced_variables(text) == set()


# Tracked config files =================================================================================================


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


def test_tracked_config_files_come_from_git(repo):
    for name in ("a.toml", "b.yaml", "c.yml", "d.conf", "Caddyfile", "e.py", "f.txt", "g.md", "uv.lock", "h.TOML"):
        (repo / name).write_text("x\n")
    (repo / "sub").mkdir()
    (repo / "sub" / "i.yaml").write_text("x\n")
    (repo / "untracked.toml").write_text("x\n")
    git(repo, "add", "--", *(p.name for p in repo.iterdir() if p.name not in {".git", "untracked.toml", "sub"}), "sub")
    found = tracked_config_files(repo, minimum=())
    assert sorted(p.relative_to(repo).as_posix()
                  for p in found) == ["Caddyfile", "a.toml", "b.yaml", "c.yml", "d.conf", "h.TOML", "sub/i.yaml"]
    assert all(p.is_absolute() and p.is_file() for p in found)


def test_a_filename_needing_git_quoting_is_returned_intact(repo):
    name = "café x.toml"
    (repo / name).write_text("x\n")
    git(repo, "add", "--", name)
    assert [p.name for p in tracked_config_files(repo, minimum=())] == [name]


def test_an_empty_result_is_an_error(repo):
    (repo / "a.py").write_text("x\n")
    git(repo, "add", "--", "a.py")
    with pytest.raises(EnvError) as raised:
        tracked_config_files(repo, minimum=())
    assert "no tracked config files" in str(raised.value)


def test_a_missing_known_file_is_an_error(repo):
    (repo / "a.toml").write_text("x\n")
    git(repo, "add", "--", "a.toml")
    with pytest.raises(EnvError) as raised:
        tracked_config_files(repo, minimum=("a.toml", "renamed.yaml"))
    assert "renamed.yaml" in str(raised.value)


def test_a_directory_that_is_not_a_git_repository_is_an_error(tmp_path):
    with pytest.raises(EnvError):
        tracked_config_files(tmp_path, minimum=())


def test_tracked_config_files_of_this_repository_include_the_known_minimum():
    found = {p.relative_to(REPO_ROOT).as_posix() for p in tracked_config_files(REPO_ROOT)}
    assert found
    assert set(env.KNOWN_MINIMUM) <= found
