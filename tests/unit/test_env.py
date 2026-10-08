import errno
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctl import env
from ctl.env import EnvError, parse, read, referenced_in_file, referenced_variables, tracked_config_files
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
    pytest.param("export K=v\n", 1, id="export"),
    pytest.param("K = v\n", 1, id="spaces-around-equals"),
    pytest.param("K =v\n", 1, id="space-before-equals"),
    pytest.param("K= v\n", 1, id="space-after-equals"),
    pytest.param("k=v\n", 1, id="lowercase-key"),
    pytest.param("1K=v\n", 1, id="digit-first-key"),
    pytest.param("K-X=v\n", 1, id="dash-in-key"),
    pytest.param("=v\n", 1, id="empty-key"),
    pytest.param("K\n", 1, id="no-equals"),
    pytest.param(" K=v\n", 1, id="indented-assignment"),
    pytest.param(" # note\n", 1, id="indented-comment"),
    pytest.param(" \n", 1, id="whitespace-only-line"),
    pytest.param("\t\n", 1, id="tab-only-line"),
    pytest.param('K="v"\n', 1, id="double-quote"),
    pytest.param("K='v'\n", 1, id="single-quote"),
    pytest.param("K=`v`\n", 1, id="backtick"),
    pytest.param("K=a\\b\n", 1, id="backslash"),
    pytest.param("K=a$B\n", 1, id="dollar"),
    pytest.param("K=${B}\n", 1, id="interpolation"),
    pytest.param("K=v # note\n", 1, id="inline-comment"),
    pytest.param("K=v#note\n", 1, id="hash-without-space"),
    pytest.param("K=a b\n", 1, id="inner-space"),
    pytest.param("K=a\tb\n", 1, id="inner-tab"),
    pytest.param("K=v \n", 1, id="trailing-space"),
    pytest.param("K=café\n", 1, id="non-ascii-value"),
    pytest.param("K=a\x7fb\n", 1, id="del"),
    pytest.param("K=a\x00b\n", 1, id="nul"),
    pytest.param("K=v\r\n", 1, id="crlf"),
    pytest.param("K=v\rL=w\n", 1, id="bare-cr"),
    pytest.param("# note\r\nK=v\n", 1, id="crlf-after-comment"),
    pytest.param("﻿K=v\n", 1, id="bom"),
    pytest.param("K=v\nK=w\n", 2, id="duplicate-key"),
    pytest.param("K=v\n\n# c\nK=\n", 4, id="duplicate-key-with-empty-value"),
]


@pytest.mark.parametrize(("text", "line"), BANNED)
def test_rejects_each_banned_construct(text, line):
    with pytest.raises(EnvError) as raised:
        parse(text, source="deploy.env")
    assert f"deploy.env:{line}" in str(raised.value)


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


def test_read_refuses_a_directory(tmp_path):
    with pytest.raises(EnvError) as raised:
        read(tmp_path)
    assert str(tmp_path) in str(raised.value)


def test_read_uses_the_windows_open_on_windows(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\n")
    opened = []

    def fake_open(target):
        opened.append(target)
        return os.open(target, os.O_RDONLY)

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(env, "_open_windows", fake_open)
    assert read(path) == {"A": "1"}
    assert opened == [path]


def test_a_windows_open_failure_is_an_env_error_naming_the_path(tmp_path, monkeypatch):

    def fake_open(target):
        raise OSError(errno.EACCES, "Access is denied")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(env, "_open_windows", fake_open)
    with pytest.raises(EnvError) as raised:
        read(tmp_path / ".env")
    assert str(tmp_path / ".env") in str(raised.value)


def test_a_windows_refusal_reaches_the_caller_unchanged(tmp_path, monkeypatch):

    def fake_open(target):
        raise EnvError(f"{target}: reparse point")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(env, "_open_windows", fake_open)
    with pytest.raises(EnvError) as raised:
        read(tmp_path / ".env")
    assert "reparse point" in str(raised.value)


def test_an_os_error_while_reading_is_an_env_error_naming_the_path(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_bytes(b"A=1\n")

    def broken(fd):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "fstat", broken)
    with pytest.raises(EnvError) as raised:
        read(path)
    assert str(path) in str(raised.value)


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
        "$X",
        "price: $5",
        "$$",
        "$${LIT}",
    ],
)
def test_referenced_variables_ignores_non_references(text):
    assert referenced_variables(text) == set()


UNSUPPORTED_ACTIONS = [
    pytest.param('{{ .Envs.X | default "y" }}', id="pipe"),
    pytest.param("{{ (.Envs.X) }}", id="parenthesised"),
    pytest.param('{{ index .Envs "X" }}', id="index"),
    pytest.param("{{ with .Envs }}{{ .X }}{{ end }}", id="with"),
    pytest.param("{{ .Envs }}", id="whole-map"),
    pytest.param("{{ .Envs.x }}", id="lowercase-name"),
    pytest.param("{{ .Envs.X.Y }}", id="field-of-value"),
    pytest.param("{{ if .Envs.X }}", id="condition"),
    pytest.param("{{ $x := .Envs.X }}", id="assignment"),
    pytest.param("{{ printf \"%s\" .Envs.X }}", id="function-call"),
    pytest.param("{{/* .Envs.X */}}", id="comment"),
    pytest.param("{{ .Envs.X", id="unterminated"),
    pytest.param("{{ .Envs.X }", id="half-closed"),
    pytest.param("{{ .Envs.X\n| quote }}", id="multi-line"),
    pytest.param('{{ printf "}}" .Envs.X }}', id="closing-braces-in-a-string"),
    pytest.param("{{ printf `}}` .Envs.X }}", id="closing-braces-in-a-raw-string"),
    pytest.param('{{ printf "{{ .Envs.X }}" .Envs.Y }}', id="a-reference-inside-a-string-hides-the-real-one"),
    pytest.param('{{ "}}" }}{{ .Envs.X | quote }}', id="string-then-pipe"),
    pytest.param('{{ index . (printf "En%s" "vs") }}', id="envs-built-at-run-time"),
    pytest.param("{{ range $k, $v := . }}{{ $v.RT_X }}{{ end }}", id="range-over-the-root"),
    pytest.param("{{ .Values.X }}", id="any-other-action"),
    pytest.param("{{ $x := 1 }}", id="variable-assignment"),
    pytest.param("{{{ .Envs.X }}", id="extra-opening-brace"),
    pytest.param("{{ .Envs.X }}{{", id="trailing-opening-braces"),
    pytest.param("# Envs are expanded here", id="the-word-outside-any-action"),
    pytest.param("x = .Envs.X", id="a-bare-field-outside-any-action"),
    pytest.param("{{ $.Envs.X }}{{ .Envs.Y | quote }}", id="valid-then-invalid"),
]


@pytest.mark.parametrize("template", UNSUPPORTED_ACTIONS)
def test_an_unsupported_envs_action_is_an_error_not_a_miss(template):
    with pytest.raises(EnvError) as raised:
        referenced_variables(f"a = 1\nb = {template}\n", source="frps.toml")
    message = str(raised.value)
    assert "frps.toml:2" in message
    assert "{{ .Envs.NAME }}" in message


def test_the_error_line_counts_from_the_unsupported_action():
    text = "{{ .Envs.A }}\n\n\n{{ .Envs.B }} {{ index .Envs \"C\" }}\n"
    with pytest.raises(EnvError) as raised:
        referenced_variables(text, source="x.toml")
    assert "x.toml:4" in str(raised.value)


def test_text_without_any_template_action_is_left_alone():
    assert referenced_variables("a = { b = 1 }\nc = '}}'\n") == set()


def test_the_strict_pattern_is_one_exported_constant():
    assert env.GO_TEMPLATE_REFERENCE.pattern == r"\{\{-?\s*\$?\.Envs\.([A-Z][A-Z0-9_]*)\s*-?\}\}"


def test_the_source_defaults_to_a_placeholder_in_the_message():
    with pytest.raises(EnvError) as raised:
        referenced_variables("{{ .Envs }}")
    assert "<text>:1" in str(raised.value)


STRICT_REJECTED = [
    "$RT_X",
    "${RT_X-d}",
    "${RT_X?e}",
    "${RT_X:+a}",
    "${RT_X:=a}",
    "${lower}",
    "${RT_A:-${RT_B}}",
    "${RT_X:-a$b}",
    "${RT_X:?a$$b}",
    "$$$",
    "${}",
    "${RT_X",
    "${ RT_X }",
    "$ {RT_X}",
    "price: $",
]


@pytest.mark.parametrize("form", STRICT_REJECTED)
def test_strict_interpolation_rejects_every_unsupported_dollar(form):
    with pytest.raises(EnvError) as raised:
        referenced_variables(f"a: 1\nb: {form}\n", source="compose.yaml", strict_dollar=True)
    assert "compose.yaml:2" in str(raised.value)


STRICT_ACCEPTED = [
    ("${A}", {"A"}),
    ("${B:?msg}", {"B"}),
    ("${C:-d}", {"C"}),
    ("${C:-}", {"C"}),
    ("${D:?a longer message}", {"D"}),
    ("x: ${A}${B}", {"A", "B"}),
    ("$${LIT}", set()),
    ("$$", set()),
    ("$$$$", set()),
    ("a $$ b", set()),
    ("$${LIT} ${A}", {"A"}),
    ("{{ $.Envs.X }}", {"X"}),
    ("no dollars", set()),
]


@pytest.mark.parametrize(("text", "names"), STRICT_ACCEPTED)
def test_strict_interpolation_accepts_the_strict_forms_and_skips_escapes(text, names):
    assert referenced_variables(text, source="compose.yaml", strict_dollar=True) == names


@pytest.mark.parametrize("text", ["$${RT_LIT}", "$RT_X", "$host", "a $ b", "$$$$ ${A}$"])
def test_lenient_scanning_ignores_a_bare_dollar_and_never_counts_an_escape(text):
    assert referenced_variables(text) <= {"A"}
    assert "RT_LIT" not in referenced_variables(text)


@pytest.mark.parametrize("form", [f for f in STRICT_REJECTED if "${" in f])
def test_lenient_scanning_still_rejects_an_unsupported_interpolation(form):
    with pytest.raises(EnvError) as raised:
        referenced_variables(f"a\n{form}\n", source="nginx.conf")
    assert "nginx.conf:2" in str(raised.value)


def test_lenient_scanning_still_finds_the_strict_forms():
    assert referenced_variables("${A} ${B:?m} ${C:-d} $host") == {"A", "B", "C"}


CADDY_PLACEHOLDERS = [
    "{$RT_X}",
    "{$RT_X:default}",
    "{env.RT_X}",
    "x {$HOME}/y",
    "root {env.ROOT_DIR}",
    'respond "{{$RT_X}"',
    "{{$RT_X}}",
    "{{env.RT_X}}",
]


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize("text", CADDY_PLACEHOLDERS)
def test_a_caddy_env_placeholder_is_unsupported(text, strict):
    with pytest.raises(EnvError) as raised:
        referenced_variables(f"a\n{text}\n", source="Caddyfile", strict_dollar=strict)
    assert "unsupported Caddy env placeholder" in str(raised.value)
    assert "Caddyfile:2" in str(raised.value)


@pytest.mark.parametrize("text", ["{ $x }", '{"env": "x"}', "{environment}", "{ env.X }", "{$ }", "{$1}"])
def test_text_that_only_resembles_a_caddy_placeholder_is_left_alone(text):
    assert referenced_variables(text) == set()


STRICT_FILES = [
    "compose.yaml", "goetia.yml", "frps.toml", "a.json", "a.ini", "a.tmpl", "a.service", "a.plist", "A.YAML"
]


@pytest.mark.parametrize("name", STRICT_FILES)
def test_referenced_in_file_is_strict_about_a_bare_dollar(tmp_path, name):
    path = tmp_path / name
    path.write_text("a\n$RT_X\n")
    with pytest.raises(EnvError) as raised:
        referenced_in_file(path)
    assert f"{path}:2" in str(raised.value)


@pytest.mark.parametrize("name", ["nginx.conf", "Caddyfile"])
def test_referenced_in_file_is_lenient_about_a_bare_dollar_in_conf_and_caddyfile(tmp_path, name):
    path = tmp_path / name
    path.write_text("proxy_set_header Host $host;\nx ${RT_A}\n")
    assert referenced_in_file(path) == {"RT_A"}


@pytest.mark.parametrize("name", ["nginx.conf", "Caddyfile"])
def test_referenced_in_file_rejects_an_odd_interpolation_even_when_lenient(tmp_path, name):
    path = tmp_path / name
    path.write_text("a ${RT_A:-${RT_B}}\n")
    with pytest.raises(EnvError) as raised:
        referenced_in_file(path)
    assert f"{path}:1" in str(raised.value)


def test_referenced_in_file_finds_go_references_in_toml(tmp_path):
    toml = tmp_path / "frps.toml"
    toml.write_text("b = '{{ .Envs.RT_B }}'\n")
    assert referenced_in_file(toml) == {"RT_B"}


@pytest.mark.parametrize("name", ["compose.yaml", "goetia.yml", "x.yaml"])
def test_referenced_in_file_reads_yaml_references(tmp_path, name):
    path = tmp_path / name
    path.write_text("a: ${RT_A}\nb: $${LIT}\n")
    assert referenced_in_file(path) == {"RT_A"}


def test_referenced_in_file_reports_a_bad_file_as_an_env_error(tmp_path):
    path = tmp_path / "x.toml"
    path.write_bytes(b"\xff")
    with pytest.raises(EnvError) as raised:
        referenced_in_file(path)
    assert str(path) in str(raised.value)
    with pytest.raises(EnvError):
        referenced_in_file(tmp_path / "absent.toml")


# Tracked config files =================================================================================================


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, env=GIT_ENV)


def test_tracked_config_files_come_from_git(repo):
    names = (
        "a.toml", "b.yaml", "c.yml", "d.conf", "Caddyfile", "e.py", "f.txt", "g.md", "uv.lock", "h.TOML", "j.json",
        "k.ini", "l.tmpl", "m.service", "n.plist", "Caddyfile.bak"
    )
    for name in names:
        (repo / name).write_text("x\n")
    (repo / "sub").mkdir()
    (repo / "sub" / "i.yaml").write_text("x\n")
    (repo / "untracked.toml").write_text("x\n")
    git(repo, "add", "--", *(p.name for p in repo.iterdir() if p.name not in {".git", "untracked.toml", "sub"}), "sub")
    found = tracked_config_files(repo, minimum=())
    assert sorted(p.relative_to(repo).as_posix() for p in found) == [
        "Caddyfile", "a.toml", "b.yaml", "c.yml", "d.conf", "h.TOML", "j.json", "k.ini", "l.tmpl", "m.service",
        "n.plist", "sub/i.yaml"
    ]
    assert all(p.is_absolute() and p.is_file() for p in found)


def test_github_files_are_not_deployment_templates(repo):
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yaml").write_text("run: echo ${{ runner.os }}\n")
    (repo / ".github" / "dependabot.yml").write_text("x: 1\n")
    (repo / "a.toml").write_text("x = 1\n")
    git(repo, "add", "--", ".github", "a.toml")
    assert [p.relative_to(repo).as_posix() for p in tracked_config_files(repo, minimum=())] == ["a.toml"]


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
