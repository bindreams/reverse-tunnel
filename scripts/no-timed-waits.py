#!/usr/bin/env python3
# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Fail when Python code waits on the clock instead of on an event.

Every wait in this project is a blocking read on a stream it owns, keyed on a positive event. A sleep, a timeout, or a
loop over a clock is a bet that some number of seconds is long enough. This walks the AST of every `.py` file under
`ctl/`, `tests/`, `scripts/` and the root `conftest.py`, resolves names through the file's imports, and reports:

- sleeps of any kind (`time.sleep`, `asyncio.sleep`, `from time import sleep`, `["sleep", ...]` as an argv);
- a timeout handed to anything (`timeout=`, `deadline=`, `settimeout`, `httpx.Timeout`, `asyncio.wait_for`,
  `socket.create_connection(addr, 5)`, a `--timeout` or `--wait-timeout` option in an argv list);
- the timed forms of blocking calls (`Event.wait(5)`, `Condition.wait_for(pred, 5)`, `Thread.join(5)`,
  `Popen.communicate(input, 5)`, `Lock.acquire(True, 5)`, `Queue.get(True, 5)`, `Future.result(5)`, `poll(5)`,
  `select.select(r, w, x, 5)`, `os.WNOHANG`, `signal.alarm`, `threading.Timer`);
- a clock read inside a loop, or added to or compared with something: the shape of `while monotonic() < deadline`.

The one exemption is a timeout that reports the failure of a genuinely external event to a human. It carries a comment
`# external-bound: <the event>`, on the statement or on the comment lines directly above it. A timeout given as a name
is exempt when the module-level assignment of that name carries the marker. Sleeps, clock loops and `WNOHANG` are never
exempt. A marker that exempts nothing, or names no event, is itself a finding.

    no-timed-waits.py [PATH...]     check these files or directories (default: the whole project)
    no-timed-waits.py --markers     also list every marker that exempted something, with its event
"""

import argparse
import ast
import io
import re
import sys
import tokenize
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("ctl", "tests", "scripts", "conftest.py")
MARKER = re.compile(r"#\s*external-bound:\s*(.*?)\s*$")

# What counts as a wait ================================================================================================

# Looked up by resolved name wherever they appear, called or not: `snooze = time.sleep` is a sleep too.
BANNED_REFERENCES = frozenset({
    "time.sleep", "asyncio.sleep", "asyncio.wait_for", "asyncio.timeout", "asyncio.timeout_at", "signal.alarm",
    "signal.setitimer", "threading.Timer", "os.WNOHANG", "socket.SO_RCVTIMEO", "socket.SO_SNDTIMEO"
})
# Never exempt: nothing about a sleep or a spin is a failure bound on an external event.
NEVER_EXEMPT = frozenset({"time.sleep", "asyncio.sleep", "signal.alarm", "signal.setitimer", "os.WNOHANG"})
# By final name alone, because the receiver's type is not known: `anyio.sleep`, `self.sleep`, `loop.call_later`.
BANNED_NAMES = frozenset({"sleep", "usleep", "nanosleep", "call_later", "call_at", "enterabs", "setitimer"})
TIMEOUT_WORD = re.compile(r"timeout|deadline", re.IGNORECASE)
# Exceptions that report a timeout are not waits: tests construct them to stand in for one.
TIMEOUT_EXCEPTION = re.compile(r"(?:Error|Expired|Exception)$|^(?:Connect|Read|Write|Pool)Timeout$")
# Libraries that apply a timeout of their own when none is given, so the call has to say `timeout=None` or a marked bound.
IMPLICIT_TIMEOUT = frozenset({
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete", "httpx.head", "httpx.options",
    "httpx.request", "httpx.stream", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "websockets.connect",
    "websockets.sync.client.connect"
})
CLOCKS = frozenset({
    "time.time", "time.monotonic", "time.perf_counter", "time.process_time", "time.thread_time", "time.time_ns",
    "time.monotonic_ns", "time.perf_counter_ns", "time.process_time_ns", "time.thread_time_ns"
})
DATETIME_CLOCK = re.compile(r"datetime\.(?:\w+\.)?(?:now|utcnow|today)$")
DYNAMIC = frozenset({"exec", "eval", "__import__", "import_module"})
SHELL_RUNNERS = frozenset({
    "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput", "shlex.split"
})
# `COMPOSE_HTTP_TIMEOUT`, `DOCKER_CLIENT_TIMEOUT`: a timeout set through the environment of a child.
ENV_TIMEOUT = re.compile(r"[A-Z][A-Z0-9_]*(?:TIMEOUT|DEADLINE)[A-Z0-9_]*$")
SHELL_WAIT = re.compile(r"\b(?:sleep|usleep|timeout|gtimeout)\b|\s--?[\w-]*timeout", re.IGNORECASE)
ARGV_PROGRAMS = frozenset({"sleep", "usleep", "timeout", "gtimeout"})
ARGV_OPTION = re.compile(r"-{1,2}[\w-]*(?:timeout|max-time|deadline)[\w-]*(?:=.*)?$", re.IGNORECASE)
# Programs whose short options are timeouts: `docker stop -t 5`, `curl -m 5`.
ARGV_SHORT = {"docker": frozenset({"-t", "--time"}), "curl": frozenset({"-m"})}
# Method names whose positional arguments past the first `n` are a timeout.
EXTRA_POSITIONAL = {"wait_for": 2, "communicate": 2, "acquire": 2, "put": 3}
NO_POSITIONAL = frozenset({"wait", "result", "poll", "select"})
# Resolved names that look like the methods above but take something else as their first argument.
NOT_A_TIMEOUT = frozenset({"asyncio.wait", "select.select"})
RESOLVED_POSITIONAL = {
    "socket.create_connection": 2, "urllib.request.urlopen": 3, "select.select": 4, "concurrent.futures.wait": 2,
    "multiprocessing.connection.wait": 2
}
TEXT_ANNOTATIONS = frozenset({"str", "bytes"})
TEXT_MODULES = frozenset({"os.path", "posixpath", "ntpath", "path"})
LOOPS = (ast.While, ast.For, ast.AsyncFor)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.message}"


@dataclass(frozen=True)
class Marker:
    path: str
    line: int
    event: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.event}"


def is_none(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def is_text(node: ast.expr) -> bool:
    return isinstance(node,
                      (ast.JoinedStr, )) or (isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)))


# One file =============================================================================================================


class Module(ast.NodeVisitor):
    """The findings of one source file, and the markers they used."""

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.tree = ast.parse(source, path)
        self.findings: list[Finding] = []
        self.markers: dict[int, str] = {}
        self.comment_only: set[int] = set()
        self.used: set[int] = set()
        self.parents: dict[ast.AST, ast.AST] = {}
        self.aliases: dict[str, str] = {}
        self.constants: dict[str, ast.stmt] = {}
        self.loops = 0
        self.whiles = 0
        self.scan_comments(source)
        self.index()

    # Setup ------------------------------------------------------------------------------------------------------------

    def scan_comments(self, source: str) -> None:
        code_lines: set[int] = set()
        comments: dict[int, str] = {}
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comments[token.start[0]] = token.string
            elif token.type not in {
                tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER
            }:
                code_lines.update(range(token.start[0], token.end[0] + 1))
        self.comment_only = set(comments) - code_lines
        for line, text in comments.items():
            if found := MARKER.match(text):
                self.markers[line] = found.group(1)

    def index(self) -> None:
        for parent in ast.walk(self.tree):
            for child in ast.iter_child_nodes(parent):
                self.parents[child] = parent
            if isinstance(parent, ast.Import):
                for name in parent.names:
                    self.aliases[name.asname
                                 or name.name.split(".")[0]] = name.name if name.asname else name.name.split(".")[0]
            elif isinstance(parent, ast.ImportFrom) and parent.module and not parent.level:
                for name in parent.names:
                    self.aliases[name.asname or name.name] = f"{parent.module}.{name.name}"
        for statement in self.tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        self.constants[target.id] = statement
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                self.constants[statement.target.id] = statement

    # Names ------------------------------------------------------------------------------------------------------------

    def resolve(self, node: ast.expr) -> str | None:
        """The dotted name `node` refers to through this file's imports, or None if it is not a plain name chain."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return None if base is None else f"{base}.{node.attr}"
        return None

    @staticmethod
    def final_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    # Markers ----------------------------------------------------------------------------------------------------------

    def statement_of(self, node: ast.AST) -> ast.stmt | None:
        while node in self.parents:
            node = self.parents[node]
            if isinstance(node, ast.stmt):
                return node
        return None

    def span_of(self, statement: ast.stmt) -> range:
        """The lines of a simple statement, or only the header of a compound one: its body is other statements."""
        first = min([statement.lineno, *(d.lineno for d in getattr(statement, "decorator_list", []))])
        body = getattr(statement, "body", None)
        if isinstance(body, list) and body:
            return range(first, max(body[0].lineno, first + 1))
        return range(first, (statement.end_lineno or statement.lineno) + 1)

    def marker_on(self, statement: ast.stmt) -> int | None:
        span = self.span_of(statement)
        for line in span:
            if line in self.markers:
                return line
        line = span.start - 1
        while line in self.comment_only:
            if line in self.markers:
                return line
            line -= 1
        return None

    def exempt(self, node: ast.AST, value: ast.expr | None = None) -> bool:
        """Whether a marker covers `node`'s statement, or the constant `value` names; the marker is then used up."""
        statement = self.statement_of(node)
        if statement is not None and (line := self.marker_on(statement)) is not None:
            self.used.add(line)
            return True
        if isinstance(value, ast.Name) and value.id in self.constants:
            if (line := self.marker_on(self.constants[value.id])) is not None:
                self.used.add(line)
                return True
        return False

    def report(
        self, node: ast.AST, rule: str, message: str, *, value: ast.expr | None = None, exempt: bool = True
    ) -> None:
        if exempt and self.exempt(node, value):
            return
        hint = " (add `# external-bound: <event>` only for an external event)" if exempt else ""
        self.findings.append(Finding(self.path, getattr(node, "lineno", 0), rule, message + hint))

    # Visitors ---------------------------------------------------------------------------------------------------------

    def visit_loop(self, node: ast.AST) -> None:
        self.loops += 1
        self.whiles += isinstance(node, ast.While)
        self.generic_visit(node)
        self.loops -= 1
        self.whiles -= isinstance(node, ast.While)

    visit_While = visit_For = visit_AsyncFor = visit_loop

    def visit_Name(self, node: ast.Name) -> None:
        self.check_reference(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.check_reference(node)
        self.generic_visit(node)

    def check_reference(self, node: ast.Name | ast.Attribute) -> None:
        if not isinstance(node.ctx, ast.Load):
            return
        name = self.resolve(node)
        if name in BANNED_REFERENCES:
            self.report(node, "banned-reference", f"{name} waits on the clock", exempt=name not in NEVER_EXEMPT)
        elif self.final_name(node) == "WNOHANG":
            self.report(node, "banned-reference", "WNOHANG polls instead of waiting", exempt=False)

    def visit_Import(self, node: ast.Import) -> None:
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for name in node.names:
            full = f"{node.module}.{name.name}" if node.module and not node.level else name.name
            if full in BANNED_REFERENCES:
                self.report(node, "banned-reference", f"importing {full}", exempt=full not in NEVER_EXEMPT)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.check_assigned_attribute(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.check_assigned_attribute([node.target], node.value, node)
        self.generic_visit(node)

    def check_assigned_attribute(self, targets: Iterable[ast.expr], value: ast.expr, node: ast.stmt) -> None:
        for target in targets:
            if isinstance(target, ast.Attribute) and TIMEOUT_WORD.search(target.attr) and not is_none(value):
                self.report(node, "timeout-assignment", f"sets {target.attr}", value=value)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key in node.keys:
            self.check_environment_key(key)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.check_environment_key(node.slice)
        self.generic_visit(node)

    def check_environment_key(self, node: ast.expr | None) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and ENV_TIMEOUT.match(node.value):
            self.report(node, "env-timeout", f"{node.value} sets a timeout through the environment")

    def visit_List(self, node: ast.List) -> None:
        self.check_argv(node)
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self.check_argv(node)
        self.generic_visit(node)

    def check_argv(self, node: ast.List | ast.Tuple) -> None:
        texts = [
            element.value for element in node.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        ]
        if node.elts and isinstance(node.elts[0], ast.Constant) and node.elts[0].value in ARGV_PROGRAMS:
            self.report(node, "argv-wait", f"runs `{node.elts[0].value}`", exempt=node.elts[0].value == "timeout")
        for element in node.elts:
            if isinstance(element, ast.JoinedStr) and element.values and isinstance(element.values[0], ast.Constant):
                head = element.values[0].value
                if isinstance(head, str) and ARGV_OPTION.match(head.split("=")[0]):
                    self.report(element, "argv-timeout", f"passes {head.split('=')[0]}")
        for text in texts:
            if ARGV_OPTION.match(text):
                self.report(node, "argv-timeout", f"passes {text}")
        for program, options in ARGV_SHORT.items():
            if program in texts:
                for text in texts:
                    if text in options:
                        self.report(node, "argv-timeout", f"passes {text} to {program}")

    def visit_Call(self, node: ast.Call) -> None:
        self.check_call(node)
        self.generic_visit(node)

    def check_call(self, node: ast.Call) -> None:
        name = self.final_name(node.func)
        resolved = self.resolve(node.func)
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        if name is None:
            return
        if name in DYNAMIC:
            self.report(node, "dynamic", f"{name}() hides what runs from this check", exempt=False)
        if name in BANNED_NAMES and resolved not in BANNED_REFERENCES:
            self.report(node, "sleep", f"{name}() waits on the clock", exempt=False)
        self.check_clock(node, resolved)
        for keyword in node.keywords:
            if keyword.arg and TIMEOUT_WORD.search(keyword.arg) and not is_none(keyword.value):
                self.report(node, "timeout-argument", f"{keyword.arg}= given to {name}()", value=keyword.value)
            if keyword.arg is None and isinstance(keyword.value, ast.Dict):
                for key in keyword.value.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and TIMEOUT_WORD.search(key.value):
                        self.report(node, "timeout-argument", f"{key.value!r} unpacked into {name}()")
        if resolved in IMPLICIT_TIMEOUT and not any(keyword.arg == "timeout" for keyword in node.keywords):
            self.report(node, "implicit-timeout", f"{resolved}() applies its own default timeout", exempt=True)
        if (
            TIMEOUT_WORD.search(name) and not TIMEOUT_EXCEPTION.search(name)
            and not (arguments and all(is_none(argument) for argument in arguments))
        ):
            self.report(node, "timeout-call", f"{name}() sets a timeout", value=node.args[0] if node.args else None)
        if name == "getattr" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            looked_up = node.args[1].value
            if isinstance(looked_up, str) and (looked_up in BANNED_NAMES or TIMEOUT_WORD.search(looked_up)):
                self.report(node, "dynamic", f"getattr(..., {looked_up!r}) reaches a wait by name", exempt=False)
        if resolved in SHELL_RUNNERS and node.args and isinstance(node.args[0], ast.Constant):
            command = node.args[0].value
            if isinstance(command, str) and SHELL_WAIT.search(command):
                self.report(node, "argv-wait", "runs a shell command that sleeps or sets a timeout")
        for argument in node.args:
            self.check_environment_key(argument)
        if isinstance(node.func, ast.Attribute):
            self.check_method(node, node.func)
        if resolved in RESOLVED_POSITIONAL and len(node.args) >= RESOLVED_POSITIONAL[resolved]:
            self.report(node, "timeout-argument", f"{resolved}() given a timeout positionally")

    def check_method(self, node: ast.Call, func: ast.Attribute) -> None:
        method, positional = func.attr, node.args
        resolved = self.resolve(func)
        if method in NO_POSITIONAL and resolved not in NOT_A_TIMEOUT | RESOLVED_POSITIONAL.keys() and positional:
            self.report(node, "timed-wait", f".{method}() given an argument, which is a timeout")
        if method in EXTRA_POSITIONAL and len(positional) >= EXTRA_POSITIONAL[method]:
            self.report(node, "timed-wait", f".{method}() given a timeout positionally")
        if method == "get" and len(positional) >= 2 and isinstance(positional[0], ast.Constant
                                                                   ) and isinstance(positional[0].value, bool):
            self.report(node, "timed-wait", ".get(block, timeout) given a timeout")
        if method == "join" and positional and not self.joins_text(func, positional[0]):
            self.report(node, "timed-wait", ".join(x) on something not known to be text: `Thread.join(5)` is a timeout")

    def joins_text(self, func: ast.Attribute, argument: ast.expr) -> bool:
        """`sep.join(parts)` and `os.path.join(...)`, as against `thread.join(seconds)`."""
        receiver = func.value
        if is_text(receiver) or self.resolve(receiver) in TEXT_MODULES:
            return True
        if isinstance(receiver, ast.Name) and self.annotated_text(receiver):
            return True
        text_producers = (ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.List, ast.Tuple, ast.Set, ast.Dict)
        return isinstance(argument, text_producers)

    def annotated_text(self, name: ast.Name) -> bool:
        """Whether `name` is a parameter annotated `str`/`bytes`, or assigned a string literal, where it is used."""
        scope: ast.AST | None = self.parents.get(name)
        while scope is not None:
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                parameters = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
                for parameter in parameters:
                    annotation = getattr(parameter, "annotation", None)
                    if parameter.arg == name.id and isinstance(
                        annotation, ast.Name
                    ) and annotation.id in TEXT_ANNOTATIONS:
                        return True
            for child in ast.walk(scope):
                if isinstance(child, ast.Assign) and is_text(child.value):
                    if any(isinstance(target, ast.Name) and target.id == name.id for target in child.targets):
                        return True
            scope = self.parents.get(scope)
        return False

    def check_clock(self, node: ast.Call, resolved: str | None) -> None:
        if resolved in CLOCKS:
            parent = self.parents.get(node)
            if self.loops:
                self.report(
                    node, "clock-loop", f"{resolved}() inside a loop is polling against the clock", exempt=False
                )
            elif isinstance(parent, (ast.BinOp, ast.Compare)):
                self.report(
                    node,
                    "clock-arithmetic",
                    f"{resolved}() added to or compared with something is a deadline",
                    exempt=False
                )
        elif resolved is not None and DATETIME_CLOCK.search(resolved) and self.whiles:
            self.report(
                node, "clock-loop", f"{resolved}() inside a while loop is polling against the clock", exempt=False
            )

    # Result -----------------------------------------------------------------------------------------------------------

    def check(self) -> tuple[list[Finding], list[Marker]]:
        self.visit(self.tree)
        for line, event in sorted(self.markers.items()):
            if not event:
                self.findings.append(Finding(self.path, line, "marker", "`external-bound:` names no event"))
            elif line not in self.used:
                self.findings.append(Finding(self.path, line, "marker", f"`external-bound: {event}` exempts nothing"))
        used = [Marker(self.path, line, self.markers[line]) for line in sorted(self.used)]
        return sorted(self.findings, key=lambda finding: finding.line), used


# Driver ===============================================================================================================


def check_source(path: str, source: str) -> tuple[list[Finding], list[Marker]]:
    try:
        return Module(path, source).check()
    except (SyntaxError, tokenize.TokenError) as exc:
        return [Finding(path, getattr(exc, "lineno", None) or 0, "unparsable", f"cannot check this file: {exc}")], []


def python_files(targets: Sequence[Path]) -> Iterator[Path]:
    for target in targets:
        if target.is_dir():
            yield from sorted(path for path in target.rglob("*.py") if ".venv" not in path.parts)
        elif target.suffix == ".py":
            yield target
        else:
            raise SystemExit(f"{target}: not a directory or a .py file")


def check_paths(targets: Sequence[Path], root: Path = ROOT) -> tuple[list[Finding], list[Marker]]:
    findings: list[Finding] = []
    markers: list[Marker] = []
    for path in python_files(targets):
        shown = path.relative_to(root).as_posix() if path.is_relative_to(root) else path.as_posix()
        found, used = check_source(shown, path.read_text(encoding="utf-8"))
        findings += found
        markers += used
    return findings, markers


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail on sleeps, timeouts and clock polling in Python code.")
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories (default: the whole project)")
    parser.add_argument("--markers", action="store_true", help="list every marker that exempted something")
    args = parser.parse_args(argv)
    targets = args.paths or [ROOT / name for name in TARGETS]
    findings, markers = check_paths(targets)
    for finding in findings:
        print(finding)
    if args.markers:
        for marker in markers:
            print(f"external-bound {marker}")
    if findings:
        print(
            f"{len(findings)} timed wait(s); block on an event instead, see scripts/no-timed-waits.py", file=sys.stderr
        )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
