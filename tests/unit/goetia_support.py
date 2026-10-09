"""A stand-in for the goetia executable: a real child process that records its argv and prints scripted answers.

`ctl.goetia` runs whatever `command(root)` names, so the fake is run through the current interpreter. It is a
subprocess like the real thing, so exit statuses, stdout and stderr travel the same way.
"""

import json
import sys
from pathlib import Path

SCRIPT = '''
import json, os, sys

state = sys.argv[1]
args = sys.argv[2:]
logs = None
if os.path.isdir("logs"):
    status = os.stat("logs")
    logs = {"uid": status.st_uid, "mode": status.st_mode & 0o7777}
with open(state + "/calls.jsonl", "a", encoding="utf-8") as calls:
    calls.write(json.dumps({"args": args, "logs": logs}) + "\\n")
with open(state + "/rules.json", encoding="utf-8") as rules:
    for rule in json.load(rules):
        if all(token in args for token in rule["match"]):
            sys.stdout.write(rule["stdout"])
            sys.stderr.write(rule["stderr"])
            sys.exit(rule["exit"])
verb = args[1] if len(args) > 1 else ""
if verb in ("install", "start", "stop", "restart", "uninstall", "enable", "disable"):
    sys.exit(0)
sys.stderr.write("unscripted goetia call: " + " ".join(args))
sys.exit(99)
'''

ERROR_KINDS = (
    "not-installed", "foreign", "unreadable", "undetermined", "invalid-id", "unavailable", "unsupported", "other"
)


def envelope(daemons=(), errors=(), undetermined=()) -> str:
    """goetia's `--json` document, as one compact line."""
    return json.dumps({"daemons": list(daemons), "errors": list(errors), "undetermined": list(undetermined)}) + "\n"


def daemon(daemon_id: str, state: str = "running", enabled: bool = True, pid: int | None = 4242) -> dict:
    return {"id": daemon_id, "state": state, "enabled": enabled, "pid": pid}


def error(kind: str, daemon_id: str | None = None, message: str = "scripted") -> dict:
    return {"id": daemon_id, "kind": kind, "message": message}


class FakeGoetia:
    """Scripted answers keyed by argv tokens; the first rule whose tokens all appear in a call answers it.

    Mutating verbs succeed unless a rule says otherwise. `list`, `status` and `show` must be scripted: an unscripted
    call exits 99, so a test cannot pass by accident on an answer nobody wrote.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "fake_goetia.py").write_text(SCRIPT, encoding="utf-8")
        (directory / "calls.jsonl").write_text("", encoding="utf-8")
        self._rules: list[dict] = []
        self._write()

    @property
    def command(self) -> list[str]:
        return [sys.executable, str(self.directory / "fake_goetia.py"), str(self.directory)]

    def _write(self) -> None:
        (self.directory / "rules.json").write_text(json.dumps(self._rules), encoding="utf-8")

    def forget(self, *match: str) -> None:
        """Drop the rules whose tokens are exactly `match`, so a later call is answered by the default or a later rule."""
        self._rules = [rule for rule in self._rules if rule["match"] != list(match)]
        self._write()

    def on(self, *match: str, stdout: str = "", stderr: str = "", exit: int = 0) -> None:
        self._rules.append({"match": list(match), "stdout": stdout, "stderr": stderr, "exit": exit})
        self._write()

    def status(self, *daemons: dict, errors=(), undetermined=(), exit: int = 0) -> None:
        self.on("status", stdout=envelope(daemons, errors, undetermined), exit=exit)

    def spec(self, daemon_id: str, *, installed: str, manifest: str | None = None) -> None:
        """What `show` renders for `daemon_id` from what is installed and from the manifest (the same by default)."""
        self.on("show", "-f", daemon_id, stdout=installed if manifest is None else manifest)
        self.on("show", daemon_id, stdout=installed)

    @property
    def records(self) -> list[dict]:
        """Each call with what the child saw of the working directory it was started in: its `logs/`, if any."""
        lines = (self.directory / "calls.jsonl").read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    @property
    def calls(self) -> list[list[str]]:
        return [record["args"] for record in self.records]

    def verbs(self) -> list[str]:
        return [call[1] for call in self.calls]

    def calls_of(self, verb: str) -> list[list[str]]:
        return [call for call in self.calls if call[1] == verb]

    def mutations(self) -> list[tuple[str, str]]:
        """Every call that changes something, as (verb, daemon id) in the order made."""
        changing = ("install", "start", "stop", "restart", "uninstall", "enable", "disable")
        return [(call[1], call[-1]) for call in self.calls if call[1] in changing]
