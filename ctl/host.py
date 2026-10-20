# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""The host role: frpc and websocat as two goetia-managed daemons, installed without cutting your own ssh session.

Hosts are reachable only through the tunnel, so `install` is three phases and the order is the safety:

- `preflight` changes nothing. It checks the accounts, asks goetia what is installed, and decides what to touch.
- `stage` changes things that disturb nothing: directories, the token, the downloaded and verified binaries.
- `apply` is the disruptive part: replace binaries, install units, restart.

A daemon is scheduled when any of four things holds, because each is a way for a running process to differ from what
the tree says: its binary is not the pinned one; its installed unit differs from the manifest; a file it reads once at
startup (the token, `host/frpc.toml`) changed; or goetia does not report it running and enabled. `bin/.digests.json`
records what the live processes were started with and is rewritten last, so a failure part-way leaves them looking
stale and a rerun finishes the job.
"""

import contextlib
import dataclasses
import hashlib
import io
import os
import sys
from collections.abc import Callable, Generator, Mapping
from pathlib import Path

from ctl import access, atomic, binaries, detach, goetia, handshake, lock, perms
from ctl.atomic import read_file, replace_file
from ctl.binaries import Pin
from ctl.config import Config, Role
from ctl.download import DIGESTS, describe_install, read_digests, record_digests
from ctl.errors import BinariesError, InstallError
from ctl.goetia import DaemonState, GoetiaError
from ctl.perms import Account, AccountMode
from ctl.removal import remove_directory
from ctl.services import Services
from ctl.session import assess

FRPC_ID = "reverse-tunnel-frpc"
WEBSOCAT_ID = "reverse-tunnel-websocat"
IDS = (FRPC_ID, WEBSOCAT_ID)

# Promotion order: goetia first, so a rerun after an interruption can already ask it what is installed.
HOST_BINARIES = ("goetia", "goetia-shim", "frpc", "websocat")
RUNS = {FRPC_ID: ("frpc", ), WEBSOCAT_ID: ("websocat", )}
# Read once at startup, so changing one means nothing until the daemon restarts. Keys of `bin/.digests.json`.
READS = {FRPC_ID: ("token", "frpc.toml")}

# Windows refuses to replace a running executable; POSIX replaces the file and the process keeps its inode.
STOP_BEFORE_REPLACE = sys.platform == "win32"
SECRETS_MODE, LOGS_MODE, BIN_MODE, STAGING_MODE = 0o711, 0o750, 0o755, 0o700
RECORD_MODE, LOG_MODE = 0o644, 0o640
STAGING = ".staging"
LOG = "install.log"
NOT_CARRYING_A_SESSION = ("stopped", "failed")  # states in which a daemon certainly carries no session

# Plan =================================================================================================================


@dataclasses.dataclass(frozen=True)
class Plan:
    binaries_to_replace: tuple[str, ...]  # install names whose file is missing or not the pinned one
    daemons_to_converge: tuple[str, ...]
    mode: AccountMode
    platform: str
    pins: tuple[Pin, ...]  # every binary a host runs, in promotion order
    bundle: Pin | None  # goetia's Sigstore bundle
    installed: tuple[str, ...]  # the daemons goetia reports installed
    detach: bool  # the apply phase must outlive this session
    inputs: Mapping[str, str]  # digests of the files the daemons will have read when started
    reasons: Mapping[str, str]  # why each scheduled daemon is


def _base(install_name: str) -> str:
    return install_name.removesuffix(".exe")


def _binaries_of(daemon_id: str, platform: str) -> tuple[str, ...]:
    """The base names of the files a daemon is started from. On Windows that includes goetia's service shim."""
    return RUNS[daemon_id] + (("goetia-shim", ) if platform.startswith("windows") else ())


def _host_pins(services: Services) -> tuple[tuple[Pin, ...], Pin | None, str]:
    lock = binaries.load_lock(services.lock_path)
    platform = services.platform or binaries.current_platform()
    found = {
        _base(pin.install_name): pin
        for tool in binaries.tools_for_role(Role.HOST)
        for pin in binaries.pins_for(lock, tool, platform)
    }
    missing = [name for name in HOST_BINARIES if name not in found]
    if missing:
        raise BinariesError(f"the lock pins no {', '.join(missing)} for {platform}")
    return tuple(found[name] for name in HOST_BINARIES), binaries.bundle_for(lock, "goetia"), platform


def _token_bytes(config: Config) -> bytes:
    return config.require("RT_TOKEN").encode("ascii") + b"\n"


def token_digest(config: Config) -> str:
    return hashlib.sha256(_token_bytes(config)).hexdigest()


def frpc_toml_digest(root: Path) -> str:
    toml = read_file(root / "host", "frpc.toml")
    if toml is None:
        raise InstallError(f"{root / 'host' / 'frpc.toml'} is missing; restore it from the repository")
    return hashlib.sha256(toml).hexdigest()


def input_digests(config: Config) -> dict[str, str]:
    """The digests `bin/.digests.json` records for the files the daemons read once at startup."""
    return {"token": token_digest(config), "frpc.toml": frpc_toml_digest(config.root)}


def _digest_on_disk(bin_dir: Path, name: str) -> str | None:
    content = read_file(bin_dir, name)  # refuses a link; None when absent
    return None if content is None else hashlib.sha256(content).hexdigest()


@dataclasses.dataclass(frozen=True)
class Observed:
    """What goetia says is installed. `certain` is false when it could not be asked although daemons may exist."""

    states: Mapping[str, DaemonState]
    current: Mapping[str, bool]
    certain: bool

    def may_be_serving(self, daemon_id: str) -> bool:
        if not self.certain:
            return True
        state = self.states.get(daemon_id)
        return state is not None and state.state not in NOT_CARRYING_A_SESSION


def _has_traces(root: Path) -> bool:
    """Whether anything shows that an install ever got as far as changing this tree.

    Without a goetia to ask, "nothing is installed" is believable only of a tree that was never installed: `rm -rf bin`
    leaves `secrets/` and `logs/` behind and the daemons it installed may be running. `bin/.staging` alone is not a trace,
    and neither is a lock file or a log. Not detected, and accepted: an operator who deletes `bin/`, `secrets/` and `logs/`
    by hand while the units still run. docs/troubleshooting.md says so.
    """
    if any(os.path.lexists(root / name) for name in ("secrets", "logs")):
        return True
    bin_dir = root / "bin"
    if not os.path.lexists(bin_dir):
        return False
    if bin_dir.is_symlink() or not bin_dir.is_dir():
        return True
    return any(entry != STAGING for entry in os.listdir(bin_dir))


def _observe(root: Path, *, specs: bool = True) -> Observed:
    if not goetia.available(root):
        return Observed({}, {}, certain=not _has_traces(root))
    states = {state.id: state for state in goetia.daemon_status(root, IDS)}
    current = {daemon_id: goetia.spec_is_current(root, daemon_id) for daemon_id in states} if specs else {}
    return Observed(states, current, certain=True)


def _reasons(
    daemon_id: str, observed: Observed, record: Mapping[str, str], inputs: Mapping[str, str], pins: Mapping[str, Pin],
    replacing: set[str], platform: str
) -> list[str]:
    reasons = []
    stale = [
        name for name in _binaries_of(daemon_id, platform)
        if pins[name].install_name in replacing or record.get(pins[name].install_name) != pins[name].member_sha256
    ]
    if stale:
        reasons.append(f"binary changed ({', '.join(stale)})")
    state = observed.states.get(daemon_id)
    if state is None:
        reasons.append("not installed" if observed.certain else "goetia is missing, so it cannot be shown installed")
    else:
        if not observed.current[daemon_id]:
            reasons.append("its installed unit differs from goetia.yaml (spec)")
        if state.state != "running":
            reasons.append(f"state is {state.state}")
        if not state.enabled:
            reasons.append("not enabled")
    reasons += [f"{name} changed" for name in READS.get(daemon_id, ()) if record.get(name) != inputs[name]]
    return reasons


def preflight(config: Config, *, services: Services, allow_self_disconnect: bool = False) -> Plan:
    """Decide what an install would touch. Changes nothing; refuses, having changed nothing, if it is not safe."""
    if config.role is not Role.HOST:
        raise InstallError(f"ROLE=host is required; this deployment is ROLE={config.role}")
    root = config.root
    service = perms.service_account(config)
    access.verify_traversable(root, service)
    access.refuse_service_writable(root, service)
    mode = perms.account_mode(root, service)

    pins, bundle, platform = _host_pins(services)
    by_base = {_base(pin.install_name): pin for pin in pins}
    record = read_digests(root / "bin")
    inputs = input_digests(config)
    replacing = {
        pin.install_name
        for pin in pins if _digest_on_disk(root / "bin", pin.install_name) != pin.member_sha256
    }
    observed = _observe(root)

    reasons = {
        daemon_id: _reasons(daemon_id, observed, record, inputs, by_base, replacing, platform)
        for daemon_id in IDS
    }
    scheduled = tuple(daemon_id for daemon_id in IDS if reasons[daemon_id])
    detach = _check_session(scheduled, observed, allow_self_disconnect)
    return Plan(
        binaries_to_replace=tuple(pin.install_name for pin in pins if pin.install_name in replacing),
        daemons_to_converge=scheduled,
        mode=mode,
        platform=platform,
        pins=pins,
        bundle=bundle,
        installed=tuple(observed.states),
        detach=detach,
        inputs=inputs,
        reasons={daemon_id: "; ".join(reasons[daemon_id])
                 for daemon_id in scheduled},
    )


# The self-disconnect guard ============================================================================================


def session_is_provably_safe() -> bool:
    """Whether this process was started from an ssh session whose client is not on loopback."""
    return assess().safe


def _check_session(scheduled: tuple[str, ...], observed: Observed, allowed: bool, action: str = "restart") -> bool:
    """Refuse unless touching the scheduled daemons is provably safe; return whether the work must be detached.

    A session through the tunnel rides frps, frpc, websocat and sshd, so touching frpc drops it exactly as touching
    websocat does. It is safe when no scheduled daemon may be carrying a session, or the session is provably off the
    tunnel. The proof is asked for because its absence is the common case: `sudo` strips `SSH_CONNECTION`. Evaluated
    before anything is changed, so a refusal leaves the tree as it was: aborting half way would leave it half done, and
    skipping one daemon would leave its unit rewritten and its process not.
    """
    serving = [daemon_id for daemon_id in scheduled if observed.may_be_serving(daemon_id)]
    if not serving:
        return False
    verdict = assess()
    if verdict.safe:
        return False
    if not allowed:
        raise InstallError(
            f"this would {action} {' and '.join(serving)}, which this session may be running over, and it cannot be "
            f"shown that it is not: {verdict.reason}. Nothing has been changed. Either run it from the machine itself "
            "or from a session that does not come through the tunnel (over ssh, keep the variable through sudo: "
            "`sudo --preserve-env=SSH_CONNECTION ...`, if sudo's policy allows it), or pass --allow-self-disconnect to "
            f"run it detached from this session, with its output in {LOG}"
        )
    return True


# Stage ================================================================================================================


def _service_readers(root: Path) -> frozenset[str]:
    """The Windows principals that read `secrets/`: the service, and the operator, who runs doctor. POSIX has modes."""
    if sys.platform != "win32":
        return frozenset()
    from ctl import perms_windows

    return frozenset({perms.SID_LOCAL_SERVICE, perms_windows.operator_sid(root)})


def _installer() -> Account | None:
    """The account running this install, which owns `bin/`: root, since a host install is always elevated.

    `bin/` is the installer's rather than the operator's, stricter than the ownership table (which leaves the directory
    to whoever cloned the repository): what root executes must not be replaceable by anyone else. Windows: `None`, the
    directory inherits.
    """
    if sys.platform == "win32":
        return None
    import pwd

    uid = os.geteuid()
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    return Account(name, uid, os.getegid())


def _converge_bin(root: Path, service: Account) -> None:
    """Converge `bin/`, its DACL written once with the service's ACE in it: nothing between this and the grant that
    follows can leave the directory the service reads without it."""
    perms.converge_dir(
        root / "bin", _installer(), BIN_MODE, frozenset(), isolate=False, service_read=service, root=root
    )


def _clear_staging(root: Path) -> None:
    """Remove `bin/.staging` and what it holds, if it exists."""
    bin_dir = root / "bin"
    if os.path.lexists(bin_dir / STAGING):
        remove_directory(bin_dir, STAGING)


def stage(config: Config, plan: Plan, *, services: Services) -> None:
    """Make the tree ready without disturbing anything running. The order matters.

    Whatever a failed run left in `bin/.staging` goes first: on Windows `grant_service_read` refuses a subdirectory of
    `bin\\`. `bin/` is converged before that grant and never again, with the service's ACE in the same write:
    converging rewrites its whole ACL. `secrets/` and `logs/` come before the token, which is created inside the first,
    and goetia must never be handed a `logs/` owned by root. `.env` is tightened last, after everything that could
    fail.
    """
    root = config.root
    service = perms.service_account(config)
    readers = _service_readers(root)
    _clear_staging(root)
    _converge_bin(root, service)
    perms.converge_dir(root / "secrets", service, SECRETS_MODE, readers, root=root)
    perms.converge_tree(root / "logs", service, LOGS_MODE, root=root)
    perms.write_secret(root / "secrets" / "token", _token_bytes(config), service, readers, root=root)
    perms.grant_service_read(root, service)
    _download(root, plan, services)
    perms.harden_file(root / ".env", None, frozenset(), root=root)


def _download(root: Path, plan: Plan, services: Services) -> None:
    if not plan.binaries_to_replace:
        return
    staging = root / "bin" / STAGING
    try:
        perms.converge_dir(staging, _installer(), STAGING_MODE, frozenset(), isolate=False, root=root)
        with services.fetcher() as fetch:
            for pin in plan.pins:
                if pin.install_name in plan.binaries_to_replace:
                    bundle = plan.bundle if pin.tool == "goetia" else None
                    print(describe_install(pin, fetch.fetch(pin, staging, bundle)))
    except BaseException:
        _clear_staging_quietly(root)
        raise


def _clear_staging_quietly(root: Path) -> None:
    """Clear `bin/.staging` on the way out of a failure, without letting a second failure hide the first."""
    try:
        _clear_staging(root)
    except InstallError as exc:
        print(f"warning: {exc}", file=sys.stderr)


# Apply ================================================================================================================


def _step(description: str, action: Callable[..., None], *args, **kwargs) -> None:
    try:
        action(*args, **kwargs)
    except GoetiaError as exc:
        raise InstallError(f"{description}: {exc}") from exc


def _promote(root: Path, plan: Plan, service: Account) -> None:
    """Replace each binary in `bin/` with its staged, pinned bytes, the service's read already on the new file.

    A file created in `bin\\` has no ACE for the service: the one `grant_service_read` wrote to its parent is not
    inheritable. So the grant is made on the temporary file, before the rename, and the final name never exists
    without it.
    """
    bin_dir, staging = root / "bin", root / "bin" / STAGING
    for pin in plan.pins:
        if pin.install_name not in plan.binaries_to_replace:
            continue
        content = read_file(staging, pin.install_name)
        if content is None:
            raise InstallError(
                f"{staging / pin.install_name} is missing: the staged binaries are gone. Run `ctl install` again"
            )
        if hashlib.sha256(content).hexdigest() != pin.member_sha256:
            raise BinariesError(
                f"{staging / pin.install_name} is not the pinned {pin.install_name}; it was changed after staging"
            )
        replace_file(bin_dir, pin.install_name, io.BytesIO(content), BIN_MODE, service=service)


def apply(config: Config, plan: Plan, *, services: Services) -> None:
    """Replace the binaries, install and restart exactly the scheduled daemons, then record what they now run.

    `install` is run per id and never without one: with none, goetia installs every daemon in the manifest, so an
    unscheduled websocat would get a rewritten unit and a process still running the old one, a divergence nothing
    afterwards detects. Each id is restarted because `install` writes and enables but never starts. `bin/.staging` is
    removed whatever happens.
    """
    root, bin_dir = config.root, config.root / "bin"
    service = perms.service_account(config)
    try:
        if STOP_BEFORE_REPLACE:
            for daemon_id in plan.daemons_to_converge:
                runs = {
                    pin.install_name
                    for pin in plan.pins if _base(pin.install_name) in _binaries_of(daemon_id, plan.platform)
                }
                if daemon_id in plan.installed and runs & set(plan.binaries_to_replace):
                    _step(f"stopping {daemon_id}", goetia.daemon_stop, root, daemon_id)
        _promote(root, plan, service)
        for daemon_id in plan.daemons_to_converge:
            _step(f"installing {daemon_id}", goetia.daemon_install, root, daemon_id, enable=True)
            _step(f"restarting {daemon_id}", goetia.daemon_restart, root, daemon_id)
            print(f"{daemon_id}: installed and restarted ({plan.reasons[daemon_id]})")
        expected = {pin.install_name: pin.member_sha256 for pin in plan.pins} | dict(plan.inputs)
        if read_digests(bin_dir) != expected:
            record_digests(bin_dir, plan.pins, plan.inputs)
            perms.assign_file(bin_dir / DIGESTS, perms.operator_account(root), RECORD_MODE, root=root)
            perms.grant_service_read_file(bin_dir / DIGESTS, service)
    finally:
        _clear_staging_quietly(root)
    if not plan.daemons_to_converge:
        print("host: both daemons are current; nothing was restarted")


# The lock and the detached child ======================================================================================


@contextlib.contextmanager
def _exclusive(root: Path, command: str, inherited: int | None) -> Generator[lock.InstallLock]:
    """Hold the install lock for the whole run: take it now (never waiting), or adopt the one the parent passed down."""
    held = lock.adopt(root, inherited,
                      command=command) if inherited is not None else lock.acquire(root, command=command)
    with held:
        yield held


class Refused(InstallError):
    """The detached child will not go on. Its parent, which reads the refusal, is the one that cleans up."""


def _confirm_started(token: int | None) -> None:
    """The detached child tells its parent it holds the lock, or why it will not go on.

    Called inside the region that cleans up after a failure, so a child that cannot say so (the parent is gone) or
    cannot outlive its session ends having applied nothing.
    """
    if token is None:
        return
    problem = detach.survival_problem()
    try:
        handshake.signal(token, refusal=problem)
    except OSError as exc:
        raise InstallError(
            "the installing session ended before the detached apply could confirm it started; nothing was applied"
        ) from exc
    if problem:
        raise Refused(problem)


def _detach(config: Config, services: Services, held: lock.InstallLock, arguments: list[str]) -> int:
    """Run the rest in a process that survives this session, writing to `install.log` at the repository root.

    The log is created once, through one descriptor, and handed to the child; the lock is handed down too, so that this
    process letting go of it changes nothing. The child's pid proves nothing (under `systemd-run` it is systemd-run's),
    and neither does what `spawn` did or did not raise: a launcher can fail after the child exists. So the pipe alone
    decides. Whatever happened, the parent's write end is closed and the pipe read: a start byte means the child owns
    `bin/.staging` and this never touches it; a refusal or end of file means no child, and it is cleared here.

    Ctrl+C is held only around the spawn and closing the write end, so the pipe is in a readable state before it can
    interrupt anything. The wait itself can be interrupted, and then the outcome is simply unknown.
    """
    root = config.root
    verb = arguments[0]
    spawn_error: Exception | None = None
    pid = None
    started = False
    interrupted = False
    pipe = None
    try:
        try:
            pipe = handshake.Pipe()
        except BaseException:
            _clear_staging_quietly(root)  # no child can exist
            raise
        try:
            with atomic.deferred_interrupts():
                try:
                    command = detach.python_command([
                        *arguments, "--inherit-lock",
                        str(held.descriptor), "--started-fd",
                        str(pipe.token)
                    ])
                    with perms.open_log(root / LOG, perms.operator_account(root), LOG_MODE, root=root) as log:
                        pid = services.spawn(command, cwd=root, log=log, inherit=[held.descriptor, pipe.token])
                except Exception as exc:
                    spawn_error = exc
                pipe.close_write()
        except KeyboardInterrupt:  # held through the above, delivered by the `with`
            interrupted = True
        try:
            started = pipe.wait()
        except KeyboardInterrupt:
            print(
                f"Interrupted while waiting for the detached {verb}: outcome unknown, so nothing was cleaned up. See "
                f"{root / LOG} for a line starting `apply finished:`; do not run `ctl {verb}` again before it appears, "
                "or before you have established that the process is gone."
            )
            raise
    finally:
        if pipe is not None:
            pipe.close()
    if not started:
        _clear_staging_quietly(root)
        why = f"it refused: {pipe.refusal}" if pipe.refusal else "it exited without taking over the install"
        failure = f"; starting it raised {type(spawn_error).__name__}: {spawn_error}" if spawn_error else ""
        raise InstallError(
            f"the detached {verb} (pid {pid}) did not start: {why}{failure}. Nothing was applied. What it wrote to "
            f"{root / LOG}:\n{_tail(root / LOG)}"
        ) from spawn_error
    also = f" Starting it also raised {type(spawn_error).__name__}: {spawn_error}." if spawn_error else ""
    print(
        f"The {verb} is running detached (pid {pid}) and will finish even if this session drops. Its progress and result "
        f"are in {root / LOG}, ending in a line that starts `apply finished:`; read it once you reconnect, and do not "
        f"run `ctl {verb}` again before then.{also}"
    )
    if interrupted:
        raise KeyboardInterrupt
    if spawn_error:
        raise InstallError(
            f"starting the detached {verb} raised {type(spawn_error).__name__}: {spawn_error}, but it did start and is "
            f"running (pid {pid}); watch {root / LOG} for `apply finished:` and do not run the install again meanwhile"
        ) from spawn_error
    return 0


def _tail(path: Path, size: int = 2000) -> str:
    try:
        with open(path, "rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - size))
            return stream.read().decode(errors="replace").strip() or "(nothing)"
    except OSError as exc:
        return f"({exc.strerror or exc})"


# Entry points =========================================================================================================


def install(
    config: Config,
    *,
    allow_self_disconnect: bool,
    apply_staged: bool,
    services: Services,
    inherit_lock: int | None = None,
    started_fd: int | None = None,
) -> int:
    """Preflight, stage, apply. With `apply_staged` only the apply phase runs: it is the detached child's job.

    Whatever goes wrong after something was staged, `bin/.staging` is removed on the way out; only a successful hand-over
    to the detached child leaves it, for the child to use.
    """
    root = config.root
    with _exclusive(root, "install", inherit_lock) as held:
        try:
            _confirm_started(started_fd)
            plan = preflight(config, services=services, allow_self_disconnect=allow_self_disconnect)
            if not apply_staged:
                if plan.detach:
                    detach.check_can_detach()
                stage(config, plan, services=services)
        except Refused:
            raise
        except BaseException:
            _clear_staging_quietly(root)
            raise
        if plan.detach and not apply_staged:
            return _detach(config, services, held, ["install", "--allow-self-disconnect", "--apply-staged"])
        apply(config, plan, services=services)  # removes bin/.staging itself, whatever happens
    return 0


def _removable_state(root: Path) -> None:
    """Without goetia, uninstall can only say so. It refuses when `bin/` holds more than a failed install leaves."""
    bin_dir = root / "bin"
    if bin_dir.is_dir() and not bin_dir.is_symlink() and any(entry != STAGING for entry in os.listdir(bin_dir)):
        raise InstallError(
            f"{bin_dir} holds files but no goetia, so the installed services cannot be removed through it. Run "
            "`ctl install` to restore it, then `ctl uninstall`"
        )
    if _has_traces(root):
        print(
            "warning: there is no goetia in bin/, so services installed earlier could not be asked about and were not "
            "uninstalled; if there are any, remove them with the system's service manager (systemctl, launchctl, sc)",
            file=sys.stderr,
        )


def uninstall(
    config: Config,
    *,
    services: Services,
    allow_self_disconnect: bool = False,
    detached: bool = False,
    inherit_lock: int | None = None,
    started_fd: int | None = None,
) -> int:
    """Uninstall both services, then remove `bin/`, `logs/` and `secrets/`. Safe to repeat, whatever a failed install left.

    The units go first: they hold the logs and, on Windows, the executables open. If goetia cannot remove one, nothing is
    deleted. Stopping the daemons cuts a session that rides on them, so this has the guard of an install and, with
    `--allow-self-disconnect`, runs detached.
    """
    root = config.root
    with _exclusive(root, "uninstall", inherit_lock) as held:
        _confirm_started(started_fd)
        if goetia.available(root):
            if not detached:
                try:
                    observed = _observe(root, specs=False)
                except GoetiaError:  # what is running cannot be told, which is not the same as nothing running
                    observed = Observed({}, {}, certain=False)
                if _check_session(IDS, observed, allow_self_disconnect, "stop and remove"):
                    return _detach(config, services, held, ["uninstall", "--allow-self-disconnect", "--detached"])
            goetia.daemon_uninstall(root, IDS)
        else:
            _removable_state(root)
        if (root / "bin").is_dir():
            _clear_staging(root)
        for name in ("bin", "logs", "secrets"):
            print(f"removed {name}/" if remove_directory(root, name) else f"{name}/ is already absent")
    return 0
