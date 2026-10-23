# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Who may read `.env`, `secrets/` and `secrets/token`: each against the exact set `ctl install` gives it. On a Windows
host it also checks that the service holds an allow for what it needs and that no deny stands in the way.

Stat only, and never an open: `secrets/` is `0711` so that an unelevated operator can `stat` the token in
separate-account mode, and that grants nothing but the name's existence, mode and owner. On POSIX the expectation is an
owner and a mode; on Windows it is the set of SIDs *and the rights each holds*, built by `winacl.grants`, the function
the installer builds the ACL with, so a token ACE widened from `(R)` to `(F)` is a failure even though no new SID appears.
"""

from collections.abc import Mapping
from pathlib import Path

from ctl import host, perms, winacl
from ctl.config import Config, ConfigError, Role
from ctl.doctor.model import Verdict, fail, not_applicable, ok
from ctl.doctor.probes import Probes
from ctl.perms import PermsError

ENV_MODE, SECRETS_MODE, TOKEN_MODE = 0o600, 0o711, 0o600
INSTALL = "run `ctl install` to restore it"
INHERITANCE = winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE
INHERITANCE_FLAGS = INHERITANCE | winacl.NO_PROPAGATE_INHERIT_ACE
INHERIT_TOKENS = (
    (winacl.OBJECT_INHERIT_ACE, "(OI)"),
    (winacl.CONTAINER_INHERIT_ACE, "(CI)"),
    (winacl.NO_PROPAGATE_INHERIT_ACE, "(NP)"),
    (winacl.INHERIT_ONLY_ACE, "(IO)"),
)
SID_NAMES = {
    winacl.SID_ADMINISTRATORS: "Administrators",
    winacl.SID_LOCAL_SERVICE: "LocalService",
    winacl.SID_EVERYONE: "Everyone",
    winacl.SID_USERS: "Users",
    winacl.SID_AUTHENTICATED_USERS: "Authenticated Users",
}
RIGHTS = {
    winacl.FULL: "F",
    winacl.MODIFY: "M",
    winacl.READ_EXECUTE: "RX",
    winacl.READ: "R",
    winacl.READ_WRITE: "R,W",
    winacl.READ_WRITE_DELETE: "R,W,D",
    winacl.LIST_AND_ADD: "list,add",
    winacl.APPEND: "append",
}

Ace = tuple[str, int, int]  # sid, rights mask, inheritance flags


def _describe(ace: Ace) -> str:
    sid, mask, flags = ace
    name = f" ({SID_NAMES[sid]})" if sid in SID_NAMES else ""
    inherit = "".join(token for bit, token in INHERIT_TOKENS if flags & bit)
    return f"{sid}{name}:{inherit}({RIGHTS.get(mask, hex(mask))})"


def _listing(aces: set[Ace]) -> str:
    return ", ".join(sorted(_describe(ace) for ace in aces))


class Permissions:
    """The three permission verdicts of one deployment, each computed only when asked for."""

    def __init__(self, config: Config, probes: Probes) -> None:
        self.config, self.probes, self.root = config, probes, config.root

    # POSIX owners -----------------------------------------------------------------------------------------------------

    def _operator(self) -> str:
        return perms.operator_account(self.root).name

    def _secrets_owner(self) -> str:
        """The service owns `secrets/` on a host; on a bridge, which has no service account, the operator does."""
        if self.config.role is Role.HOST:
            return perms.service_account(self.config).name
        return self._operator()

    # Windows grants ---------------------------------------------------------------------------------------------------

    def _readers(self) -> frozenset[str]:
        return frozenset({winacl.SID_LOCAL_SERVICE, self.probes.operator_sid(self.root)})

    def _env_grants(self) -> Mapping[str, int]:
        operator = self.probes.operator_sid(self.root)
        return winacl.grants(directory=False, operator=operator, readers=(), writers=())

    def _secrets_grants(self, *, directory: bool) -> Mapping[str, int]:
        if self.config.role is Role.HOST:
            return winacl.grants(directory=directory, operator=None, readers=self._readers(), writers=())
        operator = self.probes.operator_sid(self.root)
        return winacl.grants(directory=directory, operator=operator, readers=(), writers=())

    # The verdicts -----------------------------------------------------------------------------------------------------

    def env(self) -> Verdict:
        return self._check(self.root / ".env", ENV_MODE, directory=False, owner=self._operator, grants=self._env_grants)

    def secrets_dir(self) -> Verdict:
        return self._check(
            self.root / "secrets",
            SECRETS_MODE,
            directory=True,
            owner=self._secrets_owner,
            grants=lambda: self._secrets_grants(directory=True)
        )

    def secrets_token(self) -> Verdict:
        return self._check(
            self.root / "secrets" / "token",
            TOKEN_MODE,
            directory=False,
            owner=self._secrets_owner,
            grants=lambda: self._secrets_grants(directory=False)
        )

    def _service_needs(self) -> list[tuple[Path, int]]:
        """Each object the service opens on a Windows host, with the rights it is asked for.

        `bin` and the files in it that the daemons and the service shim run (`ctl` runs goetia itself, and doctor reads
        the record, both as the operator), `host`, every file the daemons read once at startup (`host.READS`), and
        `logs`, where the daemons write.
        """
        root = self.root
        started = [root / "bin" / f"{base}.exe" for base in host.service_binaries("windows")]
        inputs = [root / host.READ_PATHS[name] for names in host.READS.values() for name in names]
        return [
            (root / "bin", winacl.READ_EXECUTE),
            *((path, winacl.READ_EXECUTE) for path in started),
            (root / "host", winacl.READ_EXECUTE),
            *((path, winacl.READ) for path in dict.fromkeys(inputs)),
            (root / "logs", winacl.LIST_AND_ADD),
        ]

    def _log_files(self) -> list[Path]:
        """The files the daemons append to. They appear when a daemon first runs, so a missing one is no failure."""
        return [self.root / path for paths in host.WRITES.values() for path in paths]

    def service_read(self) -> Verdict:
        """Whether the service can open what it needs: an allow for it and no deny of any kind.

        Judged from each object's DACL alone: the allows for the service itself (explicit or inherited, inherit-only
        ones left out) must together cover the rights it needs. Any deny ACE fails, for anyone: install writes none, so
        one came from elsewhere. The log files the daemons append to are judged the same way, for the right to append,
        when they exist.
        """
        if not self.probes.windows:
            return not_applicable("only Windows gives the service its access by ACE; POSIX uses the owner and mode")
        problems = [problem for path, needs in self._service_needs() for problem in self._service_problems(path, needs)]
        problems += [
            problem for path in self._log_files()
            for problem in self._service_problems(path, winacl.APPEND, optional=True)
        ]
        if problems:
            summary = f"the service's access is wrong on {len(problems)} path(s); {INSTALL}"
            return fail("\n".join([summary, *problems]))
        return ok(f"LocalService is allowed what it needs in {self.root} and no ACE denies anyone anything there")

    def _service_problems(self, path: Path, needs: int, *, optional: bool = False) -> list[str]:
        try:
            entries, _ = self.probes.entries(path)
        except FileNotFoundError:
            return [] if optional else [f"{path}: missing"]
        except OSError as exc:
            return [f"{path}: {exc.strerror or exc}"]
        problems = [
            f"{path}: has a deny ACE for {_describe((e.sid, e.mask, e.flags))}" for e in entries
            if e.ace_type == winacl.ACCESS_DENIED_ACE_TYPE
        ]
        held = 0
        for e in entries:
            if (
                e.ace_type == winacl.ACCESS_ALLOWED_ACE_TYPE and e.sid == winacl.SID_LOCAL_SERVICE
                and not e.flags & winacl.INHERIT_ONLY_ACE
            ):
                held |= e.mask
        if held & needs != needs:
            holds = f"({RIGHTS.get(held, hex(held))})" if held else "no allow"
            problems.append(f"{path}: LocalService is not allowed ({RIGHTS.get(needs, hex(needs))}); it holds {holds}")
        return problems

    def _check(self, path: Path, mode: int, *, directory: bool, owner, grants) -> Verdict:
        try:
            if self.probes.windows:
                return self._windows(path, directory, grants())
            return self._posix(path, mode, owner())
        except FileNotFoundError:
            return fail(f"{path} is missing; {INSTALL}")
        except PermissionError as exc:
            return fail(
                f"{path}: {exc.strerror or exc}. Doctor reads only the mode and owner, and must run as the account that "
                "owns the repository; `secrets/` must be traversable (mode 0711 on POSIX)"
            )
        except (ConfigError, PermsError, OSError) as exc:
            return fail(f"{path}: {exc.strerror if isinstance(exc, OSError) and exc.strerror else exc}")

    def _posix(self, path: Path, mode: int, owner: str) -> Verdict:
        expected = frozenset({f"owner={owner}", f"mode={mode:04o}"})
        found = self.probes.principals(path)
        if found == expected:
            return ok(f"{path}: owner {owner}, mode {mode:04o}")
        unexpected = ", ".join(sorted(found - expected)) or "nothing"
        return fail(
            f"{path} is {', '.join(sorted(found))}; expected {', '.join(sorted(expected))} (unexpected: {unexpected}); "
            f"{INSTALL}"
        )

    def _windows(self, path: Path, directory: bool, grants: Mapping[str, int]) -> Verdict:
        acl = self.probes.acl(path)
        inherit = INHERITANCE if directory else 0
        expected = {(sid, mask, inherit) for sid, mask in grants.items()}
        found = {(ace.sid, ace.mask, ace.flags & INHERITANCE_FLAGS) for ace in acl.aces}
        problems = []
        if not acl.protected:
            problems.append("inheritance from the parent is enabled, so the parent's grants apply too")
        if found - expected:
            problems.append(f"unexpected: {_listing(found - expected)}")
        if expected - found:
            problems.append(f"missing: {_listing(expected - found)}")
        if problems:
            return fail(f"{path}: {'; '.join(problems)}; expected exactly {_listing(expected)}; {INSTALL}")
        return ok(f"{path}: {_listing(expected)}")
