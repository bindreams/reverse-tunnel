# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Who may read `.env`, `secrets/` and `secrets/token`: each against the exact set `ctl install` gives it. On a Windows
host it also checks the service's read of the repository root, `bin`, `host` and their files.

Stat only, and never an open: `secrets/` is `0711` so that an unelevated operator can `stat` the token in
separate-account mode, and that grants nothing but the name's existence, mode and owner. On POSIX the expectation is an
owner and a mode; on Windows it is the set of SIDs *and the rights each holds*, built by `winacl.grants`, the function
the installer builds the ACL with, so a token ACE widened from `(R)` to `(F)` is a failure even though no new SID appears.
"""

from collections.abc import Mapping
from pathlib import Path

from ctl import perms, winacl
from ctl.config import Config, ConfigError, Role
from ctl.doctor.model import Verdict, fail, not_applicable, ok
from ctl.doctor.probes import Probes
from ctl.perms import PermsError

ENV_MODE, SECRETS_MODE, TOKEN_MODE = 0o600, 0o711, 0o600
INSTALL = "run `ctl install` to restore it"
INHERITANCE = winacl.OBJECT_INHERIT_ACE | winacl.CONTAINER_INHERIT_ACE
INHERITANCE_FLAGS = INHERITANCE | winacl.NO_PROPAGATE_INHERIT_ACE
INHERITING = INHERITANCE_FLAGS | winacl.INHERIT_ONLY_ACE  # every flag that says where an ACE applies
FILES_ONLY = winacl.OBJECT_INHERIT_ACE | winacl.INHERIT_ONLY_ACE
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

    def service_read(self) -> Verdict:
        """The service's read-and-execute ACE on the root, `bin`, `host` and each file in them.

        On the root, `bin` and the files in `bin` it is explicit and not inheritable: the inheritable one an earlier
        `ctl install` wrote on the root makes NTFS rewrite every other entry there. `host` holds it twice, once for
        itself and once for its files only (`(OI)(IO)`), so a `frpc.toml` that git recreates is readable; a file in
        `host` may hold it by inheritance.
        """
        if not self.probes.windows:
            return not_applicable("only Windows gives the service its access by ACE; POSIX uses the owner and mode")
        paths = [(self.root, self._service_ace_problems)]
        for directory, own, entry in (
            (self.root / "bin", self._service_ace_problems, self._service_ace_problems),
            (self.root / "host", self._host_ace_problems, self._host_file_ace_problems),
        ):
            if directory.is_dir():
                paths.append((directory, own))
                paths += [(p, entry) for p in sorted(directory.iterdir()) if p.is_file() and not p.is_symlink()]
        problems = [problem for path, check in paths for problem in check(path)]
        if problems:
            summary = f"the service's read access is wrong on {len(problems)} path(s); {INSTALL}"
            return fail("\n".join([summary, *problems]))
        return ok(f"LocalService reads {self.root}, bin, host and their files; only the files in host inherit it")

    def _service_aces(self, path: Path) -> tuple[list[Ace], list[Ace]]:
        """The service's ACEs on `path`: the explicit ones, then the inherited ones."""
        mine = [(ace.sid, ace.mask, ace.flags) for ace in self.probes.acl(path).aces
                if ace.sid == winacl.SID_LOCAL_SERVICE]
        inherited = [ace for ace in mine if ace[2] & winacl.INHERITED_ACE]
        return [ace for ace in mine if ace not in inherited], inherited

    @staticmethod
    def _wrong_mask(path: Path, aces: list[Ace]) -> list[str]:
        return [
            f"{path}: {_describe(ace)} is not ({RIGHTS[winacl.READ_EXECUTE]})" for ace in aces
            if ace[1] != winacl.READ_EXECUTE
        ]

    def _service_ace_problems(self, path: Path) -> list[str]:
        """The root, `bin` and the files in `bin`: an explicit ACE that is not inheritable."""
        explicit, _ = self._service_aces(path)
        if not explicit:
            return [f"{path}: LocalService has no ACE of its own"]
        problems = [
            f"{path}: {_describe(ace)} is inheritable; an earlier install wrote it" for ace in explicit
            if ace[2] & INHERITING
        ]
        return problems + self._wrong_mask(path, explicit)

    def _host_ace_problems(self, path: Path) -> list[str]:
        """`host`: an ACE for itself and one that only its files inherit, and nothing else."""
        explicit, _ = self._service_aces(path)
        if not explicit:
            return [f"{path}: LocalService has no ACE of its own"]
        flags = {ace[2] & INHERITING for ace in explicit}
        problems = [
            f"{path}: {_describe(ace)} is neither the ACE for the directory nor the (OI)(IO) one for its files"
            for ace in explicit if ace[2] & INHERITING not in (0, FILES_ONLY)
        ]
        if 0 not in flags:
            problems.append(f"{path}: LocalService has no ACE of its own for the directory")
        if FILES_ONLY not in flags:
            problems.append(f"{path}: LocalService has no (OI)(IO) ACE, so a file created in it has no access")
        return problems + self._wrong_mask(path, explicit)

    def _host_file_ace_problems(self, path: Path) -> list[str]:
        """A file in `host`: the service's ACE, inherited or (from an earlier install) explicit, never inheritable."""
        explicit, inherited = self._service_aces(path)
        if not explicit and not inherited:
            return [f"{path}: LocalService has no ACE"]
        problems = [f"{path}: {_describe(ace)} is inheritable" for ace in explicit if ace[2] & INHERITING]
        return problems + self._wrong_mask(path, explicit + inherited)

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
