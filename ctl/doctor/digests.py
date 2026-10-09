# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""`bin/.digests.json` against what is on disk.

The record is what the running processes were started from, written only after they restarted, so it is the reference
for `bin/` and for the inputs a daemon reads once at startup. `binaries.lock.toml` is not: Renovate moves it ahead of any
install, which would turn every dependency bump red.
"""

import hashlib
from collections.abc import Collection, Iterable
from pathlib import Path

from ctl.atomic import read_file
from ctl.doctor.model import Verdict, fail, ok
from ctl.download import DIGESTS, read_digests
from ctl.errors import BinariesError

INSTALL = "run `ctl install`"


def binaries_match_record(root: Path, required: Iterable[str], inputs: Collection[str] = ()) -> Verdict:
    """Every binary in `required` is recorded, present, and the recorded bytes; `inputs` are recorded but not files of `bin/`."""
    bin_dir = root / "bin"
    try:
        record = read_digests(bin_dir)
    except BinariesError as exc:
        return fail(f"{exc}; {INSTALL}")
    if not record:
        return fail(f"{bin_dir / DIGESTS} is missing or empty, so nothing shows what was installed; {INSTALL}")
    required = list(required)
    names = sorted({*required, *(name for name in record if name not in inputs)})
    problems = []
    for name in names:
        if name not in record:
            problems.append(f"{name} is not in the record")
            continue
        try:
            content = read_file(bin_dir, name)
        except BinariesError as exc:
            problems.append(str(exc))
            continue
        if content is None:
            problems.append(f"{bin_dir / name} is missing")
        elif hashlib.sha256(content).hexdigest() != record[name]:
            problems.append(f"{name} differs from the digest recorded at install")
    if problems:
        return fail(f"{'; '.join(problems)}; {INSTALL}")
    return ok(f"{', '.join(names)}: every digest matches {DIGESTS}")


def input_matches_record(root: Path, name: str, actual: str, *, what: str) -> Verdict:
    """The digest of an input the daemon read at startup equals the one recorded when it last restarted."""
    try:
        record = read_digests(root / "bin")
    except BinariesError as exc:
        return fail(f"{exc}; {INSTALL}")
    recorded = record.get(name)
    if recorded is None:
        return fail(
            f"{DIGESTS} does not record {name}, so nothing shows which {what} the daemon started with; {INSTALL}"
        )
    if recorded != actual:
        return fail(
            f"{what} has changed since the daemon last restarted, and it reads it only at startup; {INSTALL} to apply it "
            "(it restarts the daemon, which cuts a session that runs over this tunnel)"
        )
    return ok(f"{what} is the one the daemon started with")
