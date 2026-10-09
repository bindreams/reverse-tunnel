# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""A client's checks. It has no daemon and no tunnel of its own, so only what `ctl install` put on disk is checked."""

from ctl.client import WEBSOCAT
from ctl.config import Config
from ctl.doctor.digests import binaries_match_record
from ctl.doctor.model import Check, execute
from ctl.doctor.permissions import Permissions
from ctl.doctor.probes import Probes


def checks(config: Config, probes: Probes) -> list[Check]:
    permissions = Permissions(config, probes)
    return execute([
        ("bin_digests_match_record", lambda: binaries_match_record(config.root, [WEBSOCAT])),
        ("env_permissions", permissions.env),
    ])
