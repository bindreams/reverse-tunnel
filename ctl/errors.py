# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Errors for pinned binaries and the upstream releases they come from."""


class BinariesError(Exception):
    """A pin, a release, or an archive is not what the lock requires."""


class UpstreamUnavailable(BinariesError):
    """GitHub could not answer: transport failure, rate limit, error status, or an unreadable body."""


class AttestationError(BinariesError):
    """A Sigstore bundle does not vouch for an artifact under the pinned identity."""
