# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Pytest root: a bare run collects every test that applies to this OS and none that cannot pass on it."""

import sys

collect_ignore_glob = ["tests/platform/posix/*"] if sys.platform == "win32" else ["tests/platform/windows/*"]
