#!/usr/bin/env python3
# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""Fail when text holds a personal artifact: a real name, host key, key material, e-mail address or home path.

Real names are never spelled in the tree. `personal-artifact-hashes.txt` holds `LENGTH SHA256` for each banned
lowercase name. Text is split into `[a-z0-9]+` tokens; every substring of a token whose length is a banned length is
hashed and looked up, so a name embedded in a longer token (`myNameBox2`) is still caught. Matched text is never
printed, so a public CI log does not leak what it caught. To ban a name: `no-personal-artifacts.py --hash NAME`
and append the output to the list.

Modes (default `--staged`):

    FILE...      scan these working-tree files (a symlink is scanned by its target); a missing file is an error
    --staged     scan the staged blobs and paths (what the prek hook runs)
    --tree       scan every blob and path in the index
    --history    scan every object reachable from any ref: blobs, path names, commit and tag messages, ref names
    --message F  scan every line of a commit message file, template comments and `-v` diff included

Content is read from git objects, so symlink targets are covered. Text is UTF-8 without NUL bytes, or UTF-16/32 with a
BOM that decodes cleanly. Anything else is itself a finding ("binary content not allowed"), because a compressed or
re-encoded blob can hide any name from a scanner; list intended binaries in `BINARY_ALLOWED`. BOM-marked text is also
scanned as raw bytes, so a bogus BOM cannot hide ASCII.
"""

import argparse
import codecs
import hashlib
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from typing import NoReturn
from dataclasses import dataclass
from pathlib import Path

DEFAULT_HASHES = Path(__file__).with_name("personal-artifact-hashes.txt")

TOKEN = re.compile(r"[a-z0-9]+")
ENTRY = re.compile(r"([0-9]+) ([0-9a-f]{64})")
GITLINK = "160000"

# Maps each banned length to the digests of that length.
Hashes = dict[int, frozenset[str]]

# Structural patterns ==================================================================================================

KEY_BLOB = r"AAAA[A-Za-z0-9+/=]{20,}"
STRUCTURAL = {
    "ssh-fingerprint": re.compile(r"\bSHA256:[A-Za-z0-9+/]{43}|\b(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2}\b"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "ssh-public-key": re.
    compile(rf"\b(?:sk-)?(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+)(?:@openssh\.com)?\s+{KEY_BLOB}"),
}
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
EMAIL_ADDRESSES = {"git@github.com", "noreply@github.com"}
EMAIL_DOMAINS = {"example.com", "example.org", "example.net", "users.noreply.github.com"}
# Any run of `/` or `\` separates the parts, which covers JSON-escaped `\/`. Without a drive letter the run must open a
# path: `src/home/index.html` has a segment named home but is not a home directory.
HOME_PATHS = (
    re.compile(r"(?<![A-Za-z0-9_.~/\\-])[/\\]+(?:Users|home)[/\\]+([A-Za-z0-9._-]+)", re.IGNORECASE),
    re.compile(r"[A-Za-z]:[/\\]+Users[/\\]+([A-Za-z0-9._-]+)", re.IGNORECASE),
)
HOME_NAMES = {"user", "username", "you", "me", "example", "runner", "operator", "service", "public", "default"}

# Binary content =======================================================================================================

BINARY = "binary content not allowed"
INVALID_PATH = "invalid UTF-8 in path"
# Repo paths of blobs allowed to be binary. `--history` knows only the first path git reports for a blob.
BINARY_ALLOWED: frozenset[str] = frozenset()
BOMS = {
    codecs.BOM_UTF32_LE: "utf-32",
    codecs.BOM_UTF32_BE: "utf-32",
    codecs.BOM_UTF16_LE: "utf-16",
    codecs.BOM_UTF16_BE: "utf-16",
}
OPAQUE_HEADER = re.compile(r"(?:(?:tree|parent|object) [0-9a-f]{40,64}|type (?:commit|tree|blob|tag))")
SIGNATURE_BEGIN = re.compile(r"-----BEGIN (?:PGP SIGNATURE|SSH SIGNATURE|SIGNED MESSAGE)-----")
SIGNATURE_END = re.compile(r"-----END (?:PGP SIGNATURE|SSH SIGNATURE|SIGNED MESSAGE)-----")
# An armour line of signature bytes (at most 76 characters in practice) or the `=XXXX` checksum. Short lines are
# scanned, so a name alone on a line is not hidden.
SIGNATURE_BYTES = re.compile(r"[A-Za-z0-9+/=]{40,}|=[A-Za-z0-9+/]{4}")
# Identity lines hold real people's names and e-mail addresses, so only banned terms are looked for there.
IDENTITY_KEYS = ("author ", "committer ", "tagger ")
SIGNED_HEADERS = {"gpgsig", "gpgsig-sha256", "mergetag"}
UTF8_NAMES = {"utf-8", "utf8"}


@dataclass(frozen=True)
class Finding:
    source: str
    line: int
    kind: str

    def __str__(self) -> str:
        return f"{self.source}:{self.line}: {self.kind}" if self.line else f"{self.source}: {self.kind}"


class InputError(Exception):
    """A problem with what the user asked us to scan; its message goes through `redact_text` before it is printed."""


# Scanning =============================================================================================================


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def hash_entry(term: str) -> str:
    name = term.lower()
    if not TOKEN.fullmatch(name):
        raise ValueError("a banned name must be one run of letters and digits; it is matched per token")
    return f"{len(name)} {digest(name)}"


def load_hashes(path: Path) -> Hashes:
    by_length: dict[int, set[str]] = {}
    for number, raw in enumerate(path.read_text().split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry = ENTRY.fullmatch(line)
        if not entry:
            raise ValueError(f"{path}:{number}: expected `LENGTH SHA256-HEX`")
        by_length.setdefault(int(entry[1]), set()).add(entry[2])
    if not by_length:
        raise ValueError(f"{path}: no entries, so nothing would ever match")
    return {length: frozenset(digests) for length, digests in by_length.items()}


def contains_banned_name(token: str, hashes: Hashes) -> bool:
    return any(
        digest(token[start:start + length]) in digests for length, digests in hashes.items()
        for start in range(len(token) - length + 1)
    )


def scan_line(line: str, hashes: Hashes, banned_only: bool = False) -> list[str]:
    kinds = []
    if any(contains_banned_name(token, hashes) for token in TOKEN.findall(line.lower())):
        kinds.append("banned-term")
    if banned_only:
        return kinds
    kinds += [kind for kind, pattern in STRUCTURAL.items() if pattern.search(line)]
    if any(m[0].lower() not in EMAIL_ADDRESSES and m[1].lower() not in EMAIL_DOMAINS for m in EMAIL.finditer(line)):
        kinds.append("email")
    if any(m[1].lower() not in HOME_NAMES for pattern in HOME_PATHS for m in pattern.finditer(line)):
        kinds.append("home-path")
    return kinds


def display(path: str, hashes: Hashes, locator: str) -> str:
    """The path as it may be logged: verbatim when clean, else only the kinds found and a way to locate it."""
    kinds = scan_line(path, hashes)
    return f"<path redacted: {', '.join(kinds)}> ({locator})" if kinds else path


def redact_text(text: str, hashes: Hashes) -> str:
    """Make arbitrary text (an error message, git's stderr) safe for a public log."""
    text = re.sub(r"[A-Za-z0-9]+", lambda m: "<redacted>" if contains_banned_name(m[0].lower(), hashes) else m[0], text)
    lines = []
    for line in text.split("\n"):
        kinds = scan_line(line, hashes)
        lines.append(f"<line redacted: {', '.join(kinds)}>" if kinds else line)
    return "\n".join(lines)


def unique(findings: list[Finding]) -> list[Finding]:
    return list(dict.fromkeys(findings))


def scan_text(text: str, hashes: Hashes, source: str = "") -> list[Finding]:
    return [
        Finding(source, number, kind) for number, line in enumerate(text.split("\n"), 1)
        for kind in scan_line(line, hashes)
    ]


def decodings(data: bytes) -> list[str]:
    """Every clean reading of `data` as text; empty when it is not text.

    A UTF-16 file starting with U+0000 begins like a UTF-32 BOM, so every BOM that matches is tried.
    """
    texts = []
    for bom, encoding in BOMS.items():
        if data.startswith(bom):
            try:
                texts.append(data.decode(encoding))
            except UnicodeDecodeError:
                pass
    if not texts and b"\0" not in data:
        try:
            texts.append(data.decode())
        except UnicodeDecodeError:
            pass
    return texts


def scan_content(source: str, data: bytes, hashes: Hashes, allowed: bool = False) -> list[Finding]:
    texts = decodings(data)
    findings = [f for text in texts for f in scan_text(text, hashes, source)]
    if not texts or data.startswith(tuple(BOMS)):
        findings += scan_text(data.decode("latin-1"), hashes, source)
    if not texts and not allowed:
        findings.append(Finding(source, 0, BINARY))
    return unique(findings)


def scan_blob(path: str, data: bytes, hashes: Hashes, locator: str = "") -> list[Finding]:
    shown = display(path, hashes, locator)
    path_findings = [Finding(shown, 0, kind) for kind in scan_line(path, hashes)]
    return path_findings + scan_content(shown, data, hashes, path in BINARY_ALLOWED)


# Git ==================================================================================================================


def git(*args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(["git", "--no-replace-objects", "-c", "core.quotepath=off", *args],
                            input=stdin,
                            capture_output=True,
                            check=False)
    if result.returncode:
        raise InputError(f"git {args[0]} failed (exit {result.returncode}): {result.stderr.decode(errors='replace')}")
    return result.stdout


def read_objects(ids: Sequence[str]) -> list[tuple[str, str, bytes]]:
    """Return (id, type, content) for each id, in one `git cat-file --batch`."""
    if not ids:
        return []
    out = git("cat-file", "--batch", stdin=("\n".join(ids) + "\n").encode())
    objects = []
    position = 0
    while position < len(out):
        end = out.index(b"\n", position)
        header = out[position:end].decode(errors="replace").split(" ")
        if len(header) != 3:
            raise InputError(f"git cat-file: {' '.join(header)}")
        name, kind, size = header[0], header[1], int(header[2])
        objects.append((name, kind, out[end + 1:end + 1 + size]))
        position = end + 1 + size + 1
    return objects


def as_text(path: str) -> tuple[str, bool]:
    """A path that came from git bytes as printable text, and whether it was valid UTF-8."""
    try:
        path.encode()
    except UnicodeEncodeError:
        return path.encode(errors="surrogateescape").decode(errors="replace"), False
    return path, True


def scan_entries(entries: Sequence[tuple[str, str, str]], hashes: Hashes) -> list[Finding]:
    """Scan (mode, blob id, path) triples: the path always, the blob unless it is a submodule commit."""
    findings = []
    shown = {}
    for _, blob, path in entries:
        text, valid = as_text(path)
        shown[path] = display(text, hashes, f"blob {blob[:12]}")
        findings += [Finding(shown[path], 0, kind) for kind in scan_line(text, hashes)]
        findings += [] if valid else [Finding(shown[path], 0, INVALID_PATH)]
    blobs = [(blob, path) for mode, blob, path in entries if mode != GITLINK]
    for (_, path), (_, _, data) in zip(blobs, read_objects([blob for blob, _ in blobs])):
        findings += scan_content(shown[path], data, hashes, path in BINARY_ALLOWED)
    return unique(findings)


def index_entries() -> list[tuple[str, str, str]]:
    entries = []
    for item in git("ls-files", "-s", "-z").split(b"\0"):
        if item:
            meta, _, path = item.decode(errors="surrogateescape").partition("\t")
            mode, blob, _stage = meta.split(" ")
            entries.append((mode, blob, path))
    return entries


def staged_entries() -> list[tuple[str, str, str]]:
    fields = git("diff", "--cached", "--raw", "--no-abbrev", "--no-renames", "--diff-filter=d", "-z").split(b"\0")
    entries = []
    for meta, path in zip(fields[0::2], fields[1::2]):
        _old_mode, mode, _old_blob, blob, _status = meta.decode().lstrip(":").split(" ")
        if set(blob) != {"0"}:  # an unmerged path has no blob to read
            entries.append((mode, blob, path.decode(errors="surrogateescape")))
    return entries


def scan_staged(hashes: Hashes) -> list[Finding]:
    return scan_entries(staged_entries(), hashes)


def scan_tree(hashes: Hashes) -> list[Finding]:
    return scan_entries(index_entries(), hashes)


def tree_names(data: bytes, id_size: int) -> list[tuple[str, bool]]:
    """Entry names of a tree object, each with whether it was valid UTF-8."""
    names = []
    position = 0
    while position < len(data):
        space = data.index(b" ", position)
        nul = data.index(b"\0", space)
        raw = data[space + 1:nul]
        try:
            names.append((raw.decode(), True))
        except UnicodeDecodeError:
            names.append((raw.decode(errors="replace"), False))
        position = nul + 1 + id_size
    return names


Item = tuple[int, str, int | None]  # line number, text, id of the signed region it belongs to (None: not signed)


def strip_signatures(items: Sequence[Item]) -> tuple[list[tuple[int, str]], bool]:
    """Drop the base64 body of each signature block inside a signed region; say whether a block was left open.

    Those bytes are not author-chosen text. The armour's own lines (`Comment:`, `Version:`, BEGIN and END, any short
    line) are kept, and a block opens only in a signed region and cannot run past its end.
    """
    kept = []
    inside = False
    unterminated = False
    region = None
    for number, line, line_region in items:
        if line_region != region:
            unterminated |= inside
            inside, region = False, line_region
        if line_region is not None:
            if SIGNATURE_BEGIN.search(line):
                inside = True
            elif SIGNATURE_END.search(line):
                inside = False
            elif inside and SIGNATURE_BYTES.fullmatch(line):
                continue
        kept.append((number, line))
    return kept, unterminated | inside


def header_lines(header: str) -> tuple[list[tuple[int, str]], bool]:
    """Header lines with a folded continuation (`mergetag`, `gpgsig`) unfolded into lines of its own."""
    items: list[Item] = []
    region: int | None = None
    for number, raw in enumerate(header.split("\n"), 1):
        if not raw.startswith(" "):
            region = number if raw.partition(" ")[0] in SIGNED_HEADERS else None
        line = raw.removeprefix(" ")
        if not OPAQUE_HEADER.fullmatch(line):
            items.append((number, line, region))
    return strip_signatures(items)


def scan_commit_or_tag(source: str, data: bytes, hashes: Hashes, signed_message: bool = False) -> list[Finding]:
    """`signed_message` marks a tag, whose message may end in a signature block; a commit message never does."""
    raw_header, _, raw_body = data.partition(b"\n\n")
    findings = []
    texts = {}
    for part, raw in (("header", raw_header), ("message", raw_body)):
        try:
            texts[part] = raw.decode()
        except UnicodeDecodeError:
            texts[part] = raw.decode(errors="replace")
            findings.append(Finding(source, 0, f"invalid UTF-8 in {part}"))
        if "\0" in texts[part]:  # UTF-16 text is valid UTF-8 with a NUL between its letters
            findings.append(Finding(source, 0, f"NUL byte in {part}"))
            texts[part] = texts[part].replace("\0", "")
    for line in texts["header"].split("\n"):
        encoding = line.removeprefix("encoding ") if line.startswith("encoding ") else None
        if encoding is not None and encoding.strip().lower() not in UTF8_NAMES:
            findings.append(Finding(source, 0, "non-UTF-8 commit encoding"))
    lines, unterminated = header_lines(texts["header"])
    message_items = [(n, line, 0 if signed_message else None) for n, line in enumerate(texts["message"].split("\n"), 1)]
    message, message_unterminated = strip_signatures(message_items)
    if unterminated or message_unterminated:
        findings.append(Finding(source, 0, "unterminated signature block"))
    findings += [
        Finding(f"{source} header", n, k) for n, line in lines
        for k in scan_line(line, hashes, banned_only=line.startswith(IDENTITY_KEYS))
    ]
    return findings + [
        Finding(f"{source} message", number, kind) for number, line in message for kind in scan_line(line, hashes)
    ]


def scan_object(name: str, kind: str, data: bytes, hashes: Hashes, path: str = "") -> list[Finding]:
    source = f"{kind} {name[:12]}"
    if kind == "blob":
        return scan_content(source, data, hashes, path in BINARY_ALLOWED)
    if kind in ("commit", "tag"):
        return scan_commit_or_tag(source, data, hashes, signed_message=kind == "tag")
    if kind == "tree":
        findings = []
        for entry, valid in tree_names(data, len(name) // 2):
            findings += [Finding(source, 0, k) for k in scan_line(entry, hashes)]
            findings += [] if valid else [Finding(source, 0, INVALID_PATH)]
        return findings
    return []


def scan_history(hashes: Hashes) -> list[Finding]:
    listing = [
        line.partition(" ") for line in git("rev-list", "--objects", "--all").decode(errors="replace").split("\n")
        if line
    ]
    paths = {name: path for name, _, path in listing}
    objects = read_objects([name for name, _, _ in listing])
    findings = [f for name, kind, data in objects for f in scan_object(name, kind, data, hashes, paths[name])]
    for raw_ref in git("for-each-ref", "--format=%(refname)").split(b"\n"):
        ref, valid = as_text(raw_ref.decode(errors="surrogateescape"))
        findings += [Finding("ref", 0, kind) for kind in scan_line(ref, hashes)]
        findings += [] if valid else [Finding("ref", 0, "invalid UTF-8 in ref name")]
    return unique(findings)


# Files and messages ===================================================================================================


def read_path(path: str) -> bytes:
    file = Path(path)
    try:
        if file.is_symlink():
            return os.fsencode(os.readlink(file))
        if file.is_file():
            return file.read_bytes()
    except OSError as error:
        raise InputError(f"{path}: {error.strerror or error}") from error
    raise InputError(f"{path}: not a file")


def scan_files(paths: Sequence[str], hashes: Hashes) -> list[Finding]:
    return unique([
        f for number, path in enumerate(paths, 1)
        for f in scan_blob(path, read_path(path), hashes, f"argument {number}")
    ])


def scan_message(path: str, hashes: Hashes) -> list[Finding]:
    """Scan every line: with `-m` or `-F` git keeps template comments and anything after the scissors line."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError as error:
        raise InputError(f"{path}: {error.strerror or error}") from error
    return scan_text(text, hashes, display(path, hashes, "message file"))


# Entrypoint ===========================================================================================================


def ban_list_path(argv: Sequence[str] | None) -> Path:
    """Where `--hashes` points, found without the real parser, which may be the thing that is failing."""
    probe = argparse.ArgumentParser(add_help=False, allow_abbrev=False, exit_on_error=False)
    probe.add_argument("--hashes", type=Path, default=DEFAULT_HASHES)
    try:
        return probe.parse_known_args(argv)[0].hashes
    except argparse.ArgumentError:
        return DEFAULT_HASHES


class RedactingParser(argparse.ArgumentParser):
    """An argument parser whose errors may echo a bad argument, so they are redacted like every other message."""

    argv: Sequence[str] | None = None

    def error(self, message: str) -> NoReturn:
        try:
            safe = redact_text(message, load_hashes(ban_list_path(self.argv)))
        except (OSError, ValueError):
            safe = "(details withheld: the ban list could not be read to redact them)"
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {safe}\n")


def build_parser() -> RedactingParser:
    parser = RedactingParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", help="working-tree files to scan")
    parser.add_argument("--hashes", type=Path, default=DEFAULT_HASHES, help="ban list (default: %(default)s)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--staged", action="store_true", help="scan the staged changes (default)")
    modes.add_argument("--tree", action="store_true", help="scan every blob and path in the index")
    modes.add_argument("--history", action="store_true", help="scan every object reachable from any ref")
    modes.add_argument("--message", metavar="FILE", help="scan a commit message file")
    modes.add_argument("--hash", metavar="TERM", help="print the list entry for a banned name")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.argv = argv if argv is not None else sys.argv[1:]
    args = parser.parse_args(argv)
    if args.hash is not None:
        try:
            print(hash_entry(args.hash))
        except ValueError as error:
            parser.error(str(error))
        return 0
    if args.files and (args.staged or args.tree or args.history or args.message):
        parser.error("FILE arguments cannot be combined with a scan mode")
    try:
        hashes = load_hashes(args.hashes)
    except (OSError, ValueError) as error:
        print(f"error: ban list unreadable: {error}", file=sys.stderr)
        return 2
    try:
        if args.files:
            findings = scan_files(args.files, hashes)
        elif args.tree:
            findings = scan_tree(hashes)
        elif args.history:
            findings = scan_history(hashes)
        elif args.message:
            findings = scan_message(args.message, hashes)
        else:
            findings = scan_staged(hashes)
    except (InputError, OSError) as error:
        print(redact_text(f"error: {error}", hashes), file=sys.stderr)
        return 2
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        print(f"{len(findings)} personal artifact(s) found; matched text withheld.", file=sys.stderr)
        if args.message:
            print(
                "If this matched git's commit template or a `-v` diff, rename the file or commit with -m and without -v.",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
