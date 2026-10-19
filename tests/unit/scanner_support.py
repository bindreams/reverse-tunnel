"""Shared helpers for the personal-artifact scanner tests."""

import hashlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "no-personal-artifacts.py"
TRACKED_HASHES = REPO_ROOT / "scripts" / "personal-artifact-hashes.txt"

# Synthetic stand-in for a real name; the real ones must never appear in this tree.
TERM = "zzquux"
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
}


def write_hashes_file(directory: Path) -> Path:
    path = directory / "hashes.txt"
    path.write_text(f"# banned\n{len(TERM)} {hashlib.sha256(TERM.encode()).hexdigest()}\n")
    return path


def init_repo(directory: Path) -> Path:
    root = directory / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


def load_script():
    spec = importlib.util.spec_from_file_location("no_personal_artifacts", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(["git", *args],
                            cwd=cwd,
                            env={**GIT_ENV, **(env or {})},
                            capture_output=True,
                            text=True,
                            check=True)
    return result.stdout


def hash_raw_object(cwd: Path, kind: str, content: bytes) -> str:
    """Write an object git itself would not produce, such as a commit with an odd `encoding` header."""
    result = subprocess.run(["git", "hash-object", "-t", kind, "-w", "--literally", "--stdin"],
                            cwd=cwd,
                            env=GIT_ENV,
                            input=content,
                            capture_output=True,
                            check=True)
    return result.stdout.decode().strip()


def run_script(cwd: Path, hashes: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--hashes", str(hashes), *args],
        cwd=cwd,
        env=GIT_ENV,
        capture_output=True,
        text=True,
        check=False,
    )


def kinds(text: str, hashes: Path) -> list[str]:
    module = load_script()
    return [finding.kind for finding in module.scan_text(text, module.load_hashes(hashes))]


def git_bytes(cwd: Path, *args: str, stdin: bytes) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, input=stdin, capture_output=True, check=True)
    return result.stdout.decode().strip()
