"""A content hash of the behaviour-affecting source, stamped onto every calibration
attempt.

Single-tree editing makes a stale run nearly impossible, but "nearly" is not a
guarantee, and a stale calibration entry recorded as valid is expensive and invisible.
Stamping the source hash makes it detectable after the fact: every attempt for a
template must share a hash, and the report asserts it.

The hash covers what changes a run's behaviour -- the package source and the policies --
and deliberately excludes tests, caches, and runtime state. It is a content hash of the
working tree, not a git commit, because the project is not yet under version control;
when it is, HEAD (clean) or a working-tree hash (dirty) would serve the same role.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

_ROOT: Final = Path(__file__).resolve().parent.parent
_HASHED_DIRS: Final = ("warden", "policies")
_SUFFIXES: Final = (".py", ".yaml", ".json")
_EXCLUDE_PARTS: Final = ("__pycache__",)


def _relevant_files() -> list[Path]:
    files: list[Path] = []
    for directory in _HASHED_DIRS:
        base = _ROOT / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in _SUFFIXES:
                continue
            if any(part in _EXCLUDE_PARTS for part in path.parts):
                continue
            files.append(path)
    return sorted(files)


def source_hash() -> str:
    """A stable short hash over the package source and policies.

    Path-and-content based and order-independent (files are sorted), so it changes iff
    behaviour-affecting source changes, and is identical across machines with the same
    tree. Returns `sha256:<12 hex>`.
    """
    digest = hashlib.sha256()
    for path in _relevant_files():
        rel = path.relative_to(_ROOT).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()[:12]
