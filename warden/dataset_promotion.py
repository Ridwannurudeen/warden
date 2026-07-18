"""Shared guards for human-reviewed training and benchmark promotion."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

from warden.scanner.normalize import fold_unicode

_LOCK = Lock()


def canonical_dataset_payload(value: object) -> str:
    return " ".join(fold_unicode(str(value)).casefold().split())


@contextmanager
def exclusive_dataset_lock(held_out_attacks_path: Path) -> Iterator[None]:
    lock_path = held_out_attacks_path.parent / ".warden-dataset-promotion.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    if lock_path.exists() and lock_path.is_symlink():
        raise ValueError("dataset promotion lock must not be a symlink")
    with _LOCK, lock_path.open("a+b") as handle:
        if os.name != "nt":
            os.chmod(lock_path, 0o600)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
