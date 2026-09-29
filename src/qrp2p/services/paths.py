"""Where the node keeps its files, and how it writes them (DESIGN §10.1)."""

import contextlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Final

import platformdirs

APP_NAME: Final = "qrp2p"
DATA_DIR_ENV: Final = "QRP2P_DATA_DIR"
"""Overrides the data directory, e.g. to run two nodes on one machine."""


def default_data_dir() -> Path:
    """``$QRP2P_DATA_DIR``, else the platform's per-user data directory."""
    override = os.environ.get(DATA_DIR_ENV)
    if override:
        return Path(override)
    return Path(platformdirs.user_data_dir(APP_NAME, appauthor=False))


def default_downloads_dir() -> Path:
    """The platform's downloads directory."""
    return Path(platformdirs.user_downloads_dir())


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (and parents) readable only by the owner, where the OS supports modes."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        path.chmod(0o700)


def write_private_file(path: Path, data: bytes) -> None:
    """Replace ``path`` atomically with ``data``, owner-only, flushed to disk.

    The data goes to a temporary file in the same directory, which is synced and then renamed
    over ``path``; a crash leaves either the old or the new file, never a torn one.
    """
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        if sys.platform != "win32":
            Path(tmp).chmod(0o600)
        Path(tmp).replace(path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            Path(tmp).unlink()
        raise
    _sync_directory(path.parent)


def _sync_directory(directory: Path) -> None:
    """Make a rename durable (POSIX); Windows has no directory handles to sync."""
    if sys.platform == "win32":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
