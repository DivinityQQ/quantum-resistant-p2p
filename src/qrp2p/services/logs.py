"""Diagnostics for front ends: ``app.log`` in the data directory (DESIGN §10.1).

The log never holds secrets or message text; the canary leak tests search it.
"""

import logging
import logging.handlers
import os
import sys
from io import TextIOWrapper
from pathlib import Path
from typing import Final, cast, override

from qrp2p.services.paths import ensure_private_dir

LOG_FILE: Final = "app.log"
LOG_BYTES: Final = 1_000_000


class PrivateLogHandler(logging.handlers.RotatingFileHandler):
    """A rotating log whose files are owner-only from creation (DESIGN §10.1), rotations too."""

    @override
    def _open(self) -> TextIOWrapper:
        def opener(path: str, flags: int) -> int:
            return os.open(path, flags, 0o600)

        stream = open(  # noqa: SIM115  # the handler owns and closes it
            self.baseFilename, self.mode, encoding=self.encoding, errors=self.errors, opener=opener
        )
        Path(self.baseFilename).chmod(0o600)  # a file from an older version keeps its mode
        return cast("TextIOWrapper", stream)  # text mode: always a TextIOWrapper


def setup_logging(data_dir: Path, *, verbose: bool) -> None:
    """Log to ``app.log`` in the data directory, and to standard error if ``verbose``.

    Raises:
        OSError: The data directory cannot be created or written.
    """
    ensure_private_dir(data_dir)
    handler = PrivateLogHandler(
        data_dir / LOG_FILE, maxBytes=LOG_BYTES, backupCount=1, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    logging.getLogger("zeroconf").setLevel(logging.WARNING)
    if verbose:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        root.addHandler(stream)
