"""Diagnostics for front ends: ``app.log`` in the data directory (DESIGN §10.1).

The log never holds secrets or message text; the canary leak tests search it.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Final

from qrp2p.services.paths import ensure_private_dir

LOG_FILE: Final = "app.log"
LOG_BYTES: Final = 1_000_000


def setup_logging(data_dir: Path, *, verbose: bool) -> None:
    """Log to ``app.log`` in the data directory, and to standard error if ``verbose``.

    Raises:
        OSError: The data directory cannot be created or written.
    """
    ensure_private_dir(data_dir)
    handler = logging.handlers.RotatingFileHandler(
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
