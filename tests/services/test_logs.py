"""``app.log`` is owner-only, like every file in the data directory (DESIGN §10.1)."""

import logging
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from qrp2p.services.logs import LOG_FILE, PrivateLogHandler, setup_logging

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


@pytest.fixture
def handlers() -> Iterator[None]:
    """setup_logging adds to the root logger: take its handlers off again."""
    root = logging.getLogger()
    before = list(root.handlers)
    yield
    for handler in root.handlers[:]:
        if handler not in before:
            root.removeHandler(handler)
            handler.close()


@pytest.mark.usefixtures("handlers")
def test_the_log_and_its_rotation_are_owner_only(tmp_path: Path) -> None:
    setup_logging(tmp_path, verbose=False)
    logging.getLogger("qrp2p.test").warning("hello")
    log = tmp_path / LOG_FILE
    assert log.stat().st_mode & 0o777 == 0o600
    (handler,) = [h for h in logging.getLogger().handlers if isinstance(h, PrivateLogHandler)]
    handler.doRollover()
    assert log.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / f"{LOG_FILE}.1").stat().st_mode & 0o777 == 0o600


@pytest.mark.usefixtures("handlers")
def test_a_readable_log_from_before_is_made_private(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    log = tmp_path / LOG_FILE
    log.write_text("old\n")
    log.chmod(0o644)
    setup_logging(tmp_path, verbose=False)
    assert log.stat().st_mode & 0o777 == 0o600
