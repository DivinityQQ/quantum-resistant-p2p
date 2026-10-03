"""The ``qrp2p`` entry point starts, renders its first screen and exits cleanly (``--smoke-test``).

It runs in a subprocess, as users start it: its own QGuiApplication, the bundled fonts, the icon
provider, Main.qml and the services thread. The packaged builds run the same check in CI.
"""

import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtGui import QImage


def run(tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess[str], Path]:
    shot = tmp_path / "first-screen.png"
    env = os.environ | {"QT_QPA_PLATFORM": "offscreen", "QT_QUICK_BACKEND": "software"}
    result = subprocess.run(  # noqa: S603  # our own entry point
        [
            sys.executable,
            "-m",
            "qrp2p.ui.app",
            "--data-dir",
            str(tmp_path / "data"),
            "--no-mdns",
            "--smoke-test",
            str(shot),
            *extra,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return result, shot


def test_a_fresh_start_reaches_the_messenger_without_warnings(tmp_path: Path) -> None:
    result, shot = run(tmp_path)
    assert result.returncode == 0, result.stderr
    image = QImage(str(shot))
    assert (image.width(), image.height()) == (1280, 800)
    assert QImage(str(tmp_path / "first-screen-messenger.png")).width() == 1280
    assert QImage(str(tmp_path / "first-screen-inspector.png")).width() == 1280
    assert (tmp_path / "data" / "vault.json").exists()  # the throwaway vault


def test_an_existing_data_directory_is_never_given_a_vault(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    result, shot = run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert shot.exists()
    assert not (tmp_path / "first-screen-messenger.png").exists()
    assert not (tmp_path / "data" / "vault.json").exists()


def test_an_unusable_data_directory_is_an_error_not_a_traceback(tmp_path: Path) -> None:
    blocker = tmp_path / "data"
    blocker.write_text("a file where the folder should be")
    result, _ = run(tmp_path)
    assert result.returncode == 1
    assert "Cannot use the data directory" in result.stderr
    assert "Traceback" not in result.stderr
