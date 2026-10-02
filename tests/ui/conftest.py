"""Qt for UI tests: offscreen, software-rendered, and every Qt warning fails the test.

Only these tests import Qt, so the core, lab and services suites run where Qt's system
libraries are missing. Without the ``gui`` extra the UI tests are skipped; a broken Qt
installation (a missing system library) is an error, never a silent skip.
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QUICK_BACKEND", "software")
os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")
if sys.platform == "win32":  # the offscreen platform looks for fonts in Qt's folder, not Windows'
    os.environ.setdefault(
        "QT_QPA_FONTDIR", str(Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts")
    )

pytest.importorskip("PySide6", reason="the desktop app needs the gui extra")

from PySide6.QtCore import QMessageLogContext, QtMsgType, qInstallMessageHandler
from PySide6.QtGui import QGuiApplication

_FAILING = {QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg}


@pytest.fixture(scope="session", autouse=True)
def qapp() -> QGuiApplication:
    """The one application object every UI test shares (the app runs a QGuiApplication too)."""
    existing = QGuiApplication.instance()
    if isinstance(existing, QGuiApplication):
        return existing
    return QGuiApplication(["qrp2p-tests"])


@pytest.fixture(autouse=True)
def qt_warnings_fail() -> Iterator[None]:
    """A QML error, binding loop or any other Qt warning during a test fails it."""
    messages: list[str] = []

    def record(mode: QtMsgType, context: QMessageLogContext, message: str) -> None:
        if mode in _FAILING:
            where = f" ({context.file}:{context.line})" if context.file else ""
            messages.append(f"{mode.name}: {message}{where}")

    previous = qInstallMessageHandler(record)
    yield
    qInstallMessageHandler(previous)
    if messages:
        pytest.fail("Qt warned during the test:\n" + "\n".join(messages), pytrace=False)
