"""Qt for UI tests: offscreen, software-rendered, and every Qt warning is a test failure.

The environment is set before Qt starts; pytest-qt's ``qapp`` then makes the application.
"""

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_QUICK_BACKEND", "software")
os.environ.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")

from PySide6.QtGui import QGuiApplication  # after the environment


@pytest.fixture(scope="session")
def qapp_cls() -> type[QGuiApplication]:
    """The app runs a QGuiApplication (no widgets); so do the tests."""
    return QGuiApplication
