"""The real QML window, offscreen, against a fake services side: the harness QML tests share.

The ``ui`` fixture (in conftest.py) opens it at 1100 by 760; :class:`Ui` drives it with keyboard
and mouse and finds items by object name, popups and list delegates included.
"""

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from PySide6.QtCore import QCoreApplication, QEvent, QPointF, Qt
from PySide6.QtGui import QGuiApplication, QKeyEvent
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickItem, QQuickWindow
from PySide6.QtTest import QTest

from qrp2p.ui.app import create_engine, monospace_family
from qrp2p.ui.snapshots import ActivitySnap
from qrp2p.ui.viewmodels.application import AppController
from tests.ui.fakes import SETTINGS, FakeBackend, settle, workspace


@dataclass
class Ui:
    engine: QQmlApplicationEngine
    window: QQuickWindow
    app: AppController
    backend: FakeBackend

    def find(self, name: str) -> QQuickItem | None:
        self.frame()
        found = named(self.window, name)
        return found[0] if found else None

    def frame(self) -> None:
        """Polish and render once: views create their delegates during a frame."""
        settle()
        self.window.grabWindow()
        settle()

    def until(self, condition: Callable[[], bool], timeout: float = 5.0) -> None:
        """Process events until ``condition`` holds (deferred calls run a few passes later)."""
        deadline = time.monotonic() + timeout
        while not condition():
            assert time.monotonic() < deadline, "condition not reached"
            QTest.qWait(10)

    def item(self, name: str) -> QQuickItem:
        found = self.find(name)
        assert found is not None, name
        return found

    def click(self, name: str) -> None:
        self.click_item(self.item(name))

    def click_item(self, target: QQuickItem) -> None:
        self.frame()  # positions are final only after a frame (a menu lays out its entries)
        assert target.isVisible(), target.objectName()
        center = target.mapToScene(QPointF(target.width() / 2, target.height() / 2)).toPoint()
        QTest.mouseClick(
            self.window, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, center
        )
        settle()

    def type(self, text: str) -> None:
        # QTest.keyClicks takes widgets only; a window gets the key events directly.
        for char in text:
            for kind in (QEvent.Type.KeyPress, QEvent.Type.KeyRelease):
                event = QKeyEvent(kind, 0, Qt.KeyboardModifier.NoModifier, char)
                QGuiApplication.sendEvent(self.window, event)
        settle()

    def key(
        self, key: Qt.Key, modifiers: Qt.KeyboardModifier = Qt.KeyboardModifier.NoModifier
    ) -> None:
        QTest.keyClick(self.window, key, modifiers)
        settle()

    def unlock(self, *contacts: object, settings: object = SETTINGS) -> None:
        self.backend.lifecycle("unlocked", workspace(*contacts, settings=settings))  # type: ignore[arg-type]
        activity = ActivitySnap(tuple((c.contact_id, c.created) for c in contacts))  # type: ignore[attr-defined]
        self.backend.reply(self.backend.one("recent_activity"), activity)
        settle()


def flush_deletes() -> None:
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    settle()


def items(window: QQuickWindow) -> list[QQuickItem]:
    """Every item in the window, popups included (delegates have no QObject parent to search)."""
    content = window.contentItem()
    root = content.parentItem() or content
    found: list[QQuickItem] = []
    pending = [root]
    while pending:
        item = pending.pop()
        found.append(item)
        pending.extend(item.childItems())
    return found


def named(window: QQuickWindow, name: str) -> list[QQuickItem]:
    return [item for item in items(window) if item.objectName() == name]


def of_type(ui: Ui, prefix: str) -> list[QQuickItem]:
    """Visible items whose QML type starts with ``prefix``."""
    ui.frame()
    return [
        i
        for i in items(ui.window)
        if i.metaObject().className().startswith(prefix) and i.isVisible()
    ]


@contextmanager
def open_window() -> Iterator[Ui]:
    """The app's window on a fake backend; closed and deleted afterwards."""
    backend = FakeBackend()
    controller = AppController(backend.bridge, data_dir="/data")
    engine = create_engine(controller, monospace_family())
    (root,) = engine.rootObjects()
    assert isinstance(root, QQuickWindow)
    root.resize(1100, 760)
    root.requestActivate()
    settle()
    try:
        yield Ui(engine, root, controller, backend)
    finally:
        root.close()
        engine.deleteLater()
        controller.deleteLater()
        flush_deletes()
