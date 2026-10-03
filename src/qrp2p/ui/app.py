"""``qrp2p``: the desktop app (DESIGN §12, §14; UI_DESIGN §11).

```text
qrp2p [--data-dir DIR] [--port N] [--listen HOST] [--no-mdns] [--verbose]
```

The Qt main thread runs the interface; the node runs on its own thread and event loop
(:mod:`qrp2p.ui.host`), and the two talk only through the bridge (:mod:`qrp2p.ui.bridge`).
"""

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Final

from PySide6.QtCore import (
    QCoreApplication,
    QEvent,
    QMessageLogContext,
    QMetaObject,
    QObject,
    Qt,
    QTimer,
    QtMsgType,
    QUrl,
    qInstallMessageHandler,
)
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine, QQmlComponent, QQmlEngine
from PySide6.QtQuick import QQuickItem, QQuickWindow
from PySide6.QtQuickControls2 import QQuickStyle

from qrp2p.services.logs import setup_logging
from qrp2p.services.node import Node
from qrp2p.services.paths import default_data_dir
from qrp2p.ui.bridge import Bridge
from qrp2p.ui.host import Post, ServiceHost
from qrp2p.ui.icons import IconProvider
from qrp2p.ui.portal import portal_running
from qrp2p.ui.viewmodels.application import AppController

ROOT: Final = Path(__file__).parent
QML: Final = ROOT / "qml"
FONTS: Final = ROOT / "resources" / "fonts"
APP_ICON: Final = ROOT / "resources" / "app-icon.svg"
STOP_TIMEOUT: Final = 20.0
"""Seconds to wait at exit for the node to lock and close."""
SMOKE_DELAY_MS: Final = 2500
"""``--smoke-test``: how long the first screen gets to open the node and render."""
SMOKE_UNLOCK_TIMEOUT: Final = 60.0
"""``--smoke-test``: seconds the throwaway vault may take to create and unlock."""
SMOKE_DIALOGS: Final = b"""
import QtQuick
import QtQuick.Dialogs

// Qt's own file and folder dialogs, which open wherever the platform has no native one (KDE
// without its Qt plugin, for one). A build missing a module they need opens nothing at all.
Item {
    readonly property bool shown: files.visible && folders.visible

    function openAll() {
        files.open()
        folders.open()
    }
    function closeAll() {
        files.close()
        folders.close()
    }

    FileDialog { id: files; options: FileDialog.DontUseNativeDialog }
    FolderDialog { id: folders; options: FolderDialog.DontUseNativeDialog }
}
"""
SMOKE_DIALOG_MS: Final = 1000
"""``--smoke-test``: how long Qt's own dialogs get to open."""

_log = logging.getLogger(__name__)

_INPUT_EVENTS: Final = frozenset(
    {
        QEvent.Type.KeyPress,
        QEvent.Type.MouseButtonPress,
        QEvent.Type.Wheel,
        QEvent.Type.TouchBegin,
    }
)


class ActivityFilter(QObject):
    """Reports user input to the controller, which postpones auto-lock (DESIGN §10.4)."""

    def __init__(self, controller: AppController) -> None:
        super().__init__()
        self._controller = controller

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:  # noqa: N802  # Qt's name
        """Note activity; never consume the event."""
        if event.type() in _INPUT_EVENTS:
            self._controller.touch()
        return super().eventFilter(watched, event)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """The command line."""
    parser = argparse.ArgumentParser(
        prog="qrp2p", description="QRP2P: LAN messenger with a hybrid post-quantum channel."
    )
    parser.add_argument("--data-dir", type=Path, help="data directory (default: per-user)")
    parser.add_argument("--port", type=int, help="listening port (default: setting, 47470)")
    parser.add_argument("--listen", metavar="HOST", help="listen on this address only")
    parser.add_argument("--no-mdns", action="store_true", help="no mDNS announce or discovery")
    parser.add_argument("-v", "--verbose", action="store_true", help="log to standard error")
    parser.add_argument(
        "--smoke-test",
        type=Path,
        metavar="PNG",
        help="build check: render the first screen to PNG (in a new data directory, also a "
        "throwaway vault and the messenger), then quit; 1 if Qt warned or a step failed",
    )
    return parser.parse_args(argv)


class WarningCounter:
    """Counts Qt warnings (QML errors among them) for ``--smoke-test``."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def __call__(self, mode: QtMsgType, _context: QMessageLogContext, message: str) -> None:
        """Qt's message handler: record warnings and worse, print everything."""
        if mode in {QtMsgType.QtWarningMsg, QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg}:
            self.messages.append(message)
        sys.stderr.write(f"{message}\n")


class SmokeTest:
    """``--smoke-test``: prove a build works, then quit (exit 1 if Qt warned or a step failed).

    It renders the first screen to the given PNG. In a data directory that did not exist before,
    it then creates a throwaway vault (exercising Argon2id, the identity keys, SQLite and the
    listener) and renders the messenger beside it as ``<name>-messenger.png`` and the Inspector as
    ``<name>-inspector.png``. It never touches an existing vault. Last, it opens Qt's own file and
    folder dialogs.
    """

    def __init__(
        self,
        app: QGuiApplication,
        engine: QQmlApplicationEngine,
        controller: AppController,
        out: Path,
        warnings: WarningCounter,
        *,
        fresh: bool,
    ) -> None:
        self._app = app
        self._engine = engine
        self._controller = controller
        self._out = out
        self._warnings = warnings
        self._fresh = fresh
        self._deadline = 0.0
        self._timer = QTimer()
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._wait_for_messenger)
        self._component: QQmlComponent | None = None
        self._dialogs: QObject | None = None

    def start(self) -> None:
        """Begin once the first screen has had time to settle."""
        QTimer.singleShot(SMOKE_DELAY_MS, self._first_screen)

    def _window(self) -> QQuickWindow | None:
        roots = self._engine.rootObjects()
        window = roots[0] if roots else None
        return window if isinstance(window, QQuickWindow) else None

    def _first_screen(self) -> None:
        window = self._window()
        if window is None:
            self._app.exit(1)
            return
        window.grabWindow().save(str(self._out))
        if not self._fresh or self._controller.property("phase") != "noVault":
            self._open_dialogs()
            return
        password = "smoke test only"  # noqa: S105  # a throwaway vault in a new directory
        self._controller.createVault("Smoke test", password, password)
        self._deadline = time.monotonic() + SMOKE_UNLOCK_TIMEOUT
        self._timer.start()

    def _wait_for_messenger(self) -> None:
        if self._controller.property("phase") == "unlocked":
            self._timer.stop()
            self._controller.dismissWelcome()
            QTimer.singleShot(500, self._messenger)
        elif time.monotonic() > self._deadline or self._controller.property("error"):
            self._timer.stop()
            sys.stderr.write(f"smoke test: no messenger ({self._controller.property('error')})\n")
            self._finish(ok=False)

    def _messenger(self) -> None:
        window = self._window()
        if window is None:
            self._finish(ok=False)
            return
        window.grabWindow().save(str(self._out.with_name(f"{self._out.stem}-messenger.png")))
        messenger = window.findChild(QQuickItem, "messenger")
        if messenger is None:
            self._finish(ok=False)
            return
        messenger.setProperty("inspectorOpen", True)  # noqa: FBT003  # a Qt property
        QTimer.singleShot(500, self._inspector)

    def _inspector(self) -> None:
        window = self._window()
        if window is None or window.findChild(QQuickItem, "inspectorPane") is None:
            sys.stderr.write("smoke test: the Inspector did not open\n")
            self._finish(ok=False)
            return
        window.grabWindow().save(str(self._out.with_name(f"{self._out.stem}-inspector.png")))
        self._open_dialogs()

    def _open_dialogs(self) -> None:
        window = self._window()
        component = QQmlComponent(self._engine)
        component.setData(SMOKE_DIALOGS, QUrl())
        dialogs = component.create()
        if window is None or not isinstance(dialogs, QQuickItem):
            sys.stderr.write(f"smoke test: no dialogs ({component.errorString()})\n")
            self._finish(ok=False)
            return
        QQmlEngine.setObjectOwnership(dialogs, QQmlEngine.ObjectOwnership.CppOwnership)
        dialogs.setParentItem(window.contentItem())
        self._component, self._dialogs = component, dialogs
        QMetaObject.invokeMethod(dialogs, "openAll")
        QTimer.singleShot(SMOKE_DIALOG_MS, self._dialogs_opened)

    def _dialogs_opened(self) -> None:
        dialogs = self._dialogs
        shown = dialogs is not None and bool(dialogs.property("shown"))
        if not shown:
            sys.stderr.write("smoke test: Qt's file and folder dialogs did not open\n")
        if dialogs is not None:
            QMetaObject.invokeMethod(dialogs, "closeAll")
        self._finish(ok=shown)

    def _finish(self, *, ok: bool) -> None:
        self._app.exit(0 if ok and not self._warnings.messages else 1)


def choose_platform_theme() -> None:
    """Linux: use the XDG desktop portal where it runs, unless the user chose a theme.

    The Qt in PySide6 and in our builds cannot load the desktop's own Qt plugin (KDE's is built
    against the system Qt), so KDE users would get Qt's generic file dialogs. The portal gives
    every desktop its real ones.
    """
    if sys.platform == "linux" and "QT_QPA_PLATFORMTHEME" not in os.environ and portal_running():
        os.environ["QT_QPA_PLATFORMTHEME"] = "xdgdesktopportal"


def configure_qt() -> None:
    """Process-wide Qt settings, before the application object exists."""
    choose_platform_theme()
    QQuickStyle.setStyle("Basic")
    QGuiApplication.setApplicationName("QRP2P")
    QGuiApplication.setApplicationDisplayName("QRP2P")
    QGuiApplication.setOrganizationName("QRP2P")
    QGuiApplication.setDesktopFileName("qrp2p")
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )


MONOSPACE_FALLBACKS: Final = (
    "Menlo", "SF Mono", "Consolas", "Cascadia Mono", "DejaVu Sans Mono", "Noto Sans Mono",
    "Liberation Mono", "Ubuntu Mono", "Courier New",
)  # fmt: skip


def monospace_family() -> str:
    """An installed monospace family for bytes, IDs and digits, or "" for the default font.

    Never an alias such as "monospace": Qt resolves a missing family by scanning every font
    (and warns about the cost). Only names in the font database are returned.
    """
    installed = set(QFontDatabase.families())
    system = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()
    for family in (system, *MONOSPACE_FALLBACKS):
        if family in installed:
            return family
    return ""


def load_fonts(app: QGuiApplication) -> str:
    """Register the bundled Inter; returns the monospace family for bytes and digits."""
    for path in sorted(FONTS.glob("*.ttf")):
        if QFontDatabase.addApplicationFont(str(path)) < 0:
            _log.warning("could not load the font %s", path.name)
    font = QFont("Inter")
    font.setPixelSize(15)
    font.setHintingPreference(QFont.HintingPreference.PreferVerticalHinting)
    app.setFont(font)
    return monospace_family()


def create_engine(
    controller: AppController, mono_family: str, *, main: Path = QML / "Main.qml"
) -> QQmlApplicationEngine:
    """The QML engine with the icon provider and the app's modules, showing ``main``."""
    engine = QQmlApplicationEngine()
    engine.addImageProvider("icon", IconProvider())
    engine.addImportPath(str(QML))
    engine.setInitialProperties({"app": controller, "monoFamily": mono_family})
    engine.load(str(main))
    return engine


def make_bridge(args: argparse.Namespace, data_dir: Path) -> Bridge:
    """The bridge, with a services host that builds the node on its own thread."""

    def make_node() -> Node:
        return Node(data_dir, port=args.port, listen_host=args.listen, discovery=not args.no_mdns)

    def make_host(post: Post) -> ServiceHost:
        return ServiceHost(make_node, post)

    return Bridge(make_host)


def main(argv: list[str] | None = None) -> int:
    """The ``qrp2p`` entry point."""
    args = parse_args(argv)
    data_dir: Path = args.data_dir or default_data_dir()
    fresh = not data_dir.exists()
    try:
        setup_logging(data_dir, verbose=args.verbose)
    except OSError as error:
        sys.stderr.write(f"Cannot use the data directory {data_dir}: {error.strerror or error}\n")
        return 1
    warnings = WarningCounter()
    if args.smoke_test is not None:
        qInstallMessageHandler(warnings)
    configure_qt()
    app = QGuiApplication(sys.argv[:1])
    app.setWindowIcon(QIcon(str(APP_ICON)))
    mono = load_fonts(app)
    bridge = make_bridge(args, data_dir)
    controller = AppController(bridge, data_dir=str(data_dir))
    engine = create_engine(controller, mono)
    if not engine.rootObjects():
        _log.error("the interface did not load")
        return 1
    activity = ActivityFilter(controller)
    app.installEventFilter(activity)
    # Ctrl+C in a terminal quits cleanly: Python handles signals only while it runs code.
    signal.signal(signal.SIGINT, lambda _signum, _frame: app.quit())
    ticker = QTimer()
    ticker.timeout.connect(lambda: None)
    ticker.start(250)
    bridge.start()
    smoke = None
    if args.smoke_test is not None:
        smoke = SmokeTest(app, engine, controller, args.smoke_test, warnings, fresh=fresh)
        smoke.start()
    code = app.exec()
    ticker.stop()
    # A defined teardown: views first, then the engine, then the node; nothing is left to the
    # order in which Python happens to free objects (a frozen build frees them differently).
    controller.shutdown()
    engine.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    if not bridge.stop(STOP_TIMEOUT):
        _log.warning("the node did not close within %.0f s", STOP_TIMEOUT)
    del smoke
    return code


if __name__ == "__main__":
    sys.exit(main())
