"""``qrp2p``: the desktop app (DESIGN §12, §14; UI_DESIGN §11).

```text
qrp2p [--data-dir DIR] [--port N] [--listen HOST] [--no-mdns] [--verbose] [--dev-preview]
```

The Qt main thread runs the interface; the node runs on its own thread and event loop
(:mod:`qrp2p.ui.host`), and the two talk only through the bridge (:mod:`qrp2p.ui.bridge`).
"""

import argparse
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Final

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle

from qrp2p.services.logs import setup_logging
from qrp2p.services.node import Node
from qrp2p.services.paths import default_data_dir
from qrp2p.ui.bridge import Bridge
from qrp2p.ui.host import Post, ServiceHost
from qrp2p.ui.icons import IconProvider
from qrp2p.ui.viewmodels.application import AppController

ROOT: Final = Path(__file__).parent
QML: Final = ROOT / "qml"
FONTS: Final = ROOT / "resources" / "fonts"
APP_ICON: Final = ROOT / "resources" / "app-icon.svg"
STOP_TIMEOUT: Final = 20.0
"""Seconds to wait at exit for the node to lock and close."""

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
        "--dev-preview", action="store_true", help="show development previews (Inspector layout)"
    )
    return parser.parse_args(argv)


def configure_qt() -> None:
    """Process-wide Qt settings, before the application object exists."""
    QQuickStyle.setStyle("Basic")
    QGuiApplication.setApplicationName("QRP2P")
    QGuiApplication.setApplicationDisplayName("QRP2P")
    QGuiApplication.setOrganizationName("QRP2P")
    QGuiApplication.setDesktopFileName("qrp2p")
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )


def load_fonts(app: QGuiApplication) -> str:
    """Register the bundled Inter; returns the monospace family for bytes and digits."""
    for path in sorted(FONTS.glob("*.ttf")):
        if QFontDatabase.addApplicationFont(str(path)) < 0:
            _log.warning("could not load the font %s", path.name)
    font = QFont("Inter")
    font.setPixelSize(15)
    font.setHintingPreference(QFont.HintingPreference.PreferVerticalHinting)
    app.setFont(font)
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()


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
    try:
        setup_logging(data_dir, verbose=args.verbose)
    except OSError as error:
        sys.stderr.write(f"Cannot use the data directory {data_dir}: {error.strerror or error}\n")
        return 1
    configure_qt()
    app = QGuiApplication(sys.argv[:1])
    app.setWindowIcon(QIcon(str(APP_ICON)))
    mono = load_fonts(app)
    bridge = make_bridge(args, data_dir)
    controller = AppController(
        bridge,
        data_dir=str(data_dir),
        dev_preview=args.dev_preview or os.environ.get("QRP2P_DEV_PREVIEW") == "1",
    )
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
    code = app.exec()
    ticker.stop()
    if not bridge.stop(STOP_TIMEOUT):
        _log.warning("the node did not close within %.0f s", STOP_TIMEOUT)
    del engine
    return code


if __name__ == "__main__":
    sys.exit(main())
