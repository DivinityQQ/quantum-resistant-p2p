"""Lucide icons for QML, drawn in the colour the theme asks for (UI_DESIGN §4.3, §5).

QML requests ``image://icon/<name>?color=<rrggbb>``; the provider renders the bundled SVG at the
requested size with ``currentColor`` replaced, so icons follow light and dark themes and stay
sharp at any scale. Only bundled icon names and hex colours are accepted.
"""

import re
from functools import cache
from pathlib import Path
from typing import Final, override

from PySide6.QtCore import QByteArray, QSize, Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtQuick import QQuickImageProvider
from PySide6.QtSvg import QSvgRenderer

ICONS: Final = Path(__file__).parent / "resources" / "icons"
DEFAULT_SIZE: Final = 24
STROKE: Final = "1.75"
"""Lucide draws with 2 at 24 px; a little lighter suits the calm interface."""

_NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
_COLOR = re.compile(r"[0-9a-fA-F]{6}([0-9a-fA-F]{2})?")


@cache
def _svg(name: str) -> str | None:
    if not _NAME.fullmatch(name):
        return None
    path = ICONS / f"{name}.svg"
    return path.read_text(encoding="utf-8") if path.is_file() else None


def render(name: str, color: str, size: QSize) -> QImage:
    """The icon ``name`` in ``color`` (``rrggbb`` or ``aarrggbb``) at ``size``; blank if unknown."""
    width = size.width() if size.width() > 0 else DEFAULT_SIZE
    height = size.height() if size.height() > 0 else width
    image = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(Qt.GlobalColor.transparent)
    svg = _svg(name)
    if svg is None or not _COLOR.fullmatch(color):
        return image
    # SVG wants #rrggbb plus an opacity; Qt's colour names put alpha first.
    with_alpha = len(color) == len("aarrggbb")
    rgb, alpha = (color[2:], int(color[:2], 16) / 255) if with_alpha else (color, 1.0)
    document = (
        svg.replace('stroke="currentColor"', f'stroke="#{rgb}" stroke-opacity="{alpha:.3f}"')
        .replace('fill="currentColor"', f'fill="#{rgb}" fill-opacity="{alpha:.3f}"')
        .replace('stroke-width="2"', f'stroke-width="{STROKE}"')
    )
    renderer = QSvgRenderer(QByteArray(document.encode()))
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter)
    painter.end()
    return image


class IconProvider(QQuickImageProvider):
    """``image://icon/<name>?color=<rrggbb>``."""

    def __init__(self) -> None:
        super().__init__(QQuickImageProvider.ImageType.Image)

    @override
    def requestImage(self, id: str, size: QSize, requestedSize: QSize) -> QImage:  # Qt's signature
        name, _, query = id.partition("?")
        color = query.removeprefix("color=") if query.startswith("color=") else "000000"
        image = render(name, color, requestedSize)
        size.setWidth(image.width())
        size.setHeight(image.height())
        return image
