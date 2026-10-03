"""What a paste into the composer holds: files to offer, an image to offer, or text.

Copied files (a file manager's Copy) are offered as they are. An image (a screenshot, a browser's
Copy Image) is offered as a PNG. Text is pasted as text, also when an image comes with it, as
office suites put a picture of a table beside its text; only a lone address beside an image (a
browser's Copy Image gives the image's URL as text) does not count as text.
"""

from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QMimeData
from PySide6.QtGui import QImage, QImageWriter


@dataclass(frozen=True, slots=True)
class PastedFiles:
    """Local files, by path."""

    paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PastedImage:
    """An image, encoded as PNG, with the name to offer it under."""

    name: str
    png: bytes


type Pasted = PastedFiles | PastedImage


def has_files(mime: QMimeData | None) -> bool:
    """Whether a paste would offer files or an image (not insert text)."""
    return mime is not None and (bool(_local_files(mime)) or _image_only(mime))


def what_to_paste(mime: QMimeData | None, now: datetime) -> Pasted | None:
    """The files or image to offer; ``None`` when the paste is text (or nothing)."""
    if mime is None:
        return None
    files = _local_files(mime)
    if files:
        return PastedFiles(files)
    if _image_only(mime):
        png = _png(mime.imageData())
        if png:
            return PastedImage(f"Pasted image {now:%Y-%m-%d %H-%M-%S}.png", png)
    return None


def _local_files(mime: QMimeData) -> tuple[str, ...]:
    """Every URL as a local path, or nothing if any is not a local file."""
    if not mime.hasUrls():
        return ()
    urls = mime.urls()
    if not urls or not all(url.isLocalFile() for url in urls):
        return ()
    return tuple(url.toLocalFile() for url in urls)


def _image_only(mime: QMimeData) -> bool:
    if not mime.hasImage():
        return False
    if not mime.hasText():
        return True
    text = mime.text().strip()
    lone_address = bool(text) and not any(c.isspace() for c in text)
    return lone_address and ("://" in text or text.startswith("data:"))


def _png(image: object) -> bytes:
    if not isinstance(image, QImage) or image.isNull():
        return b""
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    saved = QImageWriter(buffer, QByteArray(b"PNG")).write(image)
    buffer.close()
    return bytes(data.data()) if saved else b""
