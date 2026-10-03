"""What a paste into the composer offers: copied files, a copied image, or nothing (text)."""

from datetime import UTC, datetime

from PySide6.QtCore import QMimeData, QUrl
from PySide6.QtGui import QColor, QImage

from qrp2p.ui.clipboard import PastedFiles, PastedImage, has_files, what_to_paste

NOW = datetime(2026, 10, 3, 10, 41, 5, tzinfo=UTC)


def image() -> QImage:
    picture = QImage(4, 3, QImage.Format.Format_RGB32)
    picture.fill(QColor("teal"))
    return picture


def mime(
    *, text: str | None = None, urls: list[str] | None = None, picture: bool = False
) -> QMimeData:
    data = QMimeData()
    if text is not None:
        data.setText(text)
    if urls is not None:
        data.setUrls([QUrl(u) for u in urls])
    if picture:
        data.setImageData(image())
    return data


def test_copied_files_are_offered_as_they_are() -> None:
    pasted = what_to_paste(mime(urls=["file:///data/a.txt", "file:///data/b c.pdf"]), NOW)
    assert pasted == PastedFiles(("/data/a.txt", "/data/b c.pdf"))


def test_links_are_text() -> None:
    assert what_to_paste(mime(urls=["file:///data/a.txt", "https://example.org/b"]), NOW) is None


def test_a_copied_image_is_offered_as_png() -> None:
    pasted = what_to_paste(mime(picture=True), NOW)
    assert isinstance(pasted, PastedImage)
    assert pasted.name == "Pasted image 2026-10-03 10-41-05.png"
    assert pasted.png.startswith(b"\x89PNG\r\n\x1a\n")
    back = QImage.fromData(pasted.png)
    assert (back.width(), back.height()) == (4, 3)


def test_a_browsers_copied_image_wins_over_its_address() -> None:
    for address in ("https://example.org/cat.jpg", "data:image/png;base64,iVBORw0KGgo="):
        assert isinstance(what_to_paste(mime(picture=True, text=address), NOW), PastedImage)


def test_text_with_a_picture_beside_it_stays_text() -> None:
    # Office suites put a picture of the copied table or cell beside its text.
    for text in ("Q3 totals\t42", "Total"):
        assert what_to_paste(mime(picture=True, text=text), NOW) is None
        assert not has_files(mime(picture=True, text=text))


def test_text_and_nothing_are_not_files() -> None:
    assert what_to_paste(mime(text="hello"), NOW) is None
    assert what_to_paste(None, NOW) is None
    assert not has_files(mime(text="hello"))
    assert has_files(mime(picture=True))
