"""A hex view's rows: 16 bytes each, made only for the rows a view shows (UI_DESIGN §11.3).

A record frame can be 16 KiB, a thousand rows: the model computes a row's offset, cells and
ASCII column when the view asks for it, so a ListView builds delegates only for what is visible.
The highlighted range is a half-open ``[start, start + length)`` in the same bytes, and a view
asks :meth:`HexModel.fieldAt` which field a clicked byte belongs to.
"""

from typing import Any, Final, override

from PySide6.QtCore import (
    Property,
    QAbstractListModel,
    QByteArray,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    Qt,
    Signal,
)

BYTES_PER_ROW: Final = 16
_OFFSET, _CELLS, _ASCII, _FIRST = (Qt.ItemDataRole.UserRole + n for n in range(1, 5))

type Index = QModelIndex | QPersistentModelIndex


def _printable(byte: int) -> str:
    return chr(byte) if 0x20 <= byte < 0x7F else "·"  # noqa: PLR2004  # printable ASCII


class HexModel(QAbstractListModel):
    """The bytes of one frame or plaintext, as rows of 16."""

    changed = Signal()
    """The bytes or the highlight changed."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._data = b""
        self._start = 0
        self._length = 0

    # -- Qt ---------------------------------------------------------------------------------------

    @override
    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008  # Qt's signature
        return 0 if parent.isValid() else -(-len(self._data) // BYTES_PER_ROW)

    @override
    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        row = index.row()
        if not index.isValid() or not 0 <= row < self.rowCount():
            return None
        first = row * BYTES_PER_ROW
        chunk = self._data[first : first + BYTES_PER_ROW]
        match role:
            case r if r == _OFFSET:
                return f"{first:06x}"
            case r if r == _CELLS:
                return [f"{b:02x}" for b in chunk]
            case r if r == _ASCII:
                return "".join(_printable(b) for b in chunk)
            case r if r == _FIRST:
                return first
            case _:
                return None

    @override
    def roleNames(self) -> dict[int, QByteArray]:
        return {
            _OFFSET: QByteArray(b"offset"),
            _CELLS: QByteArray(b"cells"),
            _ASCII: QByteArray(b"ascii"),
            _FIRST: QByteArray(b"first"),
        }

    def _size(self) -> int:
        return len(self._data)

    def _highlight_start(self) -> int:
        return self._start

    def _highlight_length(self) -> int:
        return self._length

    size = Property(int, _size, notify=changed)
    highlightStart = Property(int, _highlight_start, notify=changed)  # noqa: N815
    highlightLength = Property(int, _highlight_length, notify=changed)  # noqa: N815

    # -- Python -----------------------------------------------------------------------------------

    @property
    def bytes(self) -> bytes:
        """The bytes shown."""
        return self._data

    def show(self, data: bytes, start: int = 0, length: int = 0) -> None:
        """Show ``data`` with ``[start, start + length)`` highlighted."""
        if data != self._data:
            self.beginResetModel()
            self._data = data
            self.endResetModel()
        self._start, self._length = start, length
        self.changed.emit()

    def highlight(self, start: int, length: int) -> None:
        """Highlight ``[start, start + length)``."""
        if (start, length) != (self._start, self._length):
            self._start, self._length = start, length
            self.changed.emit()
