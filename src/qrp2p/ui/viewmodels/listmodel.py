"""A list model of immutable rows that updates by minimal differences (UI_DESIGN §11.3).

View models compute the rows a list should show (a pure function of their state) and hand them to
:meth:`RowModel.sync`. The model works out which rows were removed, inserted, moved or changed and
tells the view exactly that, so delegates keep their state (focus, scroll position, a half-typed
name) and nothing flickers. Rebuilding everything with a model reset would lose all of it.

Rows are frozen dataclasses with a unique key; their fields are the roles QML sees, in camelCase
(``short_id`` becomes ``shortId``). Field values must be plain values QML understands.
"""

import dataclasses
from collections.abc import Callable, Sequence
from typing import Any, override

from PySide6.QtCore import (
    Property,
    QAbstractListModel,
    QByteArray,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    Qt,
    Signal,
    Slot,
)

type Index = QModelIndex | QPersistentModelIndex


def camel(name: str) -> str:
    """``short_id`` → ``shortId``."""
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


class RowModel[R](QAbstractListModel):
    """Rows of type ``R`` (a frozen dataclass), identified by ``key(row)``.

    Args:
        row_type: The row dataclass; its fields become the roles.
        key: A row's unique, stable identity.
        parent: The Qt parent.
    """

    countChanged = Signal()  # noqa: N815  # Qt naming

    def __init__(
        self, row_type: type[R], key: Callable[[R], str], parent: QObject | None = None
    ) -> None:
        super().__init__(parent)
        if not dataclasses.is_dataclass(row_type):
            msg = "rows must be dataclasses"
            raise TypeError(msg)
        self._fields = tuple(f.name for f in dataclasses.fields(row_type))
        self._roles = {
            Qt.ItemDataRole.UserRole + i: name for i, name in enumerate(self._fields, start=1)
        }
        self._key = key
        self._rows: list[R] = []
        self.rowsInserted.connect(self.countChanged)
        self.rowsRemoved.connect(self.countChanged)
        self.modelReset.connect(self.countChanged)

    # -- Qt -----------------------------------------------------------------------------------------

    @override
    def rowCount(self, parent: Index = QModelIndex()) -> int:  # noqa: B008  # Qt's signature
        return 0 if parent.isValid() else len(self._rows)

    @override
    def data(self, index: Index, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        name = self._roles.get(role)
        return None if name is None else getattr(self._rows[index.row()], name)

    @override
    def roleNames(self) -> dict[int, QByteArray]:
        return {role: QByteArray(camel(name).encode()) for role, name in self._roles.items()}

    def _count(self) -> int:
        return len(self._rows)

    count = Property(int, _count, notify=countChanged)

    @Slot(int, result="QVariantMap")
    def get(self, row: int) -> dict[str, object]:
        """Row ``row`` as a map of its roles (for QML); empty if out of range."""
        if not 0 <= row < len(self._rows):
            return {}
        item = self._rows[row]
        return {camel(name): getattr(item, name) for name in self._fields}

    @Slot(str, result=int)
    def indexOf(self, key: str) -> int:  # noqa: N802
        """The row with ``key``, or -1."""
        return next((i for i, row in enumerate(self._rows) if self._key(row) == key), -1)

    # -- Python ------------------------------------------------------------------------------------

    def rows(self) -> tuple[R, ...]:
        """The rows, in order."""
        return tuple(self._rows)

    def sync(self, rows: Sequence[R]) -> None:
        """Make the model show ``rows`` (unique keys), with the fewest structural changes."""
        wanted = [self._key(row) for row in rows]
        if len(set(wanted)) != len(wanted):
            msg = "row keys must be unique"
            raise ValueError(msg)
        self._remove_missing(set(wanted))
        existing = {self._key(row) for row in self._rows}
        i = 0
        while i < len(rows):
            key = wanted[i]
            current = self._key(self._rows[i]) if i < len(self._rows) else None
            if current == key:
                self._replace(i, rows[i])
                i += 1
                continue
            if key in existing:
                self._move(self._find(key, i), i)
                self._replace(i, rows[i])
                i += 1
                continue
            end = i
            while end < len(rows) and wanted[end] not in existing:  # a run of new rows
                end += 1
            self.beginInsertRows(QModelIndex(), i, end - 1)
            self._rows[i:i] = list(rows[i:end])
            self.endInsertRows()
            i = end

    def append(self, rows: Sequence[R]) -> None:
        """Add rows at the end (their keys must be new): no comparison with what is there."""
        if rows:
            self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows) + len(rows) - 1)
            self._rows.extend(rows)
            self.endInsertRows()

    def update(self, row: R) -> None:
        """Replace the row with ``row``'s key, if there is one (only its changed roles notify)."""
        key = self._key(row)
        i = next(
            (j for j in range(len(self._rows) - 1, -1, -1) if self._key(self._rows[j]) == key), -1
        )
        if i >= 0:
            self._replace(i, row)

    def reset(self, rows: Sequence[R]) -> None:
        """Show exactly ``rows``, rebuilding every delegate (for a new source, not an update)."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def clear(self) -> None:
        """Remove every row."""
        if self._rows:
            self.beginRemoveRows(QModelIndex(), 0, len(self._rows) - 1)
            self._rows.clear()
            self.endRemoveRows()

    def _remove_missing(self, keep: set[str]) -> None:
        i = len(self._rows) - 1
        while i >= 0:  # contiguous runs, from the end, so indices stay valid
            if self._key(self._rows[i]) in keep:
                i -= 1
                continue
            end = i
            while i >= 0 and self._key(self._rows[i]) not in keep:
                i -= 1
            self.beginRemoveRows(QModelIndex(), i + 1, end)
            del self._rows[i + 1 : end + 1]
            self.endRemoveRows()

    def _find(self, key: str, start: int) -> int:
        return next(j for j in range(start, len(self._rows)) if self._key(self._rows[j]) == key)

    def _move(self, source: int, destination: int) -> None:
        # Qt's destination is the row *before which* the moved row lands, in pre-move numbering.
        self.beginMoveRows(QModelIndex(), source, source, QModelIndex(), destination)
        self._rows.insert(destination, self._rows.pop(source))
        self.endMoveRows()

    def _replace(self, i: int, row: R) -> None:
        old = self._rows[i]
        if old == row:
            return
        self._rows[i] = row
        changed = [
            role for role, name in self._roles.items() if getattr(old, name) != getattr(row, name)
        ]
        index = self.index(i, 0)
        self.dataChanged.emit(index, index, changed)
