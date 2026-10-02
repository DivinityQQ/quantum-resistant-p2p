"""Small helpers for view models: read-only Qt properties and change-notifying setters.

Data flows one way. A view model's properties are read-only to QML; QML states intent by calling
slots, and the view model updates its properties from snapshots. No two-way bindings, so a value
can never bounce between QML and Python or depend on which side wrote last.
"""

from typing import Any, cast

from PySide6.QtCore import Property, QObject, Signal, SignalInstance


def readonly(kind: type | str, attr: str, notify: Signal) -> Property:
    """A read-only Qt property backed by the attribute ``attr``, announced by ``notify``."""

    def get(self: QObject) -> Any:  # noqa: ANN401  # whatever the attribute holds
        return getattr(self, attr)

    return Property(kind, get, notify=notify)  # pyright: ignore[reportArgumentType]


def constant(kind: type | str, attr: str) -> Property:
    """A Qt property that never changes after construction (a child model, say)."""

    def get(self: QObject) -> Any:  # noqa: ANN401
        return getattr(self, attr)

    return Property(kind, get, constant=True)  # pyright: ignore[reportArgumentType]


def mapped(kind: type | str, attr: str, key: str, notify: Signal) -> Property:
    """A read-only Qt property: entry ``key`` of the dict attribute ``attr``.

    For a group of values that are recomputed together and announced by one signal.
    """

    def get(self: QObject) -> Any:  # noqa: ANN401
        return getattr(self, attr)[key]

    return Property(kind, get, notify=notify)  # pyright: ignore[reportArgumentType]


def items[T](value: object, kind: type[T]) -> list[T]:
    """The items of type ``kind`` in a reply's tuple value (empty if it is not a tuple)."""
    if not isinstance(value, tuple):
        return []
    return [item for item in cast("tuple[object, ...]", value) if isinstance(item, kind)]


class ViewModel(QObject):
    """Base class: :meth:`_set` changes an attribute and emits its signal only on a change."""

    def _set(self, attr: str, /, value: object, signal: SignalInstance) -> bool:
        if getattr(self, attr) == value:
            return False
        setattr(self, attr, value)
        signal.emit()
        return True
