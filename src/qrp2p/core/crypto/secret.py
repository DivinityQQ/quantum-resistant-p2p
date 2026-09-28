"""The ``Secret`` wrapper for key material (DESIGN §11.3, "second line of defence").

A :class:`Secret` holds bytes that must never reach logs, trace events, exception text or saved
files outside glass-box and lab sessions. Its label and size are public (the Inspector shows
them as ``••••``); its value leaves only through :meth:`Secret.reveal`.

Python cannot wipe memory (DESIGN §3.5): "erasing" a secret means dropping every reference so the
object can be freed. ``Secret`` therefore keeps an immutable ``bytes`` copy and adds nothing that
would pretend otherwise.
"""

import hmac
from collections.abc import Buffer
from typing import Final, NoReturn, final, override

_REDACTED: Final = "<redacted>"


@final
class Secret:
    """Key material with a public label and size and a redacted representation.

    - ``repr``, ``str`` and every ``format`` spec show only the label and size.
    - Equality with another ``Secret`` is constant-time; ``Secret`` is not hashable.
    - Pickling and copying raise ``TypeError``; subclassing is refused.

    Args:
        value: The secret bytes. A private copy is kept.
        label: A public name such as ``"hs_R"``, shown in the Inspector.
    """

    __slots__ = ("_label", "_value")

    _label: str
    _value: bytes

    def __init__(self, value: Buffer, label: str) -> None:
        object.__setattr__(self, "_value", bytes(value))
        object.__setattr__(self, "_label", label)

    def __init_subclass__(cls) -> NoReturn:
        msg = "Secret cannot be subclassed"
        raise TypeError(msg)

    @property
    def label(self) -> str:
        """The public name of this secret."""
        return self._label

    def __len__(self) -> int:
        return len(self._value)

    def reveal(self) -> bytes:
        """Return the secret bytes.

        Call it only to hand the value to a primitive, or from ``RevealingProvider`` in
        glass-box and lab sessions. Never log, format or store the result.
        """
        return self._value

    @override
    def __repr__(self) -> str:
        return f"Secret({self._label!r}, {len(self._value)} B, {_REDACTED})"

    @override
    def __str__(self) -> str:
        return self.__repr__()

    @override
    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    __hash__ = None  # pyright: ignore[reportAssignmentType]  # unhashable on purpose

    @override
    def __setattr__(self, name: str, value: object) -> NoReturn:
        msg = "Secret is immutable"
        raise AttributeError(msg)

    @override
    def __delattr__(self, name: str) -> NoReturn:
        msg = "Secret is immutable"
        raise AttributeError(msg)

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "Secret cannot be pickled or copied"
        raise TypeError(msg)

    @override
    def __reduce__(self) -> NoReturn:
        msg = "Secret cannot be pickled or copied"
        raise TypeError(msg)
