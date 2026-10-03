"""The exposure gate: glass-box values reach the trace bus only after glass-box admission.

DESIGN §11.3: a session's crypto provider is chosen when its connection opens, before anyone
knows whether it will be glass-box. So:

- A session that can never be glass-box (we initiate and did not ask) gets a plain provider,
  which has no path to anything outside the engine.
- Every other session gets a :class:`~qrp2p.core.crypto.provider.RevealingProvider` whose sink is
  an :class:`ExposureGate`. Until admission the gate only buffers, at most
  :data:`PENDING_LIMIT` values. If Admit says ``glass_box = 1`` the gate publishes the buffer and
  then every later value; otherwise it drops the buffer and its publisher for good, and nothing
  it is given afterwards goes anywhere.

Revealed values stay wrapped in :class:`~qrp2p.core.crypto.secret.Secret` on the bus, so a
``repr`` or log line still shows ``<redacted>``; only the Inspector's snapshot of a glass-box
session unwraps them.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from qrp2p.core.crypto.provider import AeadRevealed, Revealed
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

PENDING_LIMIT: Final = 128
"""Values a gate holds before admission (a handshake reveals about forty)."""


@dataclass(frozen=True, slots=True)
class ValueRevealed:
    """A secret of a glass-box session, under its schedule name (``hs_R``, ``ap_I[0]+1``…)."""

    secret: Secret


@dataclass(frozen=True, slots=True)
class RecordRevealed:
    """A glass-box record's nonce and plaintext; ``key`` and ``seq`` identify the record."""

    key: str
    seq: int
    nonce: Secret
    plaintext: Secret
    opened: bool
    """``True`` for a record received, ``False`` for one sent."""


type Exposure = ValueRevealed | RecordRevealed
type Publish = Callable[[float, Exposure], None]
"""Receives each value with the time it was revealed."""


class GateState(StrEnum):
    """Where a gate is."""

    PENDING = "pending"
    OPEN = "open"
    CLOSED = "closed"


class ExposureGate:
    """The sink of one session's revealing provider (see the module docstring).

    Args:
        clock: The monotonic clock, to timestamp values as they are revealed.
    """

    __slots__ = ("_buffer", "_clock", "_publish", "_state")

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._state = GateState.PENDING
        self._buffer: list[tuple[float, Exposure]] = []
        self._publish: Publish | None = None

    @property
    def state(self) -> GateState:
        """Pending, open or closed."""
        return self._state

    def __call__(self, value: Revealed) -> None:
        """Take one value from the provider.

        Raises:
            ProtocolError: ``internal`` if more than :data:`PENDING_LIMIT` values arrive before
                admission; the gate closes first, so the handshake fails closed.
        """
        if self._state is GateState.CLOSED:
            return
        exposure = _exposure(value)
        if self._state is GateState.OPEN:
            assert self._publish is not None  # noqa: S101  # set when opened
            self._publish(self._clock(), exposure)
            return
        if len(self._buffer) >= PENDING_LIMIT:
            self.close()
            raise ProtocolError(CloseReason.INTERNAL, "too many values before admission")
        self._buffer.append((self._clock(), exposure))

    def open(self, publish: Publish) -> None:
        """Glass-box admission: publish the buffer, then every later value.

        Raises:
            RuntimeError: The gate was closed (a closed gate never opens).
        """
        if self._state is GateState.CLOSED:
            msg = "a closed exposure gate never opens"
            raise RuntimeError(msg)
        self._state = GateState.OPEN
        self._publish = publish
        buffer, self._buffer = self._buffer, []
        for time, exposure in buffer:
            publish(time, exposure)

    def close(self) -> None:
        """Not glass-box (or over): drop the buffer and the publisher for good."""
        self._state = GateState.CLOSED
        self._buffer = []
        self._publish = None


def _exposure(value: Revealed) -> Exposure:
    if isinstance(value, AeadRevealed):
        return RecordRevealed(value.key, value.seq, value.nonce, value.plaintext, value.opened)
    return ValueRevealed(value)
