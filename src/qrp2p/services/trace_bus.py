"""The trace bus: public trace events from the core, per session (DESIGN §11.1, §12).

The core emits typed events that carry only public data; the bus adds the session ID and a
monotonic timestamp and keeps the last 10,000 events of each session in a ring buffer. Front ends
subscribe; the desktop app batches what it receives (at most 30 times a second, DESIGN §12).
"""

from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from qrp2p.core.trace import TraceEvent

RING_SIZE: Final = 10_000
"""Events kept per session."""
ENDED_KEPT: Final = 16
"""Rings of ended sessions kept for inspection, newest first."""


@dataclass(frozen=True, slots=True)
class TraceRecord:
    """A trace event with its session and time."""

    session_id: int
    time: float
    event: TraceEvent


type TraceSubscriber = Callable[[TraceRecord], None]


class TraceBus:
    """Per-session ring buffers of trace events, and their subscribers."""

    __slots__ = ("_ended", "_rings", "_subscribers")

    def __init__(self) -> None:
        self._rings: dict[int, deque[TraceRecord]] = {}
        self._ended: OrderedDict[int, None] = OrderedDict()
        self._subscribers: list[TraceSubscriber] = []

    def publish(self, session_id: int, time: float, event: TraceEvent) -> None:
        """Record ``event`` and pass it to every subscriber."""
        record = TraceRecord(session_id, time, event)
        ring = self._rings.get(session_id)
        if ring is None:
            ring = self._rings[session_id] = deque(maxlen=RING_SIZE)
        ring.append(record)
        for subscriber in tuple(self._subscribers):
            subscriber(record)

    def events(self, session_id: int) -> tuple[TraceRecord, ...]:
        """The events kept for a session, oldest first."""
        return tuple(self._rings.get(session_id, ()))

    def session_ended(self, session_id: int) -> None:
        """Keep the ring for a while; drop the oldest ended ring beyond :data:`ENDED_KEPT`."""
        self._ended[session_id] = None
        while len(self._ended) > ENDED_KEPT:
            oldest, _ = self._ended.popitem(last=False)
            self._rings.pop(oldest, None)

    def clear(self) -> None:
        """Forget everything (on lock)."""
        self._rings.clear()
        self._ended.clear()

    def subscribe(self, subscriber: TraceSubscriber) -> Callable[[], None]:
        """Receive every future event; returns a function that unsubscribes."""
        self._subscribers.append(subscriber)

        def unsubscribe() -> None:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)

        return unsubscribe
