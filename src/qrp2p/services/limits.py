"""Resource limits of the services (DESIGN §6.4, §8.3, §9) and the two small tools that enforce them.

Before authentication a peer can make the responder hold at most one bounded frame and one
half-open slot, both globally capped (property P6). The frame bound is the core's
:class:`~qrp2p.core.wire.FrameReader`; the slots and the Hello rate are enforced here.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Final

MAX_HALF_OPEN: Final = 32
"""Handshakes in progress, all sources together."""
MAX_HALF_OPEN_PER_SOURCE: Final = 4
"""Handshakes in progress from one source address."""
HELLO_RATE: Final = 20.0
"""Hellos per second the responder processes (token bucket refill rate)."""
HELLO_BURST: Final = 40
"""Token bucket capacity."""
MAX_LIVE_SESSIONS: Final = 64
MAX_PENDING_OFFERS: Final = 3
"""File offers from one contact that wait for the user's decision."""

CONNECT_TIMEOUT: Final = 5.0
"""Seconds to open a TCP connection to one address."""
WRITE_TIMEOUT: Final = 90.0
"""Seconds a write may wait for the peer to read before the session is given up (the idle
timeout, applied to the sending direction)."""
FLUSH_TIMEOUT: Final = 5.0
"""Seconds to flush the final frames (a ``close`` record, a reject) before the connection drops."""
MAX_WRITE_BACKLOG: Final = 4096
"""Messages waiting for the writer. A peer that makes us answer faster than it reads (pings,
chats that need receipts) is closed with ``rate_limited`` rather than buffered without bound."""
FILE_QUEUE_SLOTS: Final = 8
"""File chunks a transfer may have in the writer queue at once; the sender waits for room."""
TICK_INTERVAL: Final = 0.5
"""Seconds between timer ticks of the handshakes and channels (deadlines, pings, rekeys)."""


@dataclass(slots=True)
class TokenBucket:
    """A token bucket over an injected monotonic clock.

    Args:
        rate: Tokens added per second.
        burst: Capacity; the bucket starts full.
    """

    rate: float
    burst: int
    _tokens: float = field(init=False)
    _last: float | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)

    def take(self, now: float) -> bool:
        """Take one token at time ``now``; ``False`` when the bucket is empty."""
        if self._last is not None:
            elapsed = max(now - self._last, 0.0)
            self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate)
        self._last = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True


class SlotPool:
    """Half-open handshake slots, capped globally and per source address.

    Args:
        total: The global cap.
        per_source: The cap per source address.
    """

    __slots__ = ("_by_source", "_per_source", "_total")

    def __init__(
        self, total: int = MAX_HALF_OPEN, per_source: int = MAX_HALF_OPEN_PER_SOURCE
    ) -> None:
        self._total = total
        self._per_source = per_source
        self._by_source: Counter[str] = Counter()

    @property
    def in_use(self) -> int:
        """Slots held now."""
        return self._by_source.total()

    def acquire(self, source: str) -> bool:
        """Take a slot for ``source``; ``False`` when either cap is reached."""
        if self.in_use >= self._total or self._by_source[source] >= self._per_source:
            return False
        self._by_source[source] += 1
        return True

    def release(self, source: str) -> None:
        """Return a slot taken by :meth:`acquire`.

        Raises:
            ValueError: ``source`` holds no slot.
        """
        if self._by_source[source] <= 0:
            msg = "no slot held for this source"
            raise ValueError(msg)
        self._by_source[source] -= 1
        if not self._by_source[source]:
            del self._by_source[source]
