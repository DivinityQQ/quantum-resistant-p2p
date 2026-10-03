"""The deliveries on their way from the services thread to the Qt thread (DESIGN §11.2).

Qt's event queue holds only a wake signal; the deliveries wait here, in order, until the Qt
thread takes them all at once. The trace stream is the one thing a busy Qt thread could let
pile up, so it is bounded: beyond :data:`MAILBOX_ITEMS` events or :data:`MAILBOX_BYTES`
captured bytes, the queued and later trace events of each stream become one
:class:`~qrp2p.ui.tap.TraceOverflow`, and the Inspector catches up with a fresh snapshot.
Everything else is kept: replies are one per request, and an Inspector snapshot is bounded by
what the bus retains. Networking never waits for Qt.
"""

from dataclasses import replace
from threading import Lock
from typing import Final

from qrp2p.ui.inspect.model import item_bytes
from qrp2p.ui.snapshots import Batch, Delivery, Update
from qrp2p.ui.tap import BUFFER_BYTES, BUFFER_LIMIT, TraceAppended, TraceOverflow

MAILBOX_ITEMS: Final = 2 * BUFFER_LIMIT
MAILBOX_BYTES: Final = 2 * BUFFER_BYTES
"""Room for both taps' bounded buffers (the node's and the lab's)."""


class Mailbox:
    """Thread-safe pending deliveries, with a bounded trace stream."""

    __slots__ = ("_bytes", "_closed", "_count", "_lock", "_noticed", "_overflowing", "_queue")

    def __init__(self) -> None:
        self._lock = Lock()
        self._queue: list[Delivery] = []
        self._count = 0
        self._bytes = 0
        self._overflowing = False
        self._noticed: set[tuple[int, str, int]] = set()
        """The streams (generation, source, session) already given their overflow notice."""
        self._closed = False

    def put(self, delivery: Delivery) -> bool:
        """Queue a delivery (services thread); ``True`` if the Qt thread needs a wake signal."""
        with self._lock:
            if self._closed:
                return False
            asleep = not self._queue
            if isinstance(delivery, Batch):
                delivery = self._bounded(delivery)
                if not delivery.updates:
                    return False
            self._queue.append(delivery)
            return asleep

    def take(self) -> list[Delivery]:
        """Every pending delivery, oldest first (Qt thread)."""
        with self._lock:
            queued, self._queue = self._queue, []
            self._count = self._bytes = 0
            self._overflowing = False
            self._noticed.clear()
            return queued

    def close(self) -> None:
        """Drop what is queued and refuse what follows."""
        with self._lock:
            self._closed = True
            self._queue.clear()

    def _bounded(self, batch: Batch) -> Batch:
        if not self._overflowing:
            streamed = [u for u in batch.updates if isinstance(u, TraceAppended)]
            count = sum(len(u.items) for u in streamed)
            size = sum(item_bytes(i) for u in streamed for i in u.items)
            if self._count + count <= MAILBOX_ITEMS and self._bytes + size <= MAILBOX_BYTES:
                self._count += count
                self._bytes += size
                return batch
            self._overflowing = True  # until the Qt thread takes what is queued
            self._count = self._bytes = 0
            queued = (self._noticing(d) if isinstance(d, Batch) else d for d in self._queue)
            self._queue = [d for d in queued if not isinstance(d, Batch) or d.updates]
        return self._noticing(batch)

    def _noticing(self, batch: Batch) -> Batch:
        """``batch`` with its trace events replaced by one overflow notice per stream."""
        updates: list[Update] = []
        for update in batch.updates:
            if isinstance(update, TraceAppended | TraceOverflow):
                stream = (batch.gen, update.source, update.session_id)
                if stream in self._noticed:
                    continue
                self._noticed.add(stream)
                updates.append(TraceOverflow(update.session_id, update.source))
            else:
                updates.append(update)
        return replace(batch, updates=tuple(updates))
