"""A bounded trace mailbox between the services thread and Qt's event queue.

Qt queues only a wake signal. Captured values stay here within count and byte budgets; an
overflow replaces queued trace payloads with one catch-up notice per session. Replies and
other updates retain their posting order. Networking never waits for Qt to catch up.
"""

from dataclasses import replace
from threading import Lock
from typing import Final

from qrp2p.ui.inspect.model import item_bytes
from qrp2p.ui.snapshots import Batch, Delivery, ErrorInfo, Reply, Update
from qrp2p.ui.tap import BUFFER_BYTES, BUFFER_LIMIT, InspectSnap, TraceAppended, TraceOverflow

MAILBOX_BYTES: Final = 2 * BUFFER_BYTES
MAILBOX_ITEMS: Final = 2 * BUFFER_LIMIT
"""Room for the two Inspectors' bounded snapshots, including pending replies."""


def _cost(delivery: Delivery) -> tuple[int, int]:
    if isinstance(delivery, Reply) and isinstance(delivery.value, InspectSnap):
        return sum(item_bytes(i) for i in delivery.value.items), len(delivery.value.items)
    if isinstance(delivery, Batch):
        appended = [u for u in delivery.updates if isinstance(u, TraceAppended)]
        return (
            sum(item_bytes(i) for u in appended for i in u.items),
            sum(len(u.items) for u in appended),
        )
    return 0, 0


class Mailbox:
    """Thread-safe pending deliveries, with bounded captured trace payloads."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._queue: list[Delivery] = []
        self._bytes = 0
        self._count = 0
        self._overflow: set[tuple[int, str, int]] = set()
        self._blocked_gen = -1
        self._blocked_requests: set[int] = set()
        self._closed = False

    def put(self, delivery: Delivery) -> bool:
        """Queue a delivery; return whether Qt needs a wake signal."""
        with self._lock:
            if not self._accepts(delivery):
                return False
            wake = not self._queue
            if isinstance(delivery, Batch | Reply):
                cost, count = _cost(delivery)
                if self._bytes + cost > MAILBOX_BYTES or self._count + count > MAILBOX_ITEMS:
                    self._overflow.clear()
                    self._queue = [self._bounded(d, overflow=True) for d in self._queue]
                    self._queue = [d for d in self._queue if not isinstance(d, Batch) or d.updates]
                    self._bytes = self._count = 0
                    delivery = self._bounded(delivery, overflow=True)
                else:
                    delivery = self._bounded(delivery, overflow=False)
            if not isinstance(delivery, Batch) or delivery.updates:
                self._queue.append(delivery)
            return wake and bool(self._queue)

    def _accepts(self, delivery: Delivery) -> bool:
        """Called with the mailbox lock held; future generations survive a current lock."""
        if self._closed or (isinstance(delivery, Batch) and delivery.gen <= self._blocked_gen):
            return False
        return not (
            isinstance(delivery, Reply)
            and (
                delivery.request_id in self._blocked_requests
                or (isinstance(delivery.value, InspectSnap) and delivery.gen <= self._blocked_gen)
            )
        )

    def _bounded(self, delivery: Delivery, *, overflow: bool) -> Delivery:
        if isinstance(delivery, Reply) and isinstance(delivery.value, InspectSnap):
            if overflow:
                return replace(
                    delivery,
                    value=None,
                    error=ErrorInfo("trace_overflow", "The trace display is catching up."),
                )
            cost, count = _cost(delivery)
            self._bytes += cost
            self._count += count
        if not isinstance(delivery, Batch):
            return delivery
        updates: list[Update] = []
        for update in delivery.updates:
            forwarded = update
            if isinstance(update, TraceAppended | TraceOverflow):
                key = (delivery.gen, update.source, update.session_id)
                if key in self._overflow:
                    continue
                if overflow or isinstance(update, TraceOverflow):
                    self._overflow.add(key)
                    forwarded = TraceOverflow(update.session_id, update.source)
                else:
                    self._bytes += sum(item_bytes(i) for i in update.items)
                    self._count += len(update.items)
            updates.append(forwarded)
        return replace(delivery, updates=tuple(updates))

    def take(self) -> list[Delivery]:
        """Atomically take all pending deliveries on Qt's thread."""
        with self._lock:
            queued, self._queue = self._queue, []
            self._bytes = self._count = 0
            self._overflow.clear()
            return queued

    def clear_scoped(self, request_ids: set[int], *, gen: int) -> None:
        """Drop captured values immediately on lock, including pending scoped snapshots."""
        with self._lock:
            self._blocked_gen = max(gen, self._blocked_gen)
            self._blocked_requests.update(request_ids)
            self._queue = [d for d in self._queue if self._accepts(d)]
            costs = [_cost(d) for d in self._queue]
            self._bytes = sum(b for b, _ in costs)
            self._count = sum(n for _, n in costs)
            self._overflow = {key for key in self._overflow if key[0] > self._blocked_gen}

    def close(self) -> None:
        """Drop all queued values and refuse future posts, atomically."""
        with self._lock:
            self._closed = True
            self._queue.clear()
            self._bytes = self._count = 0
            self._overflow.clear()
