"""The Qt side of the bridge: deliveries in, requests out, stale data dropped (UI_DESIGN §11.2).

The services thread posts deliveries through a queued signal, so they arrive on the Qt thread in
the order they were posted. The bridge then applies the generation rule (:mod:`qrp2p.ui.host`):

- a :class:`~qrp2p.ui.snapshots.Lifecycle` always passes and sets the current generation;
- a :class:`~qrp2p.ui.snapshots.Batch` passes only while unlocked, for the current generation;
- a :class:`~qrp2p.ui.snapshots.Reply` to a *scoped* request passes only under the same rule;
  replies to unscoped requests (create, unlock, lock) always pass.

When the user locks, the bridge stops accepting data at once, before the services thread has
even started to close the sessions: clearing the views once is not enough if already queued
deliveries could fill them again. Scoped requests are refused while not unlocked.

View models of an unlocked period make their requests through a :class:`Scope` pinned to that
period's generation, not the bridge's current one: a view model that outlives a lock (a dialog
QML still holds, say) cannot answer a request of the next unlocked period, even though the node
numbers prompts afresh and the IDs may match.
"""

import itertools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

from PySide6.QtCore import QObject, Qt, Signal, SignalInstance

from qrp2p.services.events import NodeState
from qrp2p.ui import ops
from qrp2p.ui.host import Op, Post
from qrp2p.ui.snapshots import Batch, Delivery, Lifecycle, Reply

STARTING: Final = "starting"
"""Bridge state before the node reported its first state."""

_log = logging.getLogger(__name__)

type Done = Callable[[Reply], None]


class Host(Protocol):
    """What the bridge needs of :class:`~qrp2p.ui.host.ServiceHost` (tests use a fake)."""

    def start(self) -> None:
        """Start; the first lifecycle delivery follows."""
        ...

    def submit(self, gen: int, request_id: int, op: Op, *, scoped: bool) -> None:
        """Run ``op``; its reply follows."""
        ...

    def stop(self, timeout: float = ...) -> bool:  # a thread join, not async
        """Close the node and end; ``False`` if it did not end in time."""
        ...


@dataclass(frozen=True, slots=True)
class _Pending:
    gen: int
    scoped: bool
    done: Done | None


class Scope:
    """Makes requests for one generation; refused once that generation is over."""

    __slots__ = ("_bridge", "_gen")

    def __init__(self, bridge: Bridge, gen: int) -> None:
        self._bridge = bridge
        self._gen = gen

    @property
    def gen(self) -> int:
        """The generation these requests belong to."""
        return self._gen

    @property
    def updates(self) -> SignalInstance:
        """The bridge's update signal (it carries only the current generation's updates)."""
        return self._bridge.updates

    def request(self, op: Op, done: Done | None = None) -> bool:
        """Run ``op`` if this generation is still the current, accepting one."""
        return self._bridge.submit_for(self._gen, op, done)


class Bridge(QObject):
    """Connects view models to the services host.

    Args:
        make_host: Builds the host given the function it posts deliveries with.
        parent: The Qt parent.
    """

    lifecycle = Signal(object)
    """A :class:`Lifecycle` was accepted."""
    updates = Signal(object)
    """A tuple of updates of the current unlocked generation."""
    _arrived = Signal(object)

    def __init__(self, make_host: Callable[[Post], Host], parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._arrived.connect(self._dispatch, Qt.ConnectionType.QueuedConnection)
        self._gen = 0
        self._state = STARTING
        self._locking = False
        self._closed = False
        self._pending: dict[int, _Pending] = {}
        self._ids = itertools.count(1)
        self._host = make_host(self._post)

    @property
    def gen(self) -> int:
        """The current generation."""
        return self._gen

    @property
    def state(self) -> str:
        """The node's last reported state (``starting`` before the first)."""
        return self._state

    @property
    def accepting(self) -> bool:
        """Data and scoped requests are accepted: unlocked, and no lock under way."""
        return self._state == NodeState.UNLOCKED and not self._locking and not self._closed

    def start(self) -> None:
        """Start the services thread."""
        self._host.start()

    def request(self, op: Op, done: Done | None = None, *, scoped: bool = True) -> bool:
        """Run ``op`` on the services thread; ``done`` gets its reply on the Qt thread.

        A scoped request belongs to the current generation and is refused (``False``, and
        ``done`` is never called) unless the bridge is accepting: its reply would belong to a
        generation the views no longer show. View models use :meth:`scope` instead.
        """
        return self._submit(op, done, self._gen, scoped=scoped)

    def submit_for(self, gen: int, op: Op, done: Done | None = None) -> bool:
        """A scoped request of generation ``gen``: refused unless it is the current one."""
        return self._submit(op, done, gen, scoped=True)

    def scope(self) -> Scope:
        """Requests pinned to the current generation (for one unlocked period's view models)."""
        return Scope(self, self._gen)

    def _submit(self, op: Op, done: Done | None, gen: int, *, scoped: bool) -> bool:
        if self._closed or (scoped and not (self.accepting and gen == self._gen)):
            return False
        request_id = next(self._ids)
        self._pending[request_id] = _Pending(gen, scoped, done)
        self._host.submit(gen, request_id, op, scoped=scoped)
        return True

    def lock(self, done: Done | None = None) -> None:
        """Lock: stop accepting data now, then lock the node."""
        self._locking = True
        self._drop_scoped()
        self.request(ops.lock(), done, scoped=False)

    def stop(self, timeout: float) -> bool:
        """Stop accepting anything, then close the node and end the services thread."""
        self._closed = True
        self._pending.clear()
        return self._host.stop(timeout)

    # -- deliveries ------------------------------------------------------------------------------

    def _post(self, delivery: Delivery) -> None:
        """Called on the services thread: queue the delivery for the Qt thread."""
        if not self._closed:
            self._arrived.emit(delivery)

    def _dispatch(self, delivery: Delivery) -> None:
        if self._closed:
            return
        match delivery:
            case Lifecycle():
                if delivery.gen < self._gen:  # cannot happen: deliveries keep their order
                    _log.error("an older lifecycle arrived late; ignored")
                    return
                self._gen = delivery.gen
                self._state = delivery.state
                self._locking = False
                self._drop_scoped()
                self.lifecycle.emit(delivery)
            case Batch():
                if delivery.gen == self._gen and self.accepting:
                    self.updates.emit(delivery.updates)
            case Reply():
                pending = self._pending.pop(delivery.request_id, None)
                if pending is None or pending.done is None:
                    return
                if pending.scoped and not (delivery.gen == self._gen and self.accepting):
                    return
                pending.done(delivery)

    def _drop_scoped(self) -> None:
        for request_id in [i for i, p in self._pending.items() if p.scoped]:
            del self._pending[request_id]
