"""Events shared by the sans-I/O state machines (IMPLEMENTATION_PLAN M1).

The core never performs I/O. Its machines take bytes, decisions and the current time, and return
a list of events telling the services what to do: send a frame, queue a message for the writer,
deliver a message to the user, or close the connection.
"""

from dataclasses import dataclass
from enum import IntEnum

from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.trace import TraceEvent
from qrp2p.core.wire import Frame, Inner


class Priority(IntEnum):
    """Writer queue priorities (DESIGN §8.3): lower drains first."""

    CONTROL = 0
    CHAT = 1
    FILE = 2


@dataclass(frozen=True, slots=True)
class Send:
    """Write this frame now, in order with every other ``Send`` of the connection."""

    frame: Frame


@dataclass(frozen=True, slots=True)
class Queue:
    """Put ``message`` on the writer's queue; the writer seals it at dequeue (DESIGN §8.3)."""

    message: Inner
    priority: Priority


@dataclass(frozen=True, slots=True)
class Deliver:
    """An application message from the peer (chat, receipt, file transfer)."""

    message: Inner


@dataclass(frozen=True, slots=True)
class Trace:
    """A trace event for the Inspector."""

    event: TraceEvent


@dataclass(frozen=True, slots=True)
class Closed:
    """The handshake or session is over.

    Flush anything already queued (a ``close`` record, when one was queued), then drop the
    connection. Pre-authentication failures queue nothing: they close silently (DESIGN §8.5).
    """

    reason: CloseReason
    admit_reason: AdmitReason | None = None
    by_peer: bool = False
