"""The trace bus: what the Inspector may show about each session (DESIGN §11.1, §11.2, §12).

The core emits typed events that carry only public data; the bus adds the session ID, a
session-scoped **ordinal** (0, 1, 2… in the order things happened) and a monotonic timestamp.
Glass-box sessions add the values their exposure gate let through (:mod:`~qrp2p.services.exposure`),
as records of their own type, never as public trace events.

**Retention.** A session's handshake events are kept for as long as the session's ring is: the
handshake is the part learners inspect most, and it is small and bounded. What follows goes to a
ring bounded by :data:`RING_SIZE` events **and** :data:`RING_BYTES` bytes of frames and revealed
values, so a file transfer cannot make one session hold more than a few megabytes. Rings of the
last :data:`ENDED_KEPT` ended sessions stay inspectable. Ordinals make evicted events visible: a
front end sees exactly which ordinals are missing.

**Descriptors.** The bus also keeps what the services know about each session (role, address,
profile, the authenticated peer, exposure, how it ended), so a failed handshake can be inspected
as well as an open session.

Front ends subscribe; the desktop app batches what it receives (at most 30 times a second, DESIGN
§12). Locking clears everything.
"""

from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Final

from qrp2p.core.trace import FrameTraced, TraceEvent
from qrp2p.core.wire import FRAME_HEADER_LEN
from qrp2p.services.exposure import Exposure, RecordRevealed, ValueRevealed

RING_SIZE: Final = 10_000
"""Events kept per session after its handshake."""
RING_BYTES: Final = 4 * 1024 * 1024
"""Bytes of frames and revealed values kept per session after its handshake."""
HEAD_LIMIT: Final = 2_000
"""Handshake events kept at most per session (a handshake emits about a hundred)."""
ENDED_KEPT: Final = 16
"""Rings of ended sessions kept for inspection, newest first."""


type BusEvent = TraceEvent | Exposure


@dataclass(frozen=True, slots=True)
class TraceRecord:
    """A trace event with its session, its ordinal in that session and its time."""

    session_id: int
    ordinal: int
    time: float
    event: BusEvent


@dataclass(frozen=True, slots=True)
class SessionInfo:
    """What the services know about a session, for choosing it in the Inspector.

    Everything here is public or local: the peer is named by its ``peer_id`` only once the
    handshake authenticated it.
    """

    session_id: int
    initiator: bool
    address: str
    started: float
    profile: str = ""
    pinned: bool = False
    """We initiated to a contact: the responder had to prove its pinned identity first."""
    peer_id: bytes = b""
    """The authenticated peer; empty before authentication (and for a failed handshake)."""
    peer_short_id: str = ""
    glass_box_requested: bool = False
    glass_box: bool = False
    """Admitted as glass-box: values are revealed into this session's ring."""
    established: bool = False
    ended: bool = False
    end_reason: str = ""
    """The close reason's label; empty if the connection was lost, or while not ended."""
    admit_reason: str = ""
    """A refusal's admission reason (``declined``, ``busy``…); empty otherwise."""
    by_peer: bool = False


def event_bytes(event: BusEvent) -> int:
    """What an event costs the ring's byte budget: its frame or revealed bytes."""
    match event:
        case FrameTraced(frame=frame):
            return FRAME_HEADER_LEN + len(frame.body)
        case RecordRevealed(nonce=nonce, plaintext=plaintext):
            return len(nonce) + len(plaintext)
        case ValueRevealed(secret=secret):
            return len(secret)
        case _:
            return 0


type TraceSubscriber = Callable[[TraceRecord], None]
type SessionSubscriber = Callable[[SessionInfo], None]


class _Ring:
    """One session's events: the handshake head, then a bounded tail."""

    __slots__ = ("head", "head_open", "info", "next_ordinal", "tail", "tail_bytes")

    def __init__(self, info: SessionInfo) -> None:
        self.info = info
        self.head: list[TraceRecord] = []
        self.head_open = True
        self.tail: deque[TraceRecord] = deque()
        self.tail_bytes = 0
        self.next_ordinal = 0

    def add(self, record: TraceRecord) -> None:
        if self.head_open and len(self.head) < HEAD_LIMIT:
            self.head.append(record)
            return
        self.tail.append(record)
        self.tail_bytes += event_bytes(record.event)
        while len(self.tail) > RING_SIZE or (self.tail_bytes > RING_BYTES and len(self.tail) > 1):
            self.tail_bytes -= event_bytes(self.tail.popleft().event)

    def records(self) -> tuple[TraceRecord, ...]:
        return (*self.head, *self.tail)


class TraceBus:
    """Per-session retained trace events and descriptors, and their subscribers."""

    __slots__ = ("_ended", "_rings", "_session_subscribers", "_subscribers")

    def __init__(self) -> None:
        self._rings: dict[int, _Ring] = {}
        self._ended: OrderedDict[int, None] = OrderedDict()
        self._subscribers: list[TraceSubscriber] = []
        self._session_subscribers: list[SessionSubscriber] = []

    # -- sessions -----------------------------------------------------------------------------------

    def open_session(self, info: SessionInfo) -> None:
        """Start a session's ring with what is known when its connection opens."""
        self._rings[info.session_id] = _Ring(info)
        self._announce(info)

    def describe(self, session_id: int, **changes: object) -> None:
        """Update a session's descriptor (fields of :class:`SessionInfo`)."""
        ring = self._rings.get(session_id)
        if ring is None:
            return
        info = replace(ring.info, **changes)
        if info != ring.info:
            ring.info = info
            self._announce(info)

    def handshake_done(self, session_id: int) -> None:
        """The handshake is over: later events go to the bounded tail."""
        ring = self._rings.get(session_id)
        if ring is not None:
            ring.head_open = False

    def session_ended(self, session_id: int) -> None:
        """Keep the ring for a while; drop the oldest ended ring beyond :data:`ENDED_KEPT`."""
        self.handshake_done(session_id)
        self.describe(session_id, ended=True)
        self._ended[session_id] = None
        while len(self._ended) > ENDED_KEPT:
            oldest, _ = self._ended.popitem(last=False)
            self._rings.pop(oldest, None)

    def sessions(self) -> tuple[SessionInfo, ...]:
        """Every session with a ring, oldest first."""
        return tuple(ring.info for ring in self._rings.values())

    def info(self, session_id: int) -> SessionInfo | None:
        """A session's descriptor, if its ring is kept."""
        ring = self._rings.get(session_id)
        return ring.info if ring is not None else None

    # -- events -------------------------------------------------------------------------------------

    def publish(self, session_id: int, time: float, event: BusEvent) -> None:
        """Record ``event`` and pass it to every subscriber.

        Events of a session the bus does not know (it was opened before a lock cleared the bus,
        or its ring was dropped) start a ring with an empty descriptor.
        """
        ring = self._rings.get(session_id)
        if ring is None:
            info = SessionInfo(session_id, initiator=False, address="", started=time)
            ring = self._rings[session_id] = _Ring(info)
        record = TraceRecord(session_id, ring.next_ordinal, time, event)
        ring.next_ordinal += 1
        ring.add(record)
        for subscriber in tuple(self._subscribers):
            subscriber(record)

    def events(self, session_id: int) -> tuple[TraceRecord, ...]:
        """The events kept for a session, oldest first (ordinals may skip where evicted)."""
        ring = self._rings.get(session_id)
        return ring.records() if ring is not None else ()

    def since(self, session_id: int, ordinal: int) -> tuple[tuple[TraceRecord, ...], bool]:
        """The kept events after ``ordinal``, and whether some after it are no longer kept."""
        ring = self._rings.get(session_id)
        if ring is None:
            return (), False
        later = tuple(r for r in ring.records() if r.ordinal > ordinal)
        expected = ordinal + 1
        missing = (later[0].ordinal if later else ring.next_ordinal) > expected
        return later, missing

    def clear(self) -> None:
        """Forget everything (on lock)."""
        self._rings.clear()
        self._ended.clear()

    # -- subscribers --------------------------------------------------------------------------------

    def subscribe(self, subscriber: TraceSubscriber) -> Callable[[], None]:
        """Receive every future event; returns a function that unsubscribes."""
        return _add(self._subscribers, subscriber)

    def subscribe_sessions(self, subscriber: SessionSubscriber) -> Callable[[], None]:
        """Receive every new or changed descriptor; returns a function that unsubscribes."""
        return _add(self._session_subscribers, subscriber)

    def _announce(self, info: SessionInfo) -> None:
        for subscriber in tuple(self._session_subscribers):
            subscriber(info)


def _add[T](subscribers: list[T], subscriber: T) -> Callable[[], None]:
    subscribers.append(subscriber)

    def unsubscribe() -> None:
        if subscriber in subscribers:
            subscribers.remove(subscriber)

    return unsubscribe
