"""The services-thread side of the Inspector: one inspected session's trace, as snapshots.

A tap reads one trace bus: the node's (real sessions) or the solo lab's. Its updates carry the
name of that ``source``, so the Inspector of the messenger and the lab's never mix them up.

The trace bus lives on the services thread. When the Inspector opens a session, :class:`TraceTap`
takes the session's retained events and starts forwarding its new ones *in the same loop step*,
so no event falls between the snapshot and the subscription and none arrives twice (ordinals let
the Qt side check). New events wait in a bounded buffer that the host drains into each 30 Hz
batch; if a burst overflows it, the buffer is dropped and the Qt side is told to catch up from its
last ordinal, which the bus answers with a gap marker if events were evicted meanwhile.

*Pause following* stops forwarding; *Follow live* asks for everything after the last ordinal
seen. A paused Inspector therefore queues nothing, however long it stays paused (UI_DESIGN §7.2).

Values revealed by a glass-box session's exposure gate are unwrapped here, for that session
only: a normal session has no such records on the bus at all.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from qrp2p.lab.classical import lab_profile_named
from qrp2p.services.exposure import RecordRevealed, ValueRevealed
from qrp2p.services.node import Node, NodeError
from qrp2p.services.trace_bus import RING_BYTES, SessionInfo, TraceBus, TraceRecord, event_bytes
from qrp2p.ui.inspect.model import (
    Item,
    ProfileFacts,
    RecordOpened,
    Revealed,
    SessionFacts,
    TraceItem,
)
from qrp2p.ui.text import display_name

BUFFER_LIMIT: Final = 20_000
"""Events held between two batches at most; beyond it the Qt side catches up instead."""
BUFFER_BYTES: Final = 2 * RING_BYTES


@dataclass(frozen=True, slots=True)
class InspectSnap:
    """A session's descriptor and retained events (the reply to opening or catching up)."""

    facts: SessionFacts
    items: tuple[TraceItem, ...]
    missing: bool
    """Events after the ordinal asked for are no longer retained (a gap before ``items``)."""


@dataclass(frozen=True, slots=True)
class TraceAppended:
    """New events of the inspected session, in order."""

    session_id: int
    items: tuple[TraceItem, ...]
    source: str = "node"


@dataclass(frozen=True, slots=True)
class TraceOverflow:
    """Events of the inspected session were dropped in transit: catch up from the last ordinal."""

    session_id: int
    source: str = "node"


@dataclass(frozen=True, slots=True)
class SessionDescribed:
    """A retained session appeared or its descriptor changed."""

    facts: SessionFacts
    source: str = "node"


@dataclass(frozen=True, slots=True)
class SessionRemoved:
    """A session's retained ring was evicted."""

    session_id: int
    source: str = "node"


def profile_facts(name: str) -> ProfileFacts | None:
    """A profile's algorithms and sizes (``LAB-CLASSICAL`` too); ``None`` for an unknown name."""
    profile = lab_profile_named(name)
    if profile is None:
        return None
    return ProfileFacts(
        name=profile.name,
        kem=profile.kem.name,
        signature=profile.sig.name,
        aead=profile.aead.value,
        hash=profile.hash.name,
        hash_len=profile.hash_len,
        sig_len=profile.sig_len,
        ek_len=profile.ek_len,
        ct_len=profile.ct_len,
        ek_parts=profile.kem.ek_parts,
        ct_parts=profile.kem.ct_parts,
        lab_only=profile.lab_only,
    )


def session_facts(node: Node, info: SessionInfo) -> SessionFacts:
    """What the Inspector shows about a session besides its trace."""
    contact = node.contact_for_peer(info.peer_id) if info.peer_id else None
    return SessionFacts(
        session_id=info.session_id,
        initiator=info.initiator,
        address=display_name(info.address),
        profile=profile_facts(info.profile) if info.profile else None,
        local_name="You",
        peer_name=display_name(contact.name) if contact is not None else info.peer_short_id,
        peer_short_id=info.peer_short_id,
        contact_id=contact.contact_id.hex() if contact is not None else "",
        trust=contact.trust.value if contact is not None else "",
        pinned_before=info.pinned,
        glass_box_requested=info.glass_box_requested,
        glass_box=info.glass_box,
        exposed=info.glass_box,
        lab=False,
        established=info.established,
        ended=info.ended,
        end_reason=info.end_reason,
        admit_reason=info.admit_reason,
        by_peer=info.by_peer,
        pin_result=info.pin_result,
        contact_saved=info.contact_saved,
    )


def trace_item(record: TraceRecord) -> TraceItem:
    """A bus record as an immutable snapshot; revealed values become bytes."""
    event = record.event
    item: Item
    match event:
        case ValueRevealed(secret=secret):
            item = Revealed(secret.label, secret.reveal())
        case RecordRevealed():
            item = RecordOpened(
                event.key, event.seq, event.nonce.reveal(), event.plaintext.reveal(), event.opened
            )
        case _:
            item = event
    return TraceItem(record.ordinal, record.time, item)


type Update = TraceAppended | TraceOverflow | SessionDescribed | SessionRemoved


type Describe = Callable[[SessionInfo], SessionFacts]
"""What the Inspector shows about a session besides its trace, from its descriptor."""


class TraceTap:
    """Forwards one inspected session's events and every descriptor change (services thread).

    Args:
        bus: The trace bus to read.
        describe: A session's facts from its descriptor.
        wake: Asks the host to flush soon; called when the first update is pending.
        source: The name its updates carry (``node`` or ``lab``).
    """

    def __init__(
        self, bus: TraceBus, describe: Describe, wake: Callable[[], None], source: str = "node"
    ) -> None:
        self._bus = bus
        self._describe = describe
        self._source = source
        self._wake = wake
        self._session: int | None = None
        self._watching = False
        self._buffer: list[TraceItem] = []
        self._buffer_bytes = 0
        self._overflowed = False
        self._described: dict[int, SessionFacts] = {}
        self._removed: dict[int, None] = {}
        self._unsubscribe = (
            bus.subscribe(self._on_record),
            bus.subscribe_sessions(self._on_session),
            bus.subscribe_removals(self._on_removed),
        )

    @classmethod
    def of_node(cls, node: Node, wake: Callable[[], None]) -> TraceTap:
        """The tap of the node's own sessions."""
        return cls(node.trace, lambda info: session_facts(node, info), wake)

    def detach(self) -> None:
        """Stop reading the bus for good (the lab replaced its bus)."""
        self.close()
        for unsubscribe in self._unsubscribe:
            unsubscribe()

    # -- requests (services thread) --------------------------------------------------------------

    def sessions(self) -> tuple[SessionFacts, ...]:
        """Every retained session, oldest first; descriptor changes are forwarded from now on."""
        self._watching = True
        self._described.clear()
        self._removed.clear()
        return tuple(self._describe(info) for info in self._bus.sessions())

    def inspect(self, session_id: int, after: int = -1) -> InspectSnap:
        """The session's retained events after ``after``; its new events are forwarded from now.

        Raises:
            NodeError: The session's ring is no longer kept.
        """
        info = self._bus.info(session_id)
        if info is None:
            msg = "that session is no longer retained"
            raise NodeError(msg)
        records, missing = self._bus.since(session_id, after)
        self._session = session_id
        self._buffer.clear()
        self._buffer_bytes = 0
        self._overflowed = False
        items = tuple(trace_item(r) for r in records)
        return InspectSnap(self._describe(info), items, missing)

    def pause(self) -> None:
        """Stop forwarding events (the display is paused, or shows another view)."""
        self._session = None
        self._buffer.clear()
        self._buffer_bytes = 0
        self._overflowed = False

    def close(self) -> None:
        """The Inspector closed: forward nothing."""
        self.pause()
        self._watching = False
        self._described.clear()
        self._removed.clear()

    def drain(self) -> list[Update]:
        """The updates pending since the last batch, oldest first."""
        updates: list[Update] = list(self._described_updates())
        updates.extend(SessionRemoved(s, self._source) for s in self._removed)
        self._removed.clear()
        session = self._session
        if session is not None and self._overflowed:
            updates.append(TraceOverflow(session, self._source))
        elif session is not None and self._buffer:
            updates.append(TraceAppended(session, tuple(self._buffer), self._source))
        self._buffer.clear()
        self._buffer_bytes = 0
        self._overflowed = False
        return updates

    # -- bus callbacks ---------------------------------------------------------------------------

    def _on_record(self, record: TraceRecord) -> None:
        if record.session_id != self._session or self._overflowed:
            return
        cost = event_bytes(record.event)
        if len(self._buffer) >= BUFFER_LIMIT or self._buffer_bytes + cost > BUFFER_BYTES:
            self._buffer.clear()
            self._buffer_bytes = 0
            self._overflowed = True
        else:
            self._buffer.append(trace_item(record))
            self._buffer_bytes += cost
        self._wake()

    def _on_session(self, info: SessionInfo) -> None:
        if not self._watching:
            return
        self._described[info.session_id] = self._describe(info)
        self._wake()

    def _on_removed(self, session_id: int) -> None:
        self._described.pop(session_id, None)
        if session_id == self._session:
            self.pause()
        if self._watching:
            self._removed[session_id] = None
            self._wake()

    def _described_updates(self) -> list[SessionDescribed]:
        updates = [SessionDescribed(facts, self._source) for facts in self._described.values()]
        self._described.clear()
        return updates
