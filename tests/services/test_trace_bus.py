"""The trace bus (DESIGN §11.2, §12): ordinals, retention, descriptors and subscribers."""

from qrp2p.core.crypto.secret import Secret
from qrp2p.core.trace import Direction, FrameTraced, StateChanged
from qrp2p.core.wire import Frame, FrameType
from qrp2p.services.exposure import RecordRevealed, ValueRevealed
from qrp2p.services.trace_bus import (
    ENDED_KEPT,
    HEAD_LIMIT,
    RING_BYTES,
    RING_SIZE,
    SessionInfo,
    TraceBus,
    event_bytes,
)

STATE = StateChanged("m", "s")


def frame_event(size: int) -> FrameTraced:
    return FrameTraced(Direction.OUT, Frame(FrameType.RECORD, bytes(size)), ())


def opened(bus: TraceBus, session_id: int = 1) -> TraceBus:
    bus.open_session(SessionInfo(session_id, initiator=True, address="h:1", started=0.0))
    return bus


def test_records_carry_session_ordinals_and_times() -> None:
    bus = opened(TraceBus())
    bus.publish(1, 1.5, STATE)
    bus.publish(2, 2.0, STATE)  # an unknown session gets a ring of its own
    bus.publish(1, 3.0, STATE)
    assert [(r.session_id, r.ordinal, r.time) for r in bus.events(1)] == [(1, 0, 1.5), (1, 1, 3.0)]
    assert [r.ordinal for r in bus.events(2)] == [0]
    assert bus.info(2) == SessionInfo(2, initiator=False, address="", started=2.0)


def test_the_handshake_is_kept_while_the_tail_is_bounded_by_count() -> None:
    bus = opened(TraceBus())
    for n in range(10):
        bus.publish(1, float(n), STATE)
    bus.handshake_done(1)
    for n in range(RING_SIZE + 5):
        bus.publish(1, 100.0 + n, STATE)
    events = bus.events(1)
    assert len(events) == 10 + RING_SIZE
    assert [r.ordinal for r in events[:11]] == [*range(10), 15]  # 10 to 14 were evicted
    assert events[-1].ordinal == 10 + RING_SIZE + 4


def test_the_tail_is_bounded_by_bytes() -> None:
    """A file transfer must not make one session hold more than RING_BYTES of frames."""
    bus = opened(TraceBus())
    bus.handshake_done(1)
    size = 16_000
    for n in range(1000):
        bus.publish(1, float(n), frame_event(size))
    kept = bus.events(1)
    total = sum(event_bytes(r.event) for r in kept)
    assert total <= RING_BYTES
    assert total > RING_BYTES - (size + 5)
    assert kept[-1].ordinal == 999


def test_one_oversized_event_cannot_exceed_the_byte_budget() -> None:
    bus = opened(TraceBus())
    bus.handshake_done(1)
    bus.publish(1, 0.0, frame_event(16_000))
    big = ValueRevealed(Secret(bytes(RING_BYTES + 1), "x"))
    bus.publish(1, 1.0, big)
    assert bus.events(1) == ()
    assert bus.since(1, -1) == ((), True)


def test_the_handshake_head_also_has_a_byte_budget() -> None:
    bus = opened(TraceBus())
    for n in range(1000):
        bus.publish(1, float(n), frame_event(16_000))
    assert sum(event_bytes(r.event) for r in bus.events(1)) <= 2 * RING_BYTES
    assert bus.events(1)[0].ordinal == 0
    assert bus.events(1)[-1].ordinal == 999
    assert any(
        b.ordinal != a.ordinal + 1 for a, b in zip(bus.events(1), bus.events(1)[1:], strict=False)
    )


def test_ring_evictions_are_announced_and_unsubscribe_cleanly() -> None:
    bus = TraceBus()
    removed: list[int] = []
    unsubscribe = bus.subscribe_removals(removed.append)
    for session_id in range(ENDED_KEPT + 3):
        opened(bus, session_id)
        bus.session_ended(session_id)
    assert removed == [0, 1, 2]
    assert len(bus.sessions()) == ENDED_KEPT
    unsubscribe()
    bus.clear()
    assert removed == [0, 1, 2]


def test_event_bytes_counts_frames_and_revealed_values() -> None:
    assert event_bytes(frame_event(100)) == 105
    assert event_bytes(ValueRevealed(Secret(bytes(32), "hs"))) == 32
    revealed = RecordRevealed("k", 0, Secret(bytes(12), "n"), Secret(bytes(40), "p"), opened=True)
    assert event_bytes(revealed) == 52
    assert event_bytes(STATE) == 0


def test_the_head_has_a_safety_limit() -> None:
    bus = opened(TraceBus())
    for n in range(HEAD_LIMIT + 3):
        bus.publish(1, float(n), STATE)
    assert len(bus.events(1)) == HEAD_LIMIT + 3  # the rest went to the tail


def test_since_reports_events_after_an_ordinal_and_gaps() -> None:
    bus = opened(TraceBus())
    bus.handshake_done(1)
    for n in range(RING_SIZE + 10):
        bus.publish(1, float(n), STATE)
    later, missing = bus.since(1, RING_SIZE + 5)
    assert [r.ordinal for r in later] == list(range(RING_SIZE + 6, RING_SIZE + 10))
    assert not missing
    later, missing = bus.since(1, 3)  # 4 to 9 were evicted
    assert later[0].ordinal == 10
    assert missing
    assert bus.since(1, RING_SIZE + 9) == ((), False)  # up to date
    assert bus.since(99, 0) == ((), False)


def test_since_sees_a_gap_even_when_nothing_is_kept_after_it() -> None:
    bus = opened(TraceBus())
    bus.handshake_done(1)
    bus.publish(1, 0.0, STATE)
    bus.publish(1, 0.0, ValueRevealed(Secret(bytes(RING_BYTES + 1), "big")))  # evicts ordinal 0
    later, missing = bus.since(1, -1)
    assert (later, missing) == ((), True)


def test_descriptors_are_announced_when_they_change() -> None:
    bus = TraceBus()
    seen: list[SessionInfo] = []
    unsubscribe = bus.subscribe_sessions(seen.append)
    opened(bus)
    bus.describe(1, profile="HYBRID-1")
    bus.describe(1, profile="HYBRID-1")  # unchanged: not announced again
    bus.describe(42, profile="x")  # unknown session: ignored
    bus.session_ended(1)
    assert [(i.profile, i.ended) for i in seen] == [
        ("", False),
        ("HYBRID-1", False),
        ("HYBRID-1", True),
    ]
    assert bus.sessions() == (seen[-1],)
    unsubscribe()
    bus.describe(1, end_reason="normal")
    assert len(seen) == 3


def test_event_subscribers() -> None:
    bus = TraceBus()
    seen: list[int] = []
    unsubscribe = bus.subscribe(lambda record: seen.append(record.ordinal))
    bus.publish(1, 0.0, STATE)
    bus.publish(1, 0.0, STATE)
    unsubscribe()
    unsubscribe()  # twice is harmless
    bus.publish(1, 0.0, STATE)
    assert seen == [0, 1]


def test_rings_of_ended_sessions_are_bounded() -> None:
    bus = TraceBus()
    bus.session_ended(500)  # an ended session that never traced anything
    for session in range(ENDED_KEPT):
        bus.publish(session + 100, 0.0, STATE)
        bus.session_ended(session + 100)  # the first of these pushes session 500 out
    assert all(bus.events(session + 100) for session in range(ENDED_KEPT))  # exactly kept
    bus.session_ended(999)
    assert bus.events(100) == ()
    assert bus.info(100) is None
    bus.clear()
    assert bus.sessions() == ()


def test_restoring_a_full_tail_preserves_values_flushed_after_established() -> None:
    source = opened(TraceBus())
    source.publish(1, 1.0, StateChanged("initiator", "established"))
    value = ValueRevealed(Secret(bytes(32), "hs"))
    source.publish(1, 0.5, value)  # exposure gate publishes its earlier capture after admission
    source.handshake_done(1)
    for n in range(RING_SIZE):
        source.publish(1, 2.0 + n, frame_event(10))
    info = source.info(1)
    assert info is not None
    restored = TraceBus()
    restored.restore(info, source.events(1))
    assert restored.events(1) == source.events(1)
    assert restored.events(1)[1].event == value
