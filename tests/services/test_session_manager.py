"""Sessions between real session managers over loopback TCP."""

import asyncio
import contextlib
from collections.abc import AsyncIterator
from typing import cast

import pytest

from qrp2p.core.crypto.profiles import FRAME_HEADER_LEN, HYBRID_1, MAX_FRAME_BODY, PQ_CNSA_1
from qrp2p.core.crypto.provider import PlainProvider
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.events import Priority
from qrp2p.core.handshake import Initiator
from qrp2p.core.record import IDLE_TIMEOUT
from qrp2p.core.wire import Chat, FrameType, Receipt
from qrp2p.services import session as session_module
from qrp2p.services import session_manager
from qrp2p.services import transport as transport_module
from qrp2p.services.limits import MAX_HALF_OPEN_PER_SOURCE, TokenBucket
from qrp2p.services.session import Phase, Session, SessionNotOpenError, SessionRole
from qrp2p.services.transport import PORT_ATTEMPTS, ConnectionLost, FrameStream, Listener
from tests.services.support import LOOPBACK, Clock, Peer, until
from tests.support import DeterministicRandom


@pytest.fixture
async def pair() -> AsyncIterator[tuple[Peer, Peer]]:
    alice = await Peer("alice").start()
    bob = await Peer("bob").start()
    yield alice, bob
    await alice.stop()
    await bob.stop()


async def dropped(reader: asyncio.StreamReader) -> bool:
    """Whether the peer closed the connection without sending anything.

    An abort arrives as a reset on Windows and macOS, as end-of-file on Linux.
    """
    try:
        return await asyncio.wait_for(reader.read(100), 5) == b""
    except ConnectionResetError:
        return True


def chat(n: int, text: str = "hi") -> Chat:
    return Chat(id=n.to_bytes(16, "big"), text=text)


async def established(alice: Peer, bob: Peer, **kwargs: object) -> tuple[Session, Session]:
    session = await alice.connect(bob, **kwargs)  # type: ignore[arg-type]
    await until(lambda: session.is_open and bool(bob.record.established))
    return session, bob.record.established[-1][0]


async def test_chat_both_ways(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob)
    assert a.peer == bob.identity.bundle
    assert b.peer == alice.identity.bundle
    a.send(chat(1, "hello bob"), Priority.CHAT)
    b.send(chat(2, "hello alice"), Priority.CHAT)
    await until(lambda: bool(alice.record.messages) and bool(bob.record.messages))
    assert bob.record.messages[0][1] == chat(1, "hello bob")
    assert alice.record.messages[0][1] == chat(2, "hello alice")
    assert any(m == chat(1, "hello bob") for _, m in alice.record.sent)


async def test_profile_is_negotiated_per_session(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob, profile=PQ_CNSA_1)
    assert a.profile is PQ_CNSA_1
    assert b.profile is PQ_CNSA_1


async def test_many_messages_keep_their_order(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, _ = await established(alice, bob)
    for n in range(300):
        a.send(Receipt(id=n.to_bytes(16, "big")) if n % 3 else chat(n), Priority.CHAT)
    await until(lambda: len(bob.record.messages) == 300)
    ids = [int.from_bytes(m.id, "big") for _, m in bob.record.messages]  # type: ignore[union-attr]
    assert ids == list(range(300))


async def test_close_normal_reaches_the_peer(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob)
    a.close()
    await until(lambda: bob.record.ended_for(b) is not None)
    end = bob.record.ended_for(b)
    assert end is not None
    assert end.reason is CloseReason.NORMAL
    assert end.by_peer


async def test_new_session_replaces_old(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    first, bob_first = await established(alice, bob)
    second = await alice.connect(bob)
    await until(lambda: second.is_open and len(bob.record.established) == 2)
    await until(lambda: alice.record.ended_for(first) is not None)
    await until(lambda: bob.record.ended_for(bob_first) is not None)
    alice_end = alice.record.ended_for(first)
    bob_end = bob.record.ended_for(bob_first)
    assert alice_end is not None
    assert bob_end is not None
    # Each side replaces the old session itself; whichever close arrives first names the reason.
    assert CloseReason.REPLACED in {alice_end.reason, bob_end.reason}
    assert alice.manager.live(bob.identity.bundle.peer_id) is second
    assert bob.record.established[-1][1] is bob_first


async def test_simultaneous_open_busy() -> None:
    """Both peers connect at once: the session initiated by the lower peer_id survives."""
    alice = await Peer("alice").start()
    bob = await Peer("bob").start()
    try:
        from_alice, from_bob = await asyncio.gather(alice.connect(bob), bob.connect(alice))
        low, high = sorted(
            [(alice, from_alice), (bob, from_bob)], key=lambda p: p[0].identity.bundle.peer_id
        )
        winner, loser = low[1], high[1]
        await until(lambda: winner.is_open and high[0].record.ended_for(loser) is not None)
        end = high[0].record.ended_for(loser)
        assert end is not None
        assert end.admit_reason is AdmitReason.BUSY
        assert any(s is loser and superseded for s, _, superseded in high[0].record.ended)
        await asyncio.sleep(0.1)
        # Both ends keep the same connection: the lower peer as its initiator, the other as its
        # responder, and nothing else is live.
        low_live = low[0].manager.live(high[0].identity.bundle.peer_id)
        high_live = high[0].manager.live(low[0].identity.bundle.peer_id)
        assert low_live is winner
        assert high_live is not None
        assert high_live.role is SessionRole.RESPONDER
        assert high_live.is_open
        assert [s for s in high[0].manager.sessions() if s.phase is not Phase.ENDED] == [high_live]
    finally:
        await alice.stop()
        await bob.stop()


async def test_admission_reject_reaches_initiator(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    bob.hooks.decide = lambda _s, _r: AdmitReason.DECLINED
    session = await alice.connect(bob)
    await until(lambda: alice.record.ended_for(session) is not None)
    end = alice.record.ended_for(session)
    assert end is not None
    assert end.reason is CloseReason.POLICY
    assert end.admit_reason is AdmitReason.DECLINED


async def test_deferred_admission_accepts_later(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    bob.hooks.defer = True
    session = await alice.connect(bob, glass_box=True)
    await until(lambda: bool(bob.record.admissions))
    request = bob.record.admissions[0]
    assert request.gb_request
    assert request.peer == alice.identity.bundle
    pending = next(s for s in bob.manager.sessions() if s.awaiting_admission)
    pending.accept(glass_box=True)
    await until(lambda: session.is_open)
    assert session.glass_box
    assert pending.glass_box


async def test_prompt_deadline(pair: tuple[Peer, Peer]) -> None:
    """An unanswered admission prompt expires as reject ``timeout`` (DESIGN §7.6)."""
    alice, bob = pair
    bob.hooks.defer = True
    session = await alice.connect(bob)
    await until(lambda: bool(bob.record.admissions))
    bob.clock.advance(61.0)
    bob.manager.tick()
    await until(lambda: alice.record.ended_for(session) is not None)
    end = alice.record.ended_for(session)
    assert end is not None
    assert end.admit_reason is AdmitReason.TIMEOUT


async def test_pin_mismatch_closes_before_confirm(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    carol = await Peer("carol").start()
    try:
        session = await alice.manager.connect(
            LOOPBACK, bob.port, profile=PQ_CNSA_1, pinned=carol.identity.bundle, glass_box=False
        )
        await until(lambda: alice.record.ended_for(session) is not None)
        assert alice.record.mismatches[0].actual == bob.identity.bundle
        end = alice.record.ended_for(session)
        assert end is not None
        assert end.reason is CloseReason.PIN_MISMATCH
        assert not bob.record.admissions  # alice never revealed herself
    finally:
        await carol.stop()


async def test_connecting_to_ourselves_is_reflection() -> None:
    alice = await Peer("alice").start()
    try:
        session = await alice.connect(alice, pin=False)
        await until(lambda: alice.record.ended_for(session) is not None)
        ends = {end.reason for _, end, _ in alice.record.ended}
        assert CloseReason.REFLECTION in ends
    finally:
        await alice.stop()


async def test_hello_rate_limit(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    bob.manager._hellos = TokenBucket(rate=0.0, burst=1)
    await established(alice, bob)
    second = await alice.connect(bob)
    await until(lambda: alice.record.ended_for(second) is not None)
    end = alice.record.ended_for(second)
    assert end is not None
    assert end.lost  # silently dropped before authentication
    assert any(end.reason is CloseReason.RATE_LIMITED for _, end, _ in bob.record.ended)


async def test_half_open_slots_per_source(pair: tuple[Peer, Peer]) -> None:
    _, bob = pair
    idle = [await asyncio.open_connection(LOOPBACK, bob.port) for _ in range(4)]
    await until(lambda: bob.manager.half_open == MAX_HALF_OPEN_PER_SOURCE)
    reader, writer = await asyncio.open_connection(LOOPBACK, bob.port)
    assert await dropped(reader)  # refused at once
    writer.close()
    for _, w in idle:
        w.close()
    await until(lambda: bob.manager.half_open == 0)


async def test_silent_connection_times_out(pair: tuple[Peer, Peer]) -> None:
    _, bob = pair
    reader, writer = await asyncio.open_connection(LOOPBACK, bob.port)
    await until(lambda: bob.manager.half_open == 1)
    bob.clock.advance(11.0)
    bob.manager.tick()
    assert await dropped(reader)
    writer.close()
    assert any(end.reason is CloseReason.TIMEOUT for _, end, _ in bob.record.ended)


async def test_oversize_frame_before_authentication_closes_silently(
    pair: tuple[Peer, Peer],
) -> None:
    _, bob = pair
    reader, writer = await asyncio.open_connection(LOOPBACK, bob.port)
    writer.write((MAX_FRAME_BODY + 1).to_bytes(4, "big") + bytes([FrameType.HELLO]))
    assert await dropped(reader)
    writer.close()
    await until(lambda: bool(bob.record.ended))
    assert bob.record.ended[0][1].reason is CloseReason.OVERSIZE


async def test_oversize_frame_after_authentication_sends_close(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob)
    a._stream._writer.write(  # a misbehaving peer, bypassing the writer
        (MAX_FRAME_BODY + 1).to_bytes(4, "big") + bytes([FrameType.RECORD])
    )
    await until(lambda: alice.record.ended_for(a) is not None)
    end = alice.record.ended_for(a)
    assert end is not None
    assert end.reason is CloseReason.OVERSIZE
    assert end.by_peer
    b_end = bob.record.ended_for(b)
    assert b_end is not None
    assert b_end.reason is CloseReason.OVERSIZE
    assert not b_end.by_peer
    assert FRAME_HEADER_LEN == 5


async def test_idle_timeout_closes_the_session(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, _ = await established(alice, bob)
    alice.clock.advance(IDLE_TIMEOUT + 1)
    alice.manager.tick()
    await until(lambda: alice.record.ended_for(a) is not None)
    end = alice.record.ended_for(a)
    assert end is not None
    assert end.reason is CloseReason.TIMEOUT


async def test_peer_vanishing_is_connection_lost(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob)
    a._stream.abort()
    await until(lambda: bob.record.ended_for(b) is not None)
    end = bob.record.ended_for(b)
    assert end is not None
    assert end.lost


async def test_stop_closes_sessions_with_the_reason(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    _, b = await established(alice, bob)
    await alice.manager.stop(CloseReason.LOCKED)
    await until(lambda: bob.record.ended_for(b) is not None)
    end = bob.record.ended_for(b)
    assert end is not None
    assert end.reason is CloseReason.LOCKED
    assert end.by_peer


async def test_live_session_limit_rejects_busy(
    pair: tuple[Peer, Peer], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = pair
    monkeypatch.setattr(session_manager, "MAX_LIVE_SESSIONS", 1)
    await established(alice, bob)
    carol = await Peer("carol").start()
    try:
        session = await carol.connect(bob)
        await until(lambda: carol.record.ended_for(session) is not None)
        end = carol.record.ended_for(session)
        assert end is not None
        assert end.admit_reason is AdmitReason.BUSY
    finally:
        await carol.stop()


async def test_rekey_over_tcp(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob)
    alice.clock.advance(61.0)
    bob.clock.advance(61.0)
    a.start_rekey()
    await until(lambda: a.channel is not None and a.channel.epoch == 1)
    await until(lambda: b.channel is not None and b.channel.epoch == 1)
    a.send(chat(7), Priority.CHAT)
    await until(lambda: bool(bob.record.messages))


async def test_deferred_admissions_recheck_live_capacity(
    pair: tuple[Peer, Peer], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = pair
    monkeypatch.setattr(session_manager, "MAX_LIVE_SESSIONS", 1)
    bob.hooks.defer = True
    carol = await Peer("carol").start()
    try:
        first = await alice.connect(bob)
        second = await carol.connect(bob)
        await until(lambda: len(bob.record.admissions) == 2)
        for session in [s for s in bob.manager.sessions() if s.awaiting_admission]:
            session.accept(glass_box=False)
        await until(lambda: first.is_open and carol.record.ended_for(second) is not None)
        end = carol.record.ended_for(second)
        assert end is not None
        assert end.admit_reason is AdmitReason.BUSY
        assert len(bob.manager._live) == 1
        assert len(bob.record.established) == 1
        # Replacing the same peer is permitted even at capacity.
        replacement = await alice.connect(bob)
        await until(lambda: len(bob.record.admissions) == 3)
        next(s for s in bob.manager.sessions() if s.awaiting_admission).accept(glass_box=False)
        await until(lambda: replacement.is_open and not first.is_open)
        assert len(bob.manager._live) == 1
    finally:
        await carol.stop()


async def test_outgoing_handshakes_cannot_exceed_live_capacity(
    pair: tuple[Peer, Peer], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = pair
    monkeypatch.setattr(session_manager, "MAX_LIVE_SESSIONS", 1)
    bob.hooks.defer = True
    carol = await Peer("carol").start()
    carol.hooks.defer = True
    try:
        first = await alice.connect(bob)
        second = await alice.connect(carol)
        await until(lambda: bool(bob.record.admissions) and bool(carol.record.admissions))
        next(s for s in bob.manager.sessions() if s.awaiting_admission).accept(glass_box=False)
        await until(lambda: first.is_open)
        next(s for s in carol.manager.sessions() if s.awaiting_admission).accept(glass_box=False)
        await until(lambda: alice.record.ended_for(second) is not None)
        end = alice.record.ended_for(second)
        assert end is not None
        assert end.reason is CloseReason.RATE_LIMITED
        assert len(alice.manager._live) == 1
        assert len(alice.record.established) == 1
    finally:
        await carol.stop()


def test_clock_is_monotonic_plus_offset() -> None:
    clock = Clock()
    before = clock()
    clock.advance(10)
    assert clock() >= before + 10


async def test_peer_that_never_reads_is_closed_rate_limited(
    pair: tuple[Peer, Peer], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The writer backlog is bounded (P6): answering faster than the peer reads closes."""
    alice, bob = pair
    a, _ = await established(alice, bob)
    monkeypatch.setattr(session_module, "MAX_WRITE_BACKLOG", 5)
    for n in range(10):  # queued synchronously, before the writer gets a turn
        with contextlib.suppress(SessionNotOpenError):
            a.send(chat(n), Priority.CHAT)
    await until(lambda: alice.record.ended_for(a) is not None)
    end = alice.record.ended_for(a)
    assert end is not None
    assert end.reason is CloseReason.RATE_LIMITED


class StalledStream:
    """A connection whose peer never reads: writes are accepted, drain never completes."""

    source = "192.0.2.1"

    def __init__(self) -> None:
        self.aborted = asyncio.Event()

    async def read_frame(self) -> None:
        await self.aborted.wait()
        raise ConnectionLost

    def write(self, frame: object) -> None:
        pass

    async def drain(self) -> None:
        await self.aborted.wait()
        raise ConnectionLost

    def abort(self) -> None:
        self.aborted.set()

    async def close(self) -> None:
        self.aborted.set()


async def test_write_timeout_gives_up_on_a_stalled_peer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_module, "WRITE_TIMEOUT", 0.05)
    peer = Peer("alice")
    initiator = Initiator(
        provider=PlainProvider(DeterministicRandom("stall")),
        profile=HYBRID_1,
        identity=peer.identity,
        pinned=None,
        glass_box_request=False,
        now=0.0,
    )
    session = Session(
        machine=initiator,
        stream=cast("FrameStream", StalledStream()),
        hooks=peer.manager,
        clock=peer.clock,
    )
    session.start()
    end = await asyncio.wait_for(session.run(), 5)
    assert end.reason is CloseReason.TIMEOUT


async def test_simultaneous_open_without_pins_keeps_one_session() -> None:
    """Initiators without a pin: admission sees the overlap only after Reply; establishment
    catches the rest."""
    alice = await Peer("alice").start()
    bob = await Peer("bob").start()
    try:
        from_alice, from_bob = await asyncio.gather(
            alice.connect(bob, pin=False), bob.connect(alice, pin=False)
        )
        a_id, b_id = alice.identity.bundle.peer_id, bob.identity.bundle.peer_id
        # Settled: each side lost one session and has one open (the winner's Admit may still be
        # in flight when the loser's end is recorded).
        await until(
            lambda: (
                len(alice.record.ended) == 1
                and len(bob.record.ended) == 1
                and alice.manager.live(b_id) is not None
                and bob.manager.live(a_id) is not None
            )
        )
        await asyncio.sleep(0.1)  # and it stays that way
        a = alice.manager.live(b_id)
        b = bob.manager.live(a_id)
        assert a is not None
        assert b is not None
        assert a.channel is not None
        assert b.channel is not None
        # The two ends of one connection share the exporter secret.
        assert a.channel._epoch.exporter == b.channel._epoch.exporter
        lower = min(alice, bob, key=lambda p: p.identity.bundle.peer_id)
        survivor = from_alice if lower is alice else from_bob
        assert (
            lower.manager.live((bob if lower is alice else alice).identity.bundle.peer_id)
            is survivor
        )
        for peer in (alice, bob):
            ((_, end, superseded),) = peer.record.ended
            # Rejected at admission once Reply revealed the peer, or replaced at establishment.
            assert end.reason is CloseReason.REPLACED or end.admit_reason is AdmitReason.BUSY
            assert superseded
    finally:
        await alice.stop()
        await bob.stop()


async def test_closing_drops_what_was_queued_behind_the_close(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await established(alice, bob)
    for n in range(20):
        a.send(chat(n), Priority.CHAT)
    a.close()  # before the writer ran: close goes first, the chats never
    await until(lambda: bob.record.ended_for(b) is not None)
    end = bob.record.ended_for(b)
    assert end is not None
    assert end.reason is CloseReason.NORMAL
    await asyncio.sleep(0.05)
    assert bob.record.messages == []
    assert not any(isinstance(m, Chat) for _, m in alice.record.sent)


class StalledUntilAborted(StalledStream):
    """Like a stalled peer, and closing gracefully never completes either."""

    async def close(self) -> None:
        await self.aborted.wait()


async def test_final_frames_get_a_bounded_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    """A close that cannot flush aborts the connection after FLUSH_TIMEOUT."""
    monkeypatch.setattr(session_module, "FLUSH_TIMEOUT", 0.05)
    peer = Peer("alice")
    stream = StalledUntilAborted()
    session = Session(
        machine=Initiator(
            provider=PlainProvider(DeterministicRandom("flush")),
            profile=HYBRID_1,
            identity=peer.identity,
            pinned=None,
            glass_box_request=False,
            now=0.0,
        ),
        stream=cast("FrameStream", stream),
        hooks=peer.manager,
        clock=peer.clock,
    )
    session.start()
    running = asyncio.create_task(session.run())
    await asyncio.sleep(0.02)  # the writer is now stuck draining the Hello
    session.close(CloseReason.NORMAL)
    end = await asyncio.wait_for(running, 2)
    assert end.reason is CloseReason.NORMAL
    assert stream.aborted.is_set()


async def test_busy_port_moves_to_the_next(pair: tuple[Peer, Peer]) -> None:
    _, bob = pair
    taken = bob.port  # Bob listens here; a second listener must pick another port
    listener = Listener(Peer("carol").manager.handle_incoming)
    try:
        port = await listener.start(LOOPBACK, taken)
        assert taken < port < taken + PORT_ATTEMPTS
    finally:
        await listener.close()


async def test_no_free_port_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "PORT_ATTEMPTS", 1)
    holder = Listener(Peer("dave").manager.handle_incoming)
    port = await holder.start(LOOPBACK, 0)
    try:
        with pytest.raises(OSError):  # noqa: PT011  # the OS's "address in use"
            await Listener(Peer("erin").manager.handle_incoming).start(LOOPBACK, port)
    finally:
        await holder.close()
