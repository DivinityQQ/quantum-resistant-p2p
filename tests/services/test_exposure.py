"""Glass-box containment in the services (DESIGN §11.3): the exposure gate and its use.

Values reach the trace bus only for a session admitted as glass-box. Everything else either has
a plain provider (an initiator that did not ask) or a gate that closes for good.
"""

from collections.abc import AsyncIterator

import pytest

from qrp2p.core.crypto.provider import AeadRevealed
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import AdmitReason, CloseReason, ProtocolError
from qrp2p.core.events import Priority
from qrp2p.core.wire import Chat
from qrp2p.services.exposure import (
    PENDING_LIMIT,
    Exposure,
    ExposureGate,
    GateState,
    RecordRevealed,
    ValueRevealed,
)
from qrp2p.services.session import Session
from qrp2p.services.trace_bus import SessionInfo, TraceBus
from tests.services.support import LOOPBACK, Peer, until


def secret(label: str) -> Secret:
    return Secret(label.encode().ljust(32, b"."), label)


class Times:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


# --- the gate on its own ---------------------------------------------------------------------------


def test_a_gate_holds_values_until_it_opens_then_passes_everything() -> None:
    gate = ExposureGate(Times())
    published: list[tuple[float, Exposure]] = []
    gate(secret("hs"))
    nonce, plaintext = secret("n"), secret("p")
    gate(AeadRevealed("hs_R.key", 0, nonce, plaintext, opened=False))
    assert gate.state is GateState.PENDING
    assert published == []
    gate.open(lambda time, exposure: published.append((time, exposure)))
    gate(secret("cs_0"))
    assert [time for time, _ in published] == [1.0, 2.0, 3.0]  # revealed at, not published at
    assert [e for _, e in published] == [
        ValueRevealed(published[0][1].secret),  # type: ignore[union-attr]
        RecordRevealed("hs_R.key", 0, nonce, plaintext, opened=False),
        ValueRevealed(published[2][1].secret),  # type: ignore[union-attr]
    ]
    assert [e.secret.label for _, e in published if isinstance(e, ValueRevealed)] == ["hs", "cs_0"]


def test_a_closed_gate_drops_its_buffer_and_never_opens() -> None:
    gate = ExposureGate(Times())
    gate(secret("hs"))
    gate.close()
    gate(secret("cs_0"))  # ignored
    assert gate.state is GateState.CLOSED
    with pytest.raises(RuntimeError):
        gate.open(lambda _t, _e: None)
    assert gate._buffer == []
    assert gate._publish is None


def test_too_many_values_before_admission_fail_closed() -> None:
    gate = ExposureGate(Times())
    for n in range(PENDING_LIMIT):
        gate(secret(f"s{n}"))
    with pytest.raises(ProtocolError) as info:
        gate(secret("one too many"))
    assert info.value.reason is CloseReason.INTERNAL
    assert gate.state is GateState.CLOSED
    assert gate._buffer == []


# --- sessions between session managers -------------------------------------------------------------


@pytest.fixture
async def pair() -> AsyncIterator[tuple[Peer, Peer]]:
    alice = await Peer("alice").start()
    bob = await Peer("bob").start()
    yield alice, bob
    await alice.stop()
    await bob.stop()


def exposures(bus: TraceBus, session: Session) -> list[Exposure]:
    return [
        r.event
        for r in bus.events(session.id)
        if isinstance(r.event, ValueRevealed | RecordRevealed)
    ]


async def open_pair(alice: Peer, bob: Peer, *, ask: bool, grant: bool) -> tuple[Session, Session]:
    bob.hooks.glass_box = grant
    session = await alice.connect(bob, glass_box=ask)
    await until(lambda: session.is_open and bool(bob.record.established))
    return session, bob.record.established[-1][0]


async def chat_both_ways(a: Session, b: Session, alice: Peer, bob: Peer) -> None:
    a.send(Chat(id=bytes(16), text="to bob"), Priority.CHAT)
    b.send(Chat(id=bytes(15) + b"\x01", text="to alice"), Priority.CHAT)
    await until(lambda: bool(alice.record.messages) and bool(bob.record.messages))


async def test_a_glass_box_session_reveals_into_its_ring(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await open_pair(alice, bob, ask=True, grant=True)
    assert a.glass_box
    assert b.glass_box
    await chat_both_ways(a, b, alice, bob)
    for peer, session in ((alice, a), (bob, b)):
        revealed = exposures(peer.trace, session)
        labels = {e.secret.label for e in revealed if isinstance(e, ValueRevealed)}
        assert {"ss", "ssM", "ssX", "hs", "hs_R", "fk_I", "cs_0", "ap_I[0]", "exporter_0"} <= labels
        assert ("dk" in labels) is (session is a)  # only the initiator generates one
        records = [(e.key, e.seq, e.opened) for e in revealed if isinstance(e, RecordRevealed)]
        assert ("hs_R.key", 0, session is a) in records  # Reply: sealed by Bob, opened by Alice
        assert ("hs_R.key", 1, session is a) in records  # Admit
        assert ("hs_I.key", 0, session is b) in records  # Confirm
        chats = [
            e.plaintext.reveal()
            for e in revealed
            if isinstance(e, RecordRevealed) and e.key.startswith("ap_")
        ]
        assert any(b"to bob" in p for p in chats)
        assert any(b"to alice" in p for p in chats)


async def test_no_value_reaches_the_bus_without_glass_box_admission(
    pair: tuple[Peer, Peer],
) -> None:
    alice, bob = pair
    for ask, grant in ((False, False), (True, False)):
        a, b = await open_pair(alice, bob, ask=ask, grant=grant)
        assert not a.glass_box
        await chat_both_ways(a, b, alice, bob)
        assert exposures(alice.trace, a) == []
        assert exposures(bob.trace, b) == []
        alice.record.messages.clear()
        bob.record.messages.clear()


async def test_an_initiator_that_does_not_ask_has_no_revealing_provider(
    pair: tuple[Peer, Peer],
) -> None:
    alice, bob = pair
    a, b = await open_pair(alice, bob, ask=False, grant=True)
    assert a.id not in alice.manager._gates
    assert b.id not in bob.manager._gates  # closed at admission: the Hello did not ask


async def test_a_refused_glass_box_session_closes_the_gate(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    bob.hooks.decide = lambda _s, _r: AdmitReason.DECLINED
    session = await alice.connect(bob, glass_box=True)
    await until(lambda: alice.record.ended_for(session) is not None)
    await until(lambda: not bob.manager._gates and not alice.manager._gates)
    assert exposures(alice.trace, session) == []


async def test_descriptors_follow_the_session(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    a, b = await open_pair(alice, bob, ask=True, grant=True)
    mine = alice.trace.info(a.id)
    theirs = bob.trace.info(b.id)
    assert mine == SessionInfo(
        a.id,
        initiator=True,
        address=f"{LOOPBACK}:{bob.port}",
        started=mine.started if mine else 0.0,
        profile="HYBRID-1",
        pinned=True,
        peer_id=bob.identity.bundle.peer_id,
        peer_short_id=bob.identity.bundle.short_id,
        glass_box_requested=True,
        glass_box=True,
        established=True,
    )
    assert theirs is not None
    assert (theirs.initiator, theirs.address, theirs.peer_id) == (
        False,
        LOOPBACK,
        alice.identity.bundle.peer_id,
    )
    assert (theirs.glass_box_requested, theirs.glass_box, theirs.established) == (True, True, True)
    a.close(CloseReason.NORMAL)
    await until(lambda: (info := bob.trace.info(b.id)) is not None and info.ended)
    ended = bob.trace.info(b.id)
    assert ended is not None
    assert (ended.end_reason, ended.by_peer) == ("normal", True)


async def test_a_refusal_is_described_with_its_reason(pair: tuple[Peer, Peer]) -> None:
    alice, bob = pair
    bob.hooks.decide = lambda _s, _r: AdmitReason.BUSY
    session = await alice.connect(bob)
    await until(lambda: (info := alice.trace.info(session.id)) is not None and info.ended)
    info = alice.trace.info(session.id)
    assert info is not None
    assert (info.end_reason, info.admit_reason, info.established) == ("policy", "busy", False)
    assert info.peer_id == bob.identity.bundle.peer_id  # Reply authenticated it before Admit
