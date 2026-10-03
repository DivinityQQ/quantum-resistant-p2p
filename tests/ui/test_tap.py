"""The Inspector's services-thread tap against real nodes (UI_DESIGN §7.2, §11.3).

Snapshot and subscription hand over in one loop step (no gap, no duplicate); a paused tap queues
nothing; a resumed one reports what was evicted; a burst overflows into a catch-up, never into an
unbounded queue; glass-box values are unwrapped for glass-box sessions only.
"""

import asyncio
from collections.abc import AsyncIterator, Sequence
from pathlib import Path

import pytest

from qrp2p.core.trace import Direction, FrameTraced
from qrp2p.core.wire import Frame, FrameType
from qrp2p.services import trace_bus
from qrp2p.services.events import AdmissionPrompt, SessionOpened
from qrp2p.services.trace_bus import ENDED_KEPT, SessionInfo, TraceBus
from qrp2p.ui import tap as tap_module
from qrp2p.ui.inspect.model import RecordOpened, Revealed
from qrp2p.ui.tap import (
    InspectSnap,
    SessionDescribed,
    SessionRemoved,
    TraceAppended,
    TraceOverflow,
    TraceTap,
    profile_facts,
)
from tests.services.support import NodeHarness, befriend, until
from tests.ui.inspect_support import session_facts


@pytest.fixture
async def pair(tmp_path: Path) -> AsyncIterator[tuple[NodeHarness, NodeHarness]]:
    alice = await NodeHarness(tmp_path, "alice").start()
    bob = await NodeHarness(tmp_path, "bob").start()
    yield alice, bob
    await alice.node.close()
    await bob.node.close()


class Woken:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self) -> None:
        self.count += 1


async def connected(alice: NodeHarness, bob: NodeHarness) -> tuple[bytes, bytes, int]:
    bob_id, alice_id = await befriend(alice, bob)
    session = alice.node.session_info(bob_id)
    assert session is not None
    return bob_id, alice_id, session.id


def ordinals(updates: Sequence[object], session_id: int) -> list[int]:
    return [
        i.ordinal
        for u in updates
        if isinstance(u, TraceAppended) and u.session_id == session_id
        for i in u.items
    ]


async def test_the_snapshot_and_live_events_join_without_gap_or_duplicate(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = pair
    bob_id, _, session_id = await connected(alice, bob)
    woken = Woken()
    tap = TraceTap.of_node(alice.node, woken)
    chats = [asyncio.create_task(alice.node.send_chat(bob_id, f"m{n}")) for n in range(20)]
    await asyncio.sleep(0)  # some chats are under way while the snapshot is taken
    snap = tap.inspect(session_id)
    await asyncio.gather(*chats)
    await until(lambda: len(alice.node.trace.events(session_id)) >= len(snap.items) + 40)
    await asyncio.sleep(0.2)
    live = ordinals(tap.drain(), session_id)
    seen = [i.ordinal for i in snap.items] + live
    assert seen == list(range(len(seen)))  # every ordinal exactly once, in order
    assert seen[-1] == alice.node.trace.events(session_id)[-1].ordinal
    assert woken.count > 0
    assert not snap.missing
    assert snap.facts.peer_name == "Bob"
    assert snap.facts.established
    assert snap.facts.profile == profile_facts("HYBRID-1")


async def test_a_paused_tap_queues_nothing_and_resuming_reports_evictions(
    pair: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = pair
    monkeypatch.setattr(trace_bus, "RING_SIZE", 30)
    bob_id, _, session_id = await connected(alice, bob)
    tap = TraceTap.of_node(alice.node, Woken())
    last = tap.inspect(session_id).items[-1].ordinal
    tap.pause()
    for n in range(40):
        await alice.node.send_chat(bob_id, f"while paused {n}")
    await until(lambda: alice.node.trace.events(session_id)[-1].ordinal > last + 80)
    assert tap.drain() == []  # nothing waited for the paused display
    resumed = tap.inspect(session_id, after=last)
    assert resumed.missing
    assert resumed.items[0].ordinal > last + 1


async def test_a_burst_overflows_into_a_catch_up(
    pair: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = pair
    monkeypatch.setattr(tap_module, "BUFFER_LIMIT", 5)
    bob_id, _, session_id = await connected(alice, bob)
    tap = TraceTap.of_node(alice.node, Woken())
    tap.inspect(session_id)
    for n in range(5):
        await alice.node.send_chat(bob_id, f"burst {n}")
    await until(lambda: tap._overflowed)
    assert tap.drain() == [TraceOverflow(session_id)]
    assert tap.drain() == []


async def test_descriptors_are_forwarded_while_the_inspector_watches(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = pair
    tap = TraceTap.of_node(alice.node, Woken())
    assert tap.sessions() == ()
    bob_id, _, session_id = await connected(alice, bob)
    described = [u for u in tap.drain() if isinstance(u, SessionDescribed)]
    assert described
    assert described[-1].facts.session_id == session_id
    assert described[-1].facts.established
    assert [f.session_id for f in tap.sessions()] == [session_id]
    tap.close()
    await alice.node.disconnect(bob_id)
    await until(lambda: (info := alice.node.trace.info(session_id)) is not None and info.ended)
    assert tap.drain() == []


async def test_glass_box_values_are_unwrapped_and_normal_sessions_have_none(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = pair
    bob_id, _, session_id = await connected(alice, bob)
    tap = TraceTap.of_node(alice.node, Woken())
    normal = tap.inspect(session_id)
    assert not any(isinstance(i.event, Revealed | RecordOpened) for i in normal.items)
    assert not normal.facts.exposed
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id))
    connecting = asyncio.create_task(alice.node.connect_contact(bob_id, glass_box=True))
    prompt = await bob.next(AdmissionPrompt, lambda p: p.kind.value == "glass_box")
    await bob.node.answer_prompt(prompt.prompt_id, accept=True)
    await connecting
    await alice.next(SessionOpened, lambda e: e.glass_box)
    session = alice.node.session_info(bob_id)
    assert session is not None
    glass = tap.inspect(session.id)
    assert glass.facts.exposed
    assert glass.facts.glass_box
    revealed = {i.event.label: i.event.value for i in glass.items if isinstance(i.event, Revealed)}
    assert {"ss", "hs", "cs_0", "ap_I[0]"} <= set(revealed)
    assert all(isinstance(v, bytes) and v for v in revealed.values())
    opened = [i.event for i in glass.items if isinstance(i.event, RecordOpened)]
    assert {(o.key, o.seq) for o in opened} >= {("hs_R.key", 0), ("hs_I.key", 0), ("hs_R.key", 1)}
    assert isinstance(glass, InspectSnap)
    assert any(isinstance(i.event, FrameTraced) for i in glass.items)


async def test_a_session_no_longer_retained_is_refused(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, _ = pair
    tap = TraceTap.of_node(alice.node, Woken())
    with pytest.raises(Exception, match="no longer retained"):
        tap.inspect(12345)
    assert profile_facts("NOT-A-PROFILE") is None


def test_bursts_are_bounded_by_bytes_and_evicted_sessions_leave_the_picker() -> None:

    bus = TraceBus()
    tap = TraceTap(bus, lambda info: session_facts(session_id=info.session_id), lambda: None)
    bus.open_session(SessionInfo(1, True, "in memory", 0.0))
    tap.sessions()
    tap.inspect(1)
    frame = FrameTraced(Direction.OUT, Frame(FrameType.RECORD, bytes(16_000)), ())
    for n in range(1000):
        bus.publish(1, float(n), frame)
    assert tap.drain() == [TraceOverflow(1)]
    snap = tap.inspect(1)
    assert snap.items[0].ordinal == 0
    assert snap.items[-1].ordinal == 999
    for session_id in range(2, ENDED_KEPT + 4):
        bus.open_session(SessionInfo(session_id, True, "in memory", 0.0))
        bus.session_ended(session_id)
    updates = tap.drain()
    assert SessionRemoved(2) in updates
    assert all(u.facts.session_id != 2 for u in updates if isinstance(u, SessionDescribed))
    tap.detach()
