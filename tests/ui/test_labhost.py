"""The services-thread side of the solo lab: runs, snapshots, the lab tap and the end of a period."""

import asyncio

import msgspec
import pytest

from qrp2p.core.crypto.secret import Secret
from qrp2p.lab.recording import GlassBoxRecording
from qrp2p.lab.solo import LabError
from qrp2p.services.exposure import RecordRevealed, ValueRevealed
from qrp2p.services.recordings import session_recording
from qrp2p.services.trace_bus import SessionInfo, TraceBus
from qrp2p.ui.inspect.model import RecordOpened, Revealed
from qrp2p.ui.labhost import INACTIVE, PROFILES
from qrp2p.ui.tap import InspectSnap, SessionDescribed, TraceAppended
from tests.ui.inspect_support import scripted
from tests.ui.lab_support import Recordings, lab_host


def test_a_new_run_starts_ready_with_two_lab_views() -> None:
    host = lab_host()
    assert host.snapshot() == INACTIVE
    snap = host.new("HYBRID-1")
    assert snap.active
    assert snap.phase == "ready"
    assert snap.next_step == "Start the handshake"
    assert snap.alice_session != snap.bob_session
    views = {f.session_id: f for f in host.tap.sessions()}
    alice, bob = views[snap.alice_session], views[snap.bob_session]
    assert (alice.local_name, alice.peer_name, alice.initiator) == ("Alice", "Bob", True)
    assert (bob.local_name, bob.peer_name, bob.initiator) == ("Bob", "Alice", False)
    assert alice.lab
    assert alice.exposed
    assert alice.profile is not None
    assert alice.profile.name == "HYBRID-1"
    assert PROFILES[-1] == "LAB-CLASSICAL"


def test_steps_say_what_happens_and_the_handshake_completes() -> None:
    host = lab_host()
    host.new("LAB-CLASSICAL")
    host.step()
    snap = host.step()
    assert snap.in_flight == ("Reply · Bob → Alice",)
    assert snap.next_step == "Deliver Reply to Alice"
    host.step()
    snap = host.step()
    assert snap.deciding
    assert snap.next_step == "Bob admits Alice"
    snap = host.run()
    assert (snap.phase, snap.alice_open, snap.bob_open) == ("idle", True, True)
    assert [s.number for s in snap.steps] == [1, 2, 3, 4, 5, 6]
    assert snap.steps[0].text == "Alice starts the handshake: Hello is on its way to Bob."
    snap = host.take("chat", "bob", "hi")
    assert snap.in_flight == ("Record · chat · Bob → Alice",)
    snap = host.run()
    assert snap.alice_received == ("hi",)
    with pytest.raises(LabError, match="nothing is in flight"):
        host.step()


def test_a_fork_replaces_the_run_and_its_views() -> None:
    host = lab_host()
    first = host.new("HYBRID-1")
    host.run()
    forked = host.fork(3)
    assert len(forked.steps) == 3
    assert forked.phase == "running"
    assert {forked.alice_session, forked.bob_session}.isdisjoint(
        {first.alice_session, first.bob_session}
    )
    assert {f.session_id for f in host.tap.sessions()} == {
        forked.alice_session,
        forked.bob_session,
    }
    with pytest.raises(LabError, match="no such step"):
        host.fork(99)


def test_the_lab_tap_streams_the_inspected_view_under_its_own_source() -> None:
    host = lab_host()
    snap = host.new("HYBRID-1")
    host.tap.sessions()
    opened = host.tap.inspect(snap.alice_session)
    assert isinstance(opened, InspectSnap)
    assert opened.items == ()
    host.run()
    updates = host.tap.drain()
    appended = [u for u in updates if isinstance(u, TraceAppended)]
    assert appended
    assert all(u.source == "lab" for u in appended)
    assert all(u.source == "lab" for u in updates if isinstance(u, SessionDescribed))


def test_closing_drops_the_run_and_its_values() -> None:
    host = lab_host()
    snap = host.new("HYBRID-1")
    host.run()
    host.close()
    assert host.snapshot() == INACTIVE
    assert host.tap.sessions() == ()
    with pytest.raises(Exception, match="no longer retained"):
        host.tap.inspect(snap.alice_session)
    with pytest.raises(LabError, match="no run"):
        host.step()


def test_bad_requests_are_refused_with_a_reason() -> None:
    host = lab_host()
    with pytest.raises(LabError, match="no lab profile"):
        host.new("NOT-A-PROFILE")
    host.new("HYBRID-1")
    with pytest.raises(ValueError, match="not a valid"):
        host.take("explode", "alice")
    with pytest.raises(ValueError, match="not a valid"):
        host.take("chat", "mallory", "hi")
    with pytest.raises(LabError, match="no open session"):
        host.take("chat", "alice", "too early")


def glass_box_recording(title: str = "a glass-box chat") -> GlassBoxRecording:
    """A real exposed session's trace on a bus, saved as the node would save it."""
    bus = TraceBus()
    bus.open_session(
        SessionInfo(
            9,
            initiator=True,
            address="10.0.0.2:47470",
            started=0.0,
            profile="HYBRID-1",
            peer_short_id="BOBB-BOBB",
            glass_box=True,
            established=True,
        )
    )
    for item in scripted(exposed=True).i.items[5:]:  # the first five were evicted, say
        match item.event:
            case Revealed(label=label, value=value):
                event: object = ValueRevealed(Secret(value, label))
            case RecordOpened() as opened:
                event = RecordRevealed(
                    opened.key,
                    opened.seq,
                    Secret(opened.nonce, "n"),
                    Secret(opened.plaintext, "p"),
                    opened.opened,
                )
            case other:
                event = other
        bus.publish(9, item.time, event)
    recording = session_recording(bus, 9, title, 1_800_000_000.0)
    return replace_events(recording, offset=5)


def replace_events(recording: GlassBoxRecording, offset: int) -> GlassBoxRecording:
    events = [msgspec.structs.replace(e, ordinal=e.ordinal + offset) for e in recording.events]
    return msgspec.structs.replace(recording, events=events)


def test_a_saved_run_replays_when_opened() -> None:
    store = Recordings()
    host = lab_host(store)
    host.new("HYBRID-1")
    before = host.run()
    info = asyncio.run(host.save("handshake"))
    assert info.kind == "lab"
    host.new("PQ-CNSA-1")  # something else meanwhile
    opened = asyncio.run(host.open(info.file_id))
    assert [s.text for s in opened.steps] == [s.text for s in before.steps]
    assert opened.profile == "HYBRID-1"
    assert opened.phase == "idle"
    assert opened.recording == ""  # a run, live again: it can be continued and forked
    assert host.take("chat", "alice", "after the replay").in_flight


def test_a_glass_box_recording_is_shown_view_only_with_its_gaps() -> None:
    store = Recordings()
    host = lab_host(store)
    host.new("HYBRID-1")
    info = store.add(glass_box_recording())
    snap = asyncio.run(host.open(info.file_id))
    assert snap.recording == "a glass-box chat"
    assert snap.phase == "recording"
    assert snap.steps == ()
    (facts,) = host.tap.sessions()
    assert (facts.glass_box, facts.exposed, facts.lab) == (True, True, False)
    assert facts.peer_name == "BOBB-BOBB"
    opened = host.tap.inspect(snap.alice_session)
    assert isinstance(opened, InspectSnap)
    assert opened.items[0].ordinal == 5  # the recording's own ordinals: the gap stays visible
    assert opened.missing
    assert any(isinstance(i.event, Revealed) and i.event.label == "hs" for i in opened.items)
    with pytest.raises(LabError, match="saved already"):
        asyncio.run(host.save("again"))
    with pytest.raises(LabError, match="no run"):
        host.step()
    assert host.new("HYBRID-1").recording == ""  # a new run closes the recording
