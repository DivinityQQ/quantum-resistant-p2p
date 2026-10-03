"""The services-thread side of the solo lab: runs, snapshots, the lab tap and the end of a period."""

import pytest

from qrp2p.lab.solo import LabError
from qrp2p.ui.labhost import INACTIVE, PROFILES
from qrp2p.ui.tap import InspectSnap, SessionDescribed, TraceAppended
from tests.ui.lab_support import lab_host


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
