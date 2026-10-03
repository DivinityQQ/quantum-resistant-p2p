"""The solo lab (DESIGN §11, M4 decisions 9 to 12): Alice and Bob in memory, stepped, replayed, forked.

Every profile, ``LAB-CLASSICAL`` included, completes a handshake one transition per step; the
lab only offers legal steps and says why it refuses the others; every value is revealed into
the lab's own bus; a recorded run replays to the same bytes, and a fork replays its prefix
before continuing live.
"""

import pytest
from msgspec.structs import replace

from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1
from qrp2p.core.trace import FrameTraced, SecretDerived
from qrp2p.lab.classical import LAB_CLASSICAL
from qrp2p.lab.replay import Encapsulation
from qrp2p.lab.solo import (
    CHAT_LIMIT,
    STEP_SECONDS,
    Kind,
    LabError,
    LabRun,
    Phase,
    Side,
    SoloLab,
    Step,
)
from qrp2p.services.exposure import RecordRevealed, ValueRevealed
from qrp2p.services.trace_bus import TraceBus
from tests.support import DeterministicRandom

ALICE_ID, BOB_ID = 1, 2


def fresh(profile: object = HYBRID_1, label: str = "lab") -> tuple[SoloLab, TraceBus]:
    bus = TraceBus()
    lab = SoloLab.fresh(profile, bus, (ALICE_ID, BOB_ID), DeterministicRandom(label))  # type: ignore[arg-type]
    return lab, bus


def frames(bus: TraceBus, session_id: int) -> list[bytes]:
    return [
        r.event.frame.encode() for r in bus.events(session_id) if isinstance(r.event, FrameTraced)
    ]


def revealed(bus: TraceBus, session_id: int) -> dict[str, bytes]:
    return {
        r.event.secret.label: r.event.secret.reveal()
        for r in bus.events(session_id)
        if isinstance(r.event, ValueRevealed)
    }


def conversation(lab: SoloLab) -> None:
    """Handshake, a chat each way, a KeyUpdate, a PQ rekey, then Bob closes."""
    lab.run()
    lab.take(Step(Kind.CHAT, Side.ALICE, "hello Bob"))
    lab.take(Step(Kind.CHAT, Side.BOB, "hi Alice"))
    lab.take(Step(Kind.KEY_UPDATE, Side.BOB))
    lab.run()
    lab.take(Step(Kind.REKEY, Side.ALICE))
    lab.run()
    lab.take(Step(Kind.CLOSE, Side.BOB))
    lab.run()


@pytest.mark.parametrize("profile", [HYBRID_1, PQ_CNSA_1, LAB_CLASSICAL], ids=lambda p: p.name)
def test_every_profile_completes_a_handshake_one_transition_per_step(profile: object) -> None:
    lab, bus = fresh(profile)
    assert lab.phase is Phase.READY
    assert lab.next_step() == Step(Kind.START, Side.ALICE)
    expected = [
        Step(Kind.START, Side.ALICE),  # Hello in flight
        Step(Kind.DELIVER, Side.BOB),  # Reply in flight
        Step(Kind.DELIVER, Side.ALICE),  # Confirm in flight
        Step(Kind.DELIVER, Side.BOB),  # Bob must decide
        Step(Kind.ADMIT, Side.BOB),  # Admit in flight
        Step(Kind.DELIVER, Side.ALICE),
    ]
    for step in expected:
        assert lab.next_step() == step
        lab.take(step)
    assert lab.phase is Phase.IDLE
    assert lab.next_step() is None
    assert lab.is_open(Side.ALICE)
    assert lab.is_open(Side.BOB)
    alice, bob = bus.info(ALICE_ID), bus.info(BOB_ID)
    assert alice is not None
    assert bob is not None
    assert alice.established
    assert bob.established
    assert alice.profile == bob.profile == profile.name  # type: ignore[attr-defined]
    assert lab.now == pytest.approx(len(expected) * STEP_SECONDS)


def test_a_conversation_reveals_every_value_into_the_lab_bus() -> None:
    lab, bus = fresh()
    conversation(lab)
    assert lab.phase is Phase.ENDED
    assert lab.received(Side.BOB) == ("hello Bob",)
    assert lab.received(Side.ALICE) == ("hi Alice",)
    values = revealed(bus, ALICE_ID)
    assert {"dk", "ss", "hs", "cs_0", "ap_I[0]", "dk[1]", "ss[1]", "cs_1"} <= set(values)
    derived = {r.event.label for r in bus.events(ALICE_ID) if isinstance(r.event, SecretDerived)}
    assert derived <= set(values) | {"th_hello"}  # each derivation's value is there too
    plaintexts = [
        r.event.plaintext.reveal()
        for r in bus.events(BOB_ID)
        if isinstance(r.event, RecordRevealed) and r.event.opened
    ]
    assert any(b"hello Bob" in p for p in plaintexts)
    info = bus.info(BOB_ID)
    assert info is not None
    assert (info.ended, info.end_reason, info.by_peer) == (True, "normal", False)


def test_the_lab_refuses_steps_that_cannot_happen_and_says_why() -> None:
    lab, _ = fresh()
    with pytest.raises(LabError, match="no open session"):
        lab.take(Step(Kind.CHAT, Side.ALICE, "too early"))
    with pytest.raises(LabError, match="start the handshake first"):
        lab.take(Step(Kind.WAIT, Side.ALICE))
    lab.take(Step(Kind.START, Side.ALICE))
    with pytest.raises(LabError, match="already started"):
        lab.take(Step(Kind.START, Side.ALICE))
    with pytest.raises(LabError, match="nothing is in flight to Alice"):
        lab.take(Step(Kind.DELIVER, Side.ALICE))
    with pytest.raises(LabError, match="no admission decision"):
        lab.take(Step(Kind.ADMIT, Side.BOB))
    lab.run()
    with pytest.raises(LabError, match="only Alice starts a rekey"):
        lab.take(Step(Kind.REKEY, Side.BOB))
    with pytest.raises(LabError, match=f"1 to {CHAT_LIMIT}"):
        lab.take(Step(Kind.CHAT, Side.ALICE, ""))
    assert len(lab.steps) == 6  # refused steps change nothing


def test_frames_arrive_in_order_per_direction() -> None:
    lab, bus = fresh()
    lab.run()
    for n in range(3):
        lab.take(Step(Kind.CHAT, Side.ALICE, f"m{n}"))
    assert [f.label for f in lab.in_flight] == ["Record · chat"] * 3
    lab.run()
    assert lab.received(Side.BOB) == ("m0", "m1", "m2")
    assert len(frames(bus, BOB_ID)) == len(frames(bus, ALICE_ID))


def test_a_decline_closes_both_sides_with_its_reason() -> None:
    lab, bus = fresh()
    for _ in range(4):
        lab.take(lab.next_step())  # type: ignore[arg-type]
    lab.take(Step(Kind.DECLINE, Side.BOB))
    lab.run()
    assert lab.phase is Phase.ENDED
    alice = bus.info(ALICE_ID)
    assert alice is not None
    assert alice.admit_reason == "declined"
    assert not alice.established


def test_time_passing_without_delivery_ends_the_session() -> None:
    lab, bus = fresh()
    lab.run()
    for _ in range(3):  # pings are queued but never delivered: 90 s of silence
        lab.take(Step(Kind.WAIT, Side.ALICE))
    info = bus.info(ALICE_ID)
    assert info is not None
    assert info.end_reason == "timeout"


def test_a_second_rekey_within_a_minute_does_nothing_and_says_so() -> None:
    lab, _ = fresh()
    lab.run()
    lab.take(Step(Kind.REKEY, Side.ALICE))
    lab.run()
    lab.take(Step(Kind.REKEY, Side.ALICE))
    assert lab.note.startswith("No rekey started")
    assert lab.in_flight == ()


def test_a_recorded_run_replays_to_the_same_bytes_and_values() -> None:
    lab, bus = fresh()
    conversation(lab)
    run = lab.run_record()
    again_bus = TraceBus()
    again = SoloLab.replayed(run, again_bus, (ALICE_ID, BOB_ID), random_source=None)
    assert again.phase is Phase.ENDED
    assert again.divergence == ""
    for session in (ALICE_ID, BOB_ID):
        assert frames(again_bus, session) == frames(bus, session)
        assert revealed(again_bus, session) == revealed(bus, session)
    assert again.run_record() == run


def test_a_fork_replays_its_prefix_then_lives_its_own_life() -> None:
    lab, bus = fresh()
    conversation(lab)
    run = lab.run_record()
    handshake = 6
    fork_bus = TraceBus()
    fork = SoloLab.replayed(run, fork_bus, (3, 4), upto=handshake + 1)  # after "hello Bob"
    assert fork.steps == tuple(run.steps[: handshake + 1])
    assert [f.label for f in fork.in_flight] == ["Record · chat"]  # "hello Bob", as recorded
    fork.take(Step(Kind.CHAT, Side.BOB, "something else"))
    fork.run()
    assert fork.received(Side.BOB) == ("hello Bob",)
    assert fork.received(Side.ALICE) == ("something else",)
    # Alice's first five frames (the handshake's four and "hello Bob") are the recorded ones;
    # the sixth is what this fork's Bob sent instead.
    forked, recorded = frames(fork_bus, 3), frames(bus, ALICE_ID)
    assert forked[:5] == recorded[:5]
    assert forked[5] != recorded[5]
    replayed = SoloLab.replayed(fork.run_record(), TraceBus(), (5, 6), random_source=None)
    assert replayed.received(Side.ALICE) == ("something else",)  # a fork replays in turn


def test_a_tampered_recording_diverges_with_a_named_reason() -> None:
    lab, _ = fresh()
    lab.run()
    run = lab.run_record()
    log = list(run.bob_log)
    index = next(i for i, e in enumerate(log) if isinstance(e, Encapsulation))
    log[index] = replace(log[index], ek=bytes(len(log[index].ek)))  # type: ignore[type-var]
    tampered: LabRun = replace(run, bob_log=log)
    again = SoloLab.replayed(tampered, TraceBus(), (ALICE_ID, BOB_ID), random_source=None)
    assert again.phase is Phase.DIVERGED
    assert "different ek" in again.divergence
    with pytest.raises(LabError, match="diverged"):
        again.take(Step(Kind.WAIT, Side.ALICE))
    with pytest.raises(LabError, match="cannot be replayed"):
        SoloLab.replayed(replace(run, format=99), TraceBus(), (1, 2))
    with pytest.raises(LabError, match="cannot be replayed"):
        SoloLab.replayed(run, TraceBus(), (1, 2), upto=len(run.steps) + 1)


@pytest.mark.parametrize("damage", ["negative", "backwards", "outside", "trailing", "empty"])
def test_replay_refuses_unaccounted_or_invalid_log_marks(damage: str) -> None:
    lab, _ = fresh()
    lab.run()
    run = lab.run_record()
    marks = list(run.marks)
    if damage == "negative":
        marks[0] = (-1, 0)
    elif damage == "backwards":
        marks[1] = (0, 0)
    elif damage == "outside":
        marks[-1] = (len(run.alice_log) + 1, len(run.bob_log))
    elif damage == "trailing":
        run = replace(run, alice_log=[*run.alice_log, run.alice_log[0]])
    else:
        run = replace(run, steps=[], alice_log=run.alice_log, bob_log=run.bob_log)
        marks = []
    with pytest.raises(LabError, match=r"marks|unaccounted"):
        SoloLab.replayed(replace(run, marks=marks), TraceBus(), (3, 4))


def test_a_fork_checks_each_step_before_enabling_fresh_randomness() -> None:
    lab, _ = fresh()
    lab.run()
    run = lab.run_record()
    marks = list(run.marks)
    marks[0] = (0, 0)  # monotonic and in range, but fails to account for Start's draws
    calls: list[int] = []

    def fresh_random(n: int) -> bytes:
        calls.append(n)
        return bytes(n)

    rebuilt = SoloLab.replayed(
        replace(run, marks=marks), TraceBus(), (3, 4), random_source=fresh_random
    )
    assert rebuilt.phase is Phase.DIVERGED
    assert "step 0" in rebuilt.divergence
    assert not calls
    assert len(rebuilt.steps) == 1


def test_only_the_lab_reveals_both_throwaway_identity_seed_sets() -> None:
    lab, bus = fresh()
    lab.run()
    run = lab.run_record()
    labels = ("identity.ed25519", "identity.mldsa65", "identity.mldsa87")
    for session_id, seeds in ((ALICE_ID, run.alice), (BOB_ID, run.bob)):
        values = revealed(bus, session_id)
        assert tuple(values[n] for n in labels) == seeds
    rebuilt_bus = TraceBus()
    SoloLab.replayed(run, rebuilt_bus, (3, 4), random_source=None)
    assert tuple(revealed(rebuilt_bus, 3)[n] for n in labels) == run.alice
