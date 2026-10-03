"""Recording and replay at the provider boundary (DESIGN §11.6).

A recorded run replays to the same bytes; every recorded value is checked against what the run
asks for, and any difference is a named divergence; a fork replays its prefix, then continues
live and keeps recording.
"""

import pytest
from msgspec.structs import replace

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, REAL_PROFILES
from qrp2p.core.trace import FrameTraced
from qrp2p.lab.replay import Draw, Encapsulation, LabProvider, ReplayDivergence, Signature
from tests.core.harness import alice, handshake, initiator, responder, traces
from tests.support import DeterministicRandom


def recording(label: str) -> LabProvider:
    return LabProvider(REAL_PROFILES, random_source=DeterministicRandom(label))


def frames(events: list[object]) -> list[bytes]:
    return [t.frame.encode() for t in traces(events) if isinstance(t, FrameTraced)]


def run_with(i: LabProvider, r: LabProvider) -> list[object]:
    run = handshake(initiator(prov=i), responder(prov=r))
    return [
        *run.start,
        *run.on_hello,
        *run.on_reply,
        *run.on_confirm,
        *run.on_decision,
        *run.on_admit,
    ]


def test_a_handshake_records_every_randomised_output() -> None:
    i, r = recording("i"), recording("r")
    run_with(i, r)
    assert [type(e) for e in i.log] == [
        Draw,
        Draw,
        Signature,
    ]  # nonce, kem seed, Confirm's signature
    assert [type(e) for e in r.log] == [
        Encapsulation,
        Draw,
        Signature,
    ]  # ct, nonce, Reply's signature
    encapsulation = r.log[0]
    assert isinstance(encapsulation, Encapsulation)
    assert [name for name, _ in encapsulation.secrets] == ["ssM", "ssX", "ss"]
    signature = i.log[2]
    assert isinstance(signature, Signature)
    assert signature.role == Role.INITIATOR.value


def test_a_strict_replay_gives_the_same_bytes() -> None:
    i, r = recording("i"), recording("r")
    original = frames(run_with(i, r))
    again = frames(
        run_with(
            LabProvider(REAL_PROFILES, random_source=None, replay=i.log),
            LabProvider(REAL_PROFILES, random_source=None, replay=r.log),
        )
    )
    assert again == original  # pyca's ML-KEM and ML-DSA randomness came back from the logs


def test_a_strict_replay_cannot_run_past_its_recording() -> None:
    i = recording("i")
    i.random(32)
    strict = LabProvider(REAL_PROFILES, random_source=None, replay=i.log)
    strict.random(32)
    with pytest.raises(ReplayDivergence, match="after the recording ended"):
        strict.random(32)


def test_every_recorded_input_is_checked() -> None:
    i, r = recording("i"), recording("r")
    run_with(i, r)
    encapsulation, nonce, signature = r.log
    assert isinstance(encapsulation, Encapsulation)
    assert isinstance(signature, Signature)
    keys = alice()

    def replaying(*entries: object) -> LabProvider:
        return LabProvider(REAL_PROFILES, random_source=None, replay=entries)  # type: ignore[arg-type]

    with pytest.raises(ReplayDivergence, match="asked for 16 random bytes, the recording has 32"):
        replaying(nonce).random(16)
    with pytest.raises(ReplayDivergence, match="asked for a draw, the recording has a signature"):
        replaying(signature).random(32)
    with pytest.raises(ReplayDivergence, match="to a different ek"):
        replaying(encapsulation).kem_encapsulate(HYBRID_1, b"\0" * HYBRID_1.ek_len)
    with pytest.raises(ReplayDivergence, match="another profile or epoch"):
        replaying(encapsulation).kem_encapsulate(HYBRID_1, encapsulation.ek, epoch=1)
    with pytest.raises(ReplayDivergence, match="over a different hash"):
        replaying(signature).sign(HYBRID_1, keys, Role.RESPONDER, b"\1" * 32)
    forged = replace(signature, sig=bytes(len(signature.sig)))
    with pytest.raises(ReplayDivergence, match="does not verify"):
        replaying(forged).sign(HYBRID_1, keys, Role.RESPONDER, signature.th)
    with pytest.raises(ReplayDivergence) as raised:
        replaying(encapsulation).kem_encapsulate(PQ_CNSA_1, encapsulation.ek)
    assert raised.value.index == 0
    assert encapsulation.secrets[0][1].hex() not in str(raised.value)  # names, never values


def test_a_fork_replays_its_prefix_then_goes_live_and_keeps_recording() -> None:
    i = recording("i")
    first, second = i.random(32), i.random(32)
    fork = LabProvider(REAL_PROFILES, random_source=DeterministicRandom("live"), replay=i.log[:1])
    assert fork.replaying
    assert fork.random(32) == first
    assert not fork.replaying
    assert fork.random(32) != second  # live from here
    assert len(fork.log) == 2
    assert fork.log[0] == i.log[0]


def test_replayed_shared_secrets_keep_their_epoch_names() -> None:
    r = recording("r")
    i = recording("i")
    _, ek = i.kem_keygen(HYBRID_1, epoch=2)
    shared, ct = r.kem_encapsulate(HYBRID_1, ek, epoch=2)
    again, ct_again = LabProvider(REAL_PROFILES, random_source=None, replay=r.log).kem_encapsulate(
        HYBRID_1, ek, epoch=2
    )
    assert ct_again == ct
    assert again.ss.label == shared.ss.label == "ss[2]"
    assert [c.label for c in again.components] == ["ssM[2]", "ssX[2]"]
    assert again.ss.reveal() == shared.ss.reveal()
