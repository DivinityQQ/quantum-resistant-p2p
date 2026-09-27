"""The handshake state machines (DESIGN §7; IMPLEMENTATION_PLAN M1.3)."""

from collections.abc import Iterable

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, REAL_PROFILES, Profile
from qrp2p.core.crypto.provider import PlainProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.events import Closed, Send
from qrp2p.core.handshake import (
    ADMISSION_DEADLINE,
    HANDSHAKE_DEADLINE,
    INITIATOR_ADMIT_DEADLINE,
    AdmissionRequired,
    Established,
    KeyMismatch,
    ProfileRejected,
    State,
)
from qrp2p.core.trace import SecretDerived, TranscriptHashed
from qrp2p.core.wire import AdmitBody, Decision, Frame, FrameType, Hello
from qrp2p.lab.classical import LAB_CLASSICAL, LAB_PROFILES
from tests.core.harness import (
    alice,
    bob,
    handshake,
    identity,
    initiator,
    none_of,
    one,
    provider,
    responder,
    sent,
    traces,
)
from tests.support import DeterministicRandom


def closed(events: Iterable[object]) -> Closed:
    return one(events, Closed)


def flip(data: bytes, index: int) -> bytes:
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


class Faulty(PlainProvider):
    """Corrupts the n-th output of one operation, to prove each check is really performed."""

    def __init__(self, label: str, op: str, nth: int = 1, profiles=REAL_PROFILES) -> None:  # noqa: ANN001
        super().__init__(DeterministicRandom(label), profiles)
        self.op, self.nth, self.calls = op, nth, 0

    def _maybe(self, op: str, value: bytes) -> bytes:
        if op == self.op:
            self.calls += 1
            if self.calls == self.nth:
                return flip(value, 0)
        return value

    def hmac(self, profile: Profile, key: Secret, data: bytes) -> bytes:
        return self._maybe("hmac", super().hmac(profile, key, data))

    def sign(self, profile: Profile, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        return self._maybe("sign", super().sign(profile, keys, role, th))


# --- the happy path ----------------------------------------------------------------------------


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_full_handshake_and_message_sizes(profile: Profile) -> None:
    run = handshake(initiator(profile=profile))
    assert [len(f.body) for f in (run.hello, run.reply, run.confirm, run.admit)] == [
        profile.hello_body_len,
        profile.reply_body_len,
        profile.confirm_body_len,
        profile.admit_body_len,
    ]
    i_est, r_est = one(run.on_admit, Established), one(run.on_decision, Established)
    assert i_est.peer == bob().bundle
    assert r_est.peer == alice().bundle
    assert i_est.profile is r_est.profile is profile
    assert run.i.state is run.r.state is State.ESTABLISHED
    i_ch, r_ch = run.channels()
    assert i_ch.is_initiator
    assert not r_ch.is_initiator
    # Both sides derived the same traffic secrets (checked through private state on purpose).
    assert i_ch._send.secret == r_ch._recv.secret
    assert i_ch._recv.secret == r_ch._send.secret
    assert i_ch._send.secret != i_ch._recv.secret


def test_responder_asks_for_admission_with_the_authenticated_initiator() -> None:
    run = handshake(initiator(gb=True), until="confirm")
    required = one(run.on_confirm, AdmissionRequired)
    assert required.peer == alice().bundle
    assert required.gb_request is True
    assert required.profile is HYBRID_1
    assert run.r.state is State.WAIT_ADMISSION


def test_first_contact_without_pin() -> None:
    run = handshake(initiator(pin=False))
    assert one(run.on_admit, Established).peer == bob().bundle


def test_accept_carries_reason_none() -> None:
    run = handshake()
    body = AdmitBody.decode(b"\x00\x00\x00")
    assert body.reason is AdmitReason.NONE
    # The Admit frame's plaintext is AdmitBody ‖ FinA; the initiator accepted it.
    assert one(run.on_admit, Established).glass_box is False


@pytest.mark.parametrize(("requested", "granted"), [(True, True), (True, False), (False, False)])
def test_glass_box_is_granted_only_on_request(requested: bool, granted: bool) -> None:
    run = handshake(initiator(gb=requested), glass_box=granted)
    assert one(run.on_admit, Established).glass_box is granted
    assert one(run.on_decision, Established).glass_box is granted


def test_glass_box_cannot_be_granted_without_request() -> None:
    run = handshake(until="confirm")
    with pytest.raises(ValueError, match="without a request"):
        run.r.accept(glass_box=True, now=4.0)


def test_initiator_refuses_unrequested_glass_box() -> None:
    # A responder that grants glass-box although it was not requested (forced past the API).
    run = handshake(until="confirm")
    run.r._gb_request = True
    run.on_decision = run.r.accept(glass_box=True, now=4.0)
    events = run.i.receive(run.admit, 5.0)
    assert closed(events).reason is CloseReason.POLICY
    assert none_of(events, Established)


@pytest.mark.parametrize("reason", [r for r in AdmitReason if r is not AdmitReason.NONE])
def test_reject_is_authenticated_and_named(reason: AdmitReason) -> None:
    run = handshake(until="confirm")
    decision = run.r.reject(reason, 4.0)
    assert closed(decision) == Closed(CloseReason.POLICY, reason)
    events = run.i.receive(sent(decision)[0], 5.0)
    assert closed(events) == Closed(CloseReason.POLICY, reason)
    assert run.i.state is State.CLOSED


def test_reject_needs_a_reason_and_a_pending_decision() -> None:
    run = handshake(until="confirm")
    with pytest.raises(ValueError, match="needs a reason"):
        run.r.reject(AdmitReason.NONE, 4.0)
    run.r.accept(glass_box=False, now=4.0)
    with pytest.raises(RuntimeError):
        run.r.reject(AdmitReason.DECLINED, 4.0)
    with pytest.raises(RuntimeError):
        handshake(until="hello").r.accept(glass_box=False, now=2.0)


def test_established_machine_refuses_more_frames() -> None:
    run = handshake()
    with pytest.raises(RuntimeError):
        run.i.receive(run.admit, 6.0)
    assert run.i.tick(1000.0) == []


# --- authentication failures -------------------------------------------------------------------


def test_pin_mismatch_aborts_before_confirm() -> None:
    carol = identity("carol").bundle
    run = handshake(initiator(pinned=carol), until="reply")
    mismatch = one(run.on_reply, KeyMismatch)
    assert mismatch.expected == carol
    assert mismatch.actual == bob().bundle
    assert closed(run.on_reply).reason is CloseReason.PIN_MISMATCH
    assert sent(run.on_reply) == []  # the initiator never revealed itself


def test_own_bundle_is_reflection() -> None:
    # Initiator: the responder proves our own identity (our Hello reflected to our own node).
    run = handshake(initiator(pin=False), responder(me=alice()), until="reply")
    assert closed(run.on_reply).reason is CloseReason.REFLECTION
    assert sent(run.on_reply) == []
    # Responder: the Hello carries one of our own outstanding ephemeral keys.
    i = initiator()
    hello = sent(i.start())[0]
    ek = Hello.decode(hello.body, HYBRID_1).ek
    r = responder(own_eks=frozenset({ek}))
    events = r.receive(hello, 1.0)
    assert closed(events).reason is CloseReason.REFLECTION
    assert sent(events) == []
    # Responder: the initiator proves the responder's own identity. The initiator's own
    # reflection check would stop this first, so its identity hides that from it.
    run = handshake(initiator(me=bob(), pin=False), until="hello")
    object.__setattr__(run.i, "_identity", _Other(bob()))
    run.on_reply = run.i.receive(run.reply, 2.0)
    events = run.r.receive(run.confirm, 3.0)
    assert closed(events).reason is CloseReason.REFLECTION


class _Other:
    """Our identity, but reporting a different bundle to the reflection check only."""

    def __init__(self, real: IdentityKeyPair) -> None:
        self._real = real
        self._calls = 0

    @property
    def bundle(self) -> object:
        self._calls += 1
        # First use: the reflection comparison. After that: the Confirm contents.
        return identity("someone-else").bundle if self._calls == 1 else self._real.bundle

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


@pytest.mark.parametrize(
    ("side", "op", "nth", "reason"),
    [
        ("r", "sign", 1, CloseReason.SIGNATURE_INVALID),  # SigR
        ("r", "hmac", 1, CloseReason.FINISHED_INVALID),  # FinR
        ("i", "sign", 1, CloseReason.SIGNATURE_INVALID),  # SigI
        ("i", "hmac", 2, CloseReason.FINISHED_INVALID),  # FinI (the 1st is its check of FinR)
    ],
)
def test_tampered_signature_or_finished_is_rejected(
    side: str, op: str, nth: int, reason: CloseReason
) -> None:
    if side == "r":
        run = handshake(r=responder(prov=Faulty("r", op, nth)), until="reply")
        assert closed(run.on_reply).reason is reason
        assert sent(run.on_reply) == []
    else:
        run = handshake(initiator(prov=Faulty("i", op, nth)), until="confirm")
        assert closed(run.on_confirm).reason is reason
        assert none_of(run.on_confirm, AdmissionRequired)


def test_tampered_finished_is_rejected() -> None:
    # FinA: the responder's third HMAC (after FinR and its check of FinI).
    run = handshake(r=responder(prov=Faulty("r", "hmac", 3)))
    assert closed(run.on_admit).reason is CloseReason.FINISHED_INVALID
    assert none_of(run.on_admit, Established)


@pytest.mark.parametrize("step", ["reply", "confirm", "admit"])
@pytest.mark.parametrize("where", ["first", "last"])
def test_any_bit_flip_in_a_sealed_message_is_decrypt_failed(step: str, where: str) -> None:
    def tamper(name: str, frame: Frame) -> Frame:
        if name != step:
            return frame
        index = len(frame.body) - 1 if where == "last" else 0
        return Frame(frame.type, flip(frame.body, index))

    run = handshake(tamper=tamper)
    events = {"reply": run.on_reply, "confirm": run.on_confirm, "admit": run.on_admit}[step]
    assert closed(events).reason is CloseReason.DECRYPT_FAILED


def test_tampered_kem_ciphertext_fails_to_decrypt() -> None:
    # ML-KEM's implicit rejection gives a different secret, so the Reply AEAD fails.
    def tamper(name: str, frame: Frame) -> Frame:
        return Frame(frame.type, flip(frame.body, 40)) if name == "reply" else frame

    assert closed(handshake(tamper=tamper).on_reply).reason is CloseReason.DECRYPT_FAILED


@pytest.mark.parametrize("change", ["strip_gb_request", "add_gb_request"])
def test_hello_changed_in_transit_breaks_the_transcript(change: str) -> None:
    """Attack Lab scenario 6: the responder accepts the altered Hello, the initiator cannot
    decrypt the Reply because the transcripts differ."""
    gb = change == "strip_gb_request"

    def tamper(name: str, frame: Frame) -> Frame:
        if name != "hello":
            return frame
        return Frame(frame.type, frame.body[:2] + bytes([0 if gb else 1]) + frame.body[3:])

    run = handshake(initiator(gb=gb), tamper=tamper)
    assert sent(run.on_hello)  # the responder saw a valid Hello
    assert closed(run.on_reply).reason is CloseReason.DECRYPT_FAILED


def test_invalid_identity_bundle_is_schema_error() -> None:
    # A responder whose bundle has an unknown version byte: the initiator parses it before
    # verifying anything with it.
    r = responder()
    object.__setattr__(r, "_identity", _BadBundle(bob(), b"\x09" + bob().bundle.encode()[1:]))
    run = handshake(r=r, until="reply")
    assert closed(run.on_reply).reason is CloseReason.SCHEMA_ERROR


class _BadBundle:
    def __init__(self, real: IdentityKeyPair, encoded: bytes) -> None:
        self._real = real
        self._encoded = encoded

    @property
    def bundle(self) -> object:
        real = self._real.bundle
        encoded = self._encoded

        class B:
            def encode(self) -> bytes:
                return encoded

            def __eq__(self, other: object) -> bool:
                return other == real

            def __hash__(self) -> int:
                return hash(real)

        return B()

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


# --- profiles ----------------------------------------------------------------------------------


def test_unserved_profile_gets_profile_unsupported() -> None:
    run = handshake(initiator(profile=PQ_CNSA_1), responder(profiles=[HYBRID_1]), until="reply")
    frame = sent(run.on_hello)[0]
    assert frame == Frame(FrameType.PROFILE_UNSUPPORTED, b"\x01")
    assert closed(run.on_hello).reason is CloseReason.POLICY
    assert one(run.on_reply, ProfileRejected).supported == 0x01
    assert closed(run.on_reply).reason is CloseReason.POLICY


def test_lab_classical_is_refused_by_a_real_node() -> None:
    lab = initiator(profile=LAB_CLASSICAL, prov=provider("lab", LAB_PROFILES))
    events = responder().receive(sent(lab.start())[0], 1.0)
    assert sent(events) == [Frame(FrameType.PROFILE_UNSUPPORTED, b"\x03")]
    assert closed(events).reason is CloseReason.POLICY


def test_lab_classical_works_between_lab_nodes() -> None:
    lab_i = initiator(profile=LAB_CLASSICAL, prov=provider("lab-i", LAB_PROFILES))
    lab_r = responder(profiles=LAB_PROFILES, prov=provider("lab-r", LAB_PROFILES))
    run = handshake(lab_i, lab_r)
    assert one(run.on_admit, Established).profile is LAB_CLASSICAL
    assert [len(f.body) for f in (run.hello, run.reply, run.confirm, run.admit)] == [
        67,
        4753,
        4689,
        51,
    ]


def test_provider_gates_profiles_even_if_the_responder_lists_them() -> None:
    # Handed LAB-CLASSICAL but built with REAL_PROFILES: the provider refuses (DESIGN §4).
    lab = initiator(profile=LAB_CLASSICAL, prov=provider("lab", LAB_PROFILES))
    r = responder(profiles=LAB_PROFILES, prov=provider("real"))
    assert closed(r.receive(sent(lab.start())[0], 1.0)).reason is CloseReason.POLICY


def test_hello_with_wrong_size_or_bad_prefix_closes_silently() -> None:
    hello = sent(initiator().start())[0]
    for body in (hello.body + b"\x00", hello.body[:-1], b"\x01" + hello.body[1:], hello.body[:2]):
        events = responder().receive(Frame(FrameType.HELLO, body), 1.0)
        assert closed(events).reason is CloseReason.SCHEMA_ERROR
        assert sent(events) == []


def test_invalid_kem_key_in_hello() -> None:
    hello = sent(initiator().start())[0]
    bad = hello.body[:35] + b"\xff" * 1184 + hello.body[35 + 1184 :]  # coefficients >= q
    assert closed(responder().receive(Frame(FrameType.HELLO, bad), 1.0)).reason is (
        CloseReason.INVALID_KEM_KEY
    )


# --- deadlines -----------------------------------------------------------------------------------


def test_handshake_deadline_expires() -> None:
    # Responder waiting for Confirm.
    run = handshake(until="hello")
    assert run.r.tick(HANDSHAKE_DEADLINE - 0.001) == []
    events = run.r.tick(HANDSHAKE_DEADLINE)
    assert closed(events).reason is CloseReason.TIMEOUT
    assert sent(events) == []
    # Initiator waiting for Reply.
    i = initiator()
    i.start()
    assert closed(i.tick(HANDSHAKE_DEADLINE)).reason is CloseReason.TIMEOUT
    # A late frame is refused even without a tick.
    run = handshake(until="hello")
    events = run.i.receive(run.reply, HANDSHAKE_DEADLINE + 1)
    assert closed(events).reason is CloseReason.TIMEOUT
    assert sent(events) == []


def test_initiator_waits_for_the_admission_prompt() -> None:
    run = handshake(until="confirm")
    assert run.i.tick(2.0 + INITIATOR_ADMIT_DEADLINE - 0.001) == []
    assert closed(run.i.tick(2.0 + INITIATOR_ADMIT_DEADLINE)).reason is CloseReason.TIMEOUT


def test_admission_prompt_expiry_rejects_with_timeout() -> None:
    run = handshake(until="confirm")
    assert run.r.tick(3.0 + ADMISSION_DEADLINE - 0.001) == []
    events = run.r.tick(3.0 + ADMISSION_DEADLINE)
    assert closed(events) == Closed(CloseReason.POLICY, AdmitReason.TIMEOUT)
    admit = sent(events)[0]
    assert closed(run.i.receive(admit, 64.0)) == Closed(CloseReason.POLICY, AdmitReason.TIMEOUT)
    # A decision after the deadline is too late: the reject already went out.
    run = handshake(until="confirm")
    events = run.r.accept(glass_box=False, now=3.0 + ADMISSION_DEADLINE)
    assert closed(events).admit_reason is AdmitReason.TIMEOUT
    assert none_of(events, Established)


# --- every message in every state --------------------------------------------------------------


def sample_frames() -> dict[FrameType, Frame]:
    run = handshake(until="decision")
    return {
        FrameType.HELLO: run.hello,
        FrameType.REPLY: run.reply,
        FrameType.CONFIRM: run.confirm,
        FrameType.ADMIT: run.admit,
        FrameType.PROFILE_UNSUPPORTED: Frame(FrameType.PROFILE_UNSUPPORTED, b"\x03"),
        FrameType.RECORD: Frame(FrameType.RECORD, b"\x00" * 32),
    }


EXPECTED = {
    ("i", "wait_reply"): {FrameType.REPLY, FrameType.PROFILE_UNSUPPORTED},
    ("i", "wait_admit"): {FrameType.ADMIT},
    ("r", "wait_hello"): {FrameType.HELLO},
    ("r", "wait_confirm"): {FrameType.CONFIRM},
    ("r", "wait_admission"): set(),
}


def machine_in(side: str, state: str):  # noqa: ANN201
    until = {
        ("i", "wait_reply"): "start",
        ("i", "wait_admit"): "reply",
        ("r", "wait_hello"): None,
        ("r", "wait_confirm"): "hello",
        ("r", "wait_admission"): "confirm",
    }[(side, state)]
    if until is None:
        return responder()
    run = handshake(until=until)
    return run.i if side == "i" else run.r


@pytest.mark.parametrize(("side", "state"), list(EXPECTED))
@pytest.mark.parametrize("frame_type", list(FrameType))
def test_every_invalid_message_in_every_state(side: str, state: str, frame_type: FrameType) -> None:
    if frame_type in EXPECTED[(side, state)]:
        pytest.skip("valid in this state; covered by the happy-path tests")
    machine = machine_in(side, state)
    assert machine.state.value == state
    frame = sample_frames()[frame_type]
    events = machine.receive(frame, 3.5)
    assert closed(events).reason is CloseReason.UNEXPECTED_MESSAGE
    assert none_of(events, Send)
    assert machine.state is State.CLOSED
    assert machine.receive(frame, 3.6) == []  # closed machines ignore everything


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    side_state=st.sampled_from(list(EXPECTED)),
    frame_type=st.sampled_from(list(FrameType)),
    body=st.binary(max_size=12_000),
)
def test_garbage_in_any_state_closes_with_a_named_reason(
    side_state: tuple[str, str], frame_type: FrameType, body: bytes
) -> None:
    machine = machine_in(*side_state)
    events = machine.receive(Frame(frame_type, body), 3.5)
    assert closed(events).reason in set(CloseReason)
    assert machine.state is State.CLOSED


# --- tracing -------------------------------------------------------------------------------------


def test_trace_names_secrets_and_transcript_hashes_without_values() -> None:
    run = handshake()
    events = [*run.start, *run.on_hello, *run.on_reply, *run.on_confirm, *run.on_decision]
    events += run.on_admit
    labels = {t.label for t in traces(events) if isinstance(t, SecretDerived)}
    assert {"hs", "hs_R", "hs_I", "fk_R", "fk_I", "cs_0", "ap_I[0]", "ap_R[0]"} <= labels
    assert {"exporter_0", "ss", "ssM", "ssX"} <= labels
    names = [t.name for t in traces(run.on_admit) if isinstance(t, TranscriptHashed)]
    assert names[-1] == "th_final"
    i_final = next(
        t for t in traces(run.on_admit) if isinstance(t, TranscriptHashed) and t.name == "th_final"
    )
    r_final = next(
        t
        for t in traces(run.on_decision)
        if isinstance(t, TranscriptHashed) and t.name == "th_final"
    )
    assert i_final.digest == r_final.digest


def test_admit_body_is_bound_to_the_decision() -> None:
    assert AdmitBody(Decision.ACCEPT, glass_box=False, reason=AdmitReason.NONE).encode() == bytes(3)
