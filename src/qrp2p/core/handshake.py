"""The four-message handshake with admission, as sans-I/O state machines (DESIGN §7).

```text
I -> R  Hello    (plaintext)  profile, flags, nonce_I, ek_I
R -> I  Reply    nonce_R, ct, AEAD(Keys(hs_R), 0, IdR ‖ SigR ‖ FinR)
I -> R  Confirm  AEAD(Keys(hs_I), 0, IdI ‖ SigI ‖ FinI)       only after IdR matched the pin
R -> I  Admit    AEAD(Keys(hs_R), 1, AdmitBody ‖ FinA)         only after the admission decision
```

The services drive the machines: they pass in frames, the current monotonic time and the user's
admission decision, and act on the returned :mod:`~qrp2p.core.events`. Randomness and every
cryptographic operation come from the injected provider.

Every failure closes the handshake silently with a named reason (DESIGN §8.5: failures before
authentication close silently). After a close, the machine ignores further input.
"""

import hmac
from collections.abc import Callable, Container, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.profiles import NONCE_LEN, Profile
from qrp2p.core.crypto.provider import CryptoProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import AdmitReason, CloseReason, ProtocolError
from qrp2p.core.events import Closed, Send, Trace
from qrp2p.core.record import Channel
from qrp2p.core.schedule import HandshakeSecrets, first_epoch, handshake_secrets
from qrp2p.core.trace import (
    Direction,
    FrameTraced,
    ReleaseCause,
    SecretDerived,
    SecretsReleased,
    SessionClosed,
    StateChanged,
    TranscriptHashed,
    dissect,
)
from qrp2p.core.wire import (
    ADMIT_BODY_LEN,
    AdmitBody,
    Decision,
    Frame,
    FrameType,
    Hello,
    Reply,
    SignedInner,
    Tag,
    Transcript,
    check_sealed_len,
    decode_profile_unsupported,
    frame_header,
    hello_prefix,
    profile_bitmask,
)

HANDSHAKE_DEADLINE: Final = 10.0
"""Seconds from Hello to Confirm (DESIGN §6.4)."""
ADMISSION_DEADLINE: Final = 60.0
"""Seconds the responder's user has to decide (DESIGN §6.4, §7.6)."""
INITIATOR_ADMIT_DEADLINE: Final = ADMISSION_DEADLINE + HANDSHAKE_DEADLINE
"""Seconds the initiator waits for Admit after sending Confirm: the prompt plus network slack."""


@dataclass(frozen=True, slots=True)
class AdmissionRequired:
    """Responder: the initiator is authenticated; decide with ``accept`` or ``reject``.

    The policy (DESIGN §7.6) lives in the services, because it needs the contact list.
    """

    peer: IdentityBundle
    gb_request: bool
    profile: Profile


@dataclass(frozen=True, slots=True)
class KeyMismatch:
    """Initiator: the responder proved a bundle other than the pinned one (DESIGN §5.3).

    The handshake closes with ``pin_mismatch`` before the initiator reveals itself.
    """

    expected: IdentityBundle
    actual: IdentityBundle


@dataclass(frozen=True, slots=True)
class ProfileRejected:
    """Initiator: the responder does not serve the offered profile.

    ``supported`` is an unauthenticated hint (DESIGN §7.7); it MUST NOT change a contact's
    configured profile.
    """

    supported: int


@dataclass(frozen=True, slots=True)
class Established:
    """The session is open. ``channel`` carries the traffic keys; never trace this event."""

    channel: Channel
    peer: IdentityBundle
    profile: Profile
    glass_box: bool


type HandshakeEvent = (
    Send | Trace | Closed | AdmissionRequired | KeyMismatch | ProfileRejected | Established
)


class State(StrEnum):
    """Handshake states."""

    START = "start"
    WAIT_HELLO = "wait_hello"
    WAIT_REPLY = "wait_reply"
    WAIT_CONFIRM = "wait_confirm"
    WAIT_ADMISSION = "wait_admission"
    WAIT_ADMIT = "wait_admit"
    ESTABLISHED = "established"
    CLOSED = "closed"


def _check_finished(expected: bytes, received: bytes) -> None:
    if not hmac.compare_digest(expected, received):
        raise ProtocolError(CloseReason.FINISHED_INVALID, "Finished MAC mismatch")


class _Machine:
    """What both roles share: state, transcript, tracing and failure handling."""

    _machine_name: str = ""

    def __init__(self, provider: CryptoProvider, identity: IdentityKeyPair, now: float) -> None:
        self._provider = provider
        self._identity = identity
        self._state = State.START
        self._deadline = now + HANDSHAKE_DEADLINE
        self._profile: Profile | None = None
        self._transcript: Transcript | None = None
        self._secrets: HandshakeSecrets | None = None
        self._events: list[HandshakeEvent] = []

    @property
    def state(self) -> State:
        """The current state."""
        return self._state

    @property
    def profile(self) -> Profile | None:
        """The session's profile, once known."""
        return self._profile

    # -- helpers ----------------------------------------------------------------------------

    def _emit(self, event: HandshakeEvent) -> None:
        self._events.append(event)

    def _take(self) -> list[HandshakeEvent]:
        events, self._events = self._events, []
        return events

    def _enter(self, state: State) -> None:
        self._state = state
        self._emit(Trace(StateChanged(self._machine_name, state.value)))

    def _send(self, frame: Frame) -> None:
        self._emit(Trace(FrameTraced(Direction.OUT, frame, dissect(frame, self._profile))))
        self._emit(Send(frame))

    def _trace_in(self, frame: Frame, profile: Profile | None = None) -> None:
        dissected = dissect(frame, profile or self._profile)
        self._emit(Trace(FrameTraced(Direction.IN, frame, dissected)))

    def _trace_secrets(self, *secrets: Secret) -> None:
        for secret in secrets:
            self._emit(Trace(SecretDerived(secret.label, len(secret))))

    def _release(self, cause: ReleaseCause, *secrets: Secret) -> None:
        """Note that the engine dropped its references to ``secrets`` (DESIGN §7.4 "erase")."""
        if secrets:
            labels = tuple(secret.label for secret in secrets)
            self._emit(Trace(SecretsReleased(labels, cause)))

    def _hash(self, name: str) -> bytes:
        assert self._transcript is not None  # noqa: S101  # set before any hashing
        digest = self._transcript.digest()
        self._emit(Trace(TranscriptHashed(name, digest)))
        return digest

    def _close(self, reason: CloseReason, admit_reason: AdmitReason | None = None) -> None:
        self._drop_secrets(ReleaseCause.CLOSED)
        self._enter(State.CLOSED)
        self._emit(Trace(SessionClosed(reason, admit_reason, by_peer=False)))
        self._emit(Closed(reason, admit_reason))

    def _held(self) -> tuple[Secret, ...]:
        """The secrets the machine references now."""
        return self._secrets.all() if self._secrets is not None else ()

    def _drop_secrets(self, cause: ReleaseCause) -> None:
        """Erase: drop every reference to handshake secrets (DESIGN §3.5, §7.4)."""
        held = self._held()
        self._secrets = None
        self._release(cause, *held)

    def _require_not_established(self) -> None:
        if self._state is State.ESTABLISHED:
            msg = "the handshake is over; frames now go to the channel"
            raise RuntimeError(msg)

    def _run(self, step: Callable[[], object]) -> list[HandshakeEvent]:
        if self._state in {State.CLOSED, State.ESTABLISHED}:
            return []
        try:
            step()
        except ProtocolError as error:
            self._close(error.reason)
        return self._take()

    def _check_deadline(self, now: float) -> bool:
        if now >= self._deadline and self._state not in {State.ESTABLISHED, State.CLOSED}:
            self._on_deadline()
            return True
        return False

    def _on_deadline(self) -> None:
        self._close(CloseReason.TIMEOUT)

    def tick(self, now: float) -> list[HandshakeEvent]:
        """Advance time; enforce deadlines."""
        return self._run(lambda: self._check_deadline(now))

    def _establish(
        self,
        peer: IdentityBundle,
        th_final: bytes,
        *,
        glass_box: bool,
        is_initiator: bool,
        now: float,
    ) -> None:
        profile, secrets = self._profile, self._secrets
        assert profile is not None and secrets is not None  # noqa: S101, PT018
        salt, epoch = first_epoch(self._provider, profile, secrets.hs, th_final)
        self._trace_secrets(salt, *epoch.all())
        channel = Channel(
            provider=self._provider,
            profile=profile,
            is_initiator=is_initiator,
            identity=self._identity,
            peer=peer,
            epoch=epoch,
            glass_box=glass_box,
            now=now,
        )
        self._events.extend(channel.take_traces())  # its traffic keys, derived just now
        # The salt and cs_0 are a derivation root, not state (DESIGN §7.4).
        self._release(ReleaseCause.USED, salt, epoch.cs)
        self._drop_secrets(ReleaseCause.HANDSHAKE_DONE)
        self._enter(State.ESTABLISHED)
        self._emit(Established(channel, peer, profile, glass_box))


class Initiator(_Machine):
    """The initiator (DESIGN §7.5).

    Args:
        provider: The session's crypto provider.
        profile: The profile to offer: the contact's configured one, else ``HYBRID-1``.
        identity: Our identity.
        pinned: The contact's pinned bundle, or ``None`` for a first contact (discovery or manual
            connect with no contact).
        glass_box_request: Ask for a glass-box session (``gb_request``).
        now: The current monotonic time.
    """

    _machine_name = "initiator"

    def __init__(
        self,
        *,
        provider: CryptoProvider,
        profile: Profile,
        identity: IdentityKeyPair,
        pinned: IdentityBundle | None,
        glass_box_request: bool,
        now: float,
    ) -> None:
        super().__init__(provider, identity, now)
        self._profile = profile
        self._pinned = pinned
        self._gb_request = glass_box_request
        self._dk: Secret | None = None
        self._ek: bytes | None = None
        self._peer: IdentityBundle | None = None

    @property
    def ephemeral_key(self) -> bytes | None:
        """Our outstanding ``ek_I``, for the services' reflection check (DESIGN §7.5)."""
        return self._ek if self._state is State.WAIT_REPLY else None

    @property
    def peer(self) -> IdentityBundle | None:
        """The responder, once Reply proved it (pin and reflection checked), else ``None``.

        The services need it before Admit, to recognise a simultaneous open (DESIGN §7.8).
        """
        return self._peer

    def start(self) -> list[HandshakeEvent]:
        """Send Hello."""
        if self._state is not State.START:
            msg = "start() called twice"
            raise RuntimeError(msg)
        return self._run(self._start)

    def _start(self) -> None:
        profile = self._profile
        assert profile is not None  # noqa: S101
        self._dk, self._ek = self._provider.kem_keygen(profile)
        self._trace_secrets(self._dk)
        hello = Hello(profile.id, self._gb_request, self._provider.random(NONCE_LEN), self._ek)
        self._transcript = Transcript(profile.hash)
        self._transcript.add(Tag.HELLO, hello.encode())
        self._send(Frame(FrameType.HELLO, hello.encode()))
        self._enter(State.WAIT_REPLY)

    def receive(self, frame: Frame, now: float) -> list[HandshakeEvent]:
        """Process a frame from the responder.

        Raises:
            RuntimeError: The handshake is already established.
        """
        self._require_not_established()
        return self._run(lambda: self._receive(frame, now))

    def _receive(self, frame: Frame, now: float) -> None:
        if self._check_deadline(now):
            return
        self._trace_in(frame)
        match (self._state, frame.type):
            case (State.WAIT_REPLY, FrameType.REPLY):
                self._on_reply(frame, now)
            case (State.WAIT_REPLY, FrameType.PROFILE_UNSUPPORTED):
                self._emit(ProfileRejected(decode_profile_unsupported(frame.body)))
                self._close(CloseReason.POLICY)
            case (State.WAIT_ADMIT, FrameType.ADMIT):
                self._on_admit(frame, now)
            case _:
                raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "frame not expected now")

    def _on_reply(self, frame: Frame, now: float) -> None:
        profile, transcript, dk = self._profile, self._transcript, self._dk
        assert profile is not None and transcript is not None and dk is not None  # noqa: S101, PT018
        provider = self._provider
        reply = Reply.decode(frame.body, profile)
        shared = provider.kem_decapsulate(profile, dk, reply.ct)
        self._dk = None  # erase the ephemeral key: it has done its only job
        self._release(ReleaseCause.USED, dk)
        transcript.add(Tag.REPLY, reply.transcript_value)
        secrets = handshake_secrets(provider, profile, shared.ss, self._hash("th_hello"))
        self._secrets = secrets
        self._trace_secrets(*shared.components, shared.ss, *secrets.all())
        self._release(ReleaseCause.USED, *shared.components, shared.ss)

        plaintext = provider.unseal(profile, secrets.keys_r, 0, frame.header, reply.sealed)
        inner = SignedInner.decode(plaintext, profile)
        peer = IdentityBundle.decode(inner.identity)
        transcript.add(Tag.ID_R, inner.identity)
        provider.verify(profile, peer, Role.RESPONDER, self._hash("th_sig_R"), inner.signature)
        transcript.add(Tag.SIG_R, inner.signature)
        _check_finished(
            provider.hmac(profile, secrets.fk_r, self._hash("th_fin_R")), inner.finished
        )
        if self._pinned is not None and peer != self._pinned:
            self._emit(KeyMismatch(self._pinned, peer))
            raise ProtocolError(CloseReason.PIN_MISMATCH, "responder is not the pinned contact")
        if peer == self._identity.bundle:
            raise ProtocolError(CloseReason.REFLECTION, "responder proved our own identity")
        self._peer = peer

        # Confirm: only now do we reveal who we are.
        transcript.add(Tag.FIN_R, inner.finished)
        own = self._identity.bundle.encode()
        transcript.add(Tag.ID_I, own)
        sig = provider.sign(profile, self._identity, Role.INITIATOR, self._hash("th_sig_I"))
        transcript.add(Tag.SIG_I, sig)
        fin = provider.hmac(profile, secrets.fk_i, self._hash("th_fin_I"))
        transcript.add(Tag.FIN_I, fin)
        header = frame_header(FrameType.CONFIRM, profile.confirm_body_len)
        body = provider.seal(profile, secrets.keys_i, 0, header, own + sig + fin)
        self._send(Frame(FrameType.CONFIRM, body))
        self._deadline = now + INITIATOR_ADMIT_DEADLINE
        self._enter(State.WAIT_ADMIT)

    def _on_admit(self, frame: Frame, now: float) -> None:
        profile, transcript, secrets = self._profile, self._transcript, self._secrets
        assert profile is not None and transcript is not None and secrets is not None  # noqa: S101, PT018
        assert self._peer is not None  # noqa: S101
        check_sealed_len(frame.body, profile.admit_body_len)
        plaintext = self._provider.unseal(profile, secrets.keys_r, 1, frame.header, frame.body)
        body = AdmitBody.decode(plaintext[:ADMIT_BODY_LEN])
        transcript.add(Tag.ADMIT_BODY, plaintext[:ADMIT_BODY_LEN])
        expected = self._provider.hmac(profile, secrets.fk_r, self._hash("th_fin_A"))
        _check_finished(expected, plaintext[ADMIT_BODY_LEN:])
        transcript.add(Tag.FIN_A, plaintext[ADMIT_BODY_LEN:])
        th_final = self._hash("th_final")
        if body.glass_box and not self._gb_request:
            raise ProtocolError(CloseReason.POLICY, "glass-box granted but never requested")
        if body.decision is Decision.REJECT:
            self._close(CloseReason.POLICY, body.reason)
            return
        self._establish(self._peer, th_final, glass_box=body.glass_box, is_initiator=True, now=now)

    def _held(self) -> tuple[Secret, ...]:
        return (*super()._held(), *((self._dk,) if self._dk is not None else ()))

    def _drop_secrets(self, cause: ReleaseCause) -> None:
        super()._drop_secrets(cause)
        self._dk = None


class Responder(_Machine):
    """The responder, including the admission step (DESIGN §7.5, §7.6).

    Args:
        provider: The session's crypto provider; it serves ``profiles``.
        profiles: The profiles this node serves. Real nodes pass ``REAL_PROFILES``; only solo-lab
            nodes add ``LAB-CLASSICAL``.
        identity: Our identity.
        own_ephemeral_keys: Our outstanding initiator ``ek_I`` values (live view), for the
            reflection check.
        now: The current monotonic time.
    """

    _machine_name = "responder"

    def __init__(
        self,
        *,
        provider: CryptoProvider,
        profiles: Iterable[Profile],
        identity: IdentityKeyPair,
        own_ephemeral_keys: Container[bytes],
        now: float,
    ) -> None:
        super().__init__(provider, identity, now)
        self._served = {p.id: p for p in profiles}
        self._own_eks = own_ephemeral_keys
        self._state = State.WAIT_HELLO
        self._gb_request = False
        self._peer: IdentityBundle | None = None

    def receive(self, frame: Frame, now: float) -> list[HandshakeEvent]:
        """Process a frame from the initiator.

        Raises:
            RuntimeError: The handshake is already established.
        """
        self._require_not_established()
        return self._run(lambda: self._receive(frame, now))

    def _receive(self, frame: Frame, now: float) -> None:
        if self._check_deadline(now):
            return
        match (self._state, frame.type):
            case (State.WAIT_HELLO, FrameType.HELLO):
                self._on_hello(frame)
            case (State.WAIT_CONFIRM, FrameType.CONFIRM):
                self._trace_in(frame)
                self._on_confirm(frame, now)
            case _:
                self._trace_in(frame)
                raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "frame not expected now")

    def _on_hello(self, frame: Frame) -> None:
        try:
            profile_id, gb_request = hello_prefix(frame.body)
        except ProtocolError:
            self._trace_in(frame)
            raise
        profile = self._served.get(profile_id)
        self._trace_in(frame, profile)  # with the offered profile, so the trace splits ek_I
        if profile is None:
            supported = profile_bitmask(self._served.values())
            self._send(Frame(FrameType.PROFILE_UNSUPPORTED, bytes([supported])))
            raise ProtocolError(CloseReason.POLICY, "profile not served")
        self._profile = profile
        hello = Hello.decode(frame.body, profile)
        if hello.ek in self._own_eks:
            raise ProtocolError(CloseReason.REFLECTION, "Hello carries our own ephemeral key")
        self._gb_request = gb_request
        provider = self._provider
        shared, ct = provider.kem_encapsulate(profile, hello.ek)
        nonce = provider.random(NONCE_LEN)
        transcript = self._transcript = Transcript(profile.hash)
        transcript.add(Tag.HELLO, frame.body)
        transcript.add(Tag.REPLY, nonce + ct)
        secrets = handshake_secrets(provider, profile, shared.ss, self._hash("th_hello"))
        self._secrets = secrets
        self._trace_secrets(*shared.components, shared.ss, *secrets.all())
        self._release(ReleaseCause.USED, *shared.components, shared.ss)

        own = self._identity.bundle.encode()
        transcript.add(Tag.ID_R, own)
        sig = provider.sign(profile, self._identity, Role.RESPONDER, self._hash("th_sig_R"))
        transcript.add(Tag.SIG_R, sig)
        fin = provider.hmac(profile, secrets.fk_r, self._hash("th_fin_R"))
        transcript.add(Tag.FIN_R, fin)
        header = frame_header(FrameType.REPLY, profile.reply_body_len)
        sealed = provider.seal(profile, secrets.keys_r, 0, header, own + sig + fin)
        self._send(Frame(FrameType.REPLY, Reply(nonce, ct, sealed).encode()))
        self._enter(State.WAIT_CONFIRM)

    def _on_confirm(self, frame: Frame, now: float) -> None:
        profile, transcript, secrets = self._profile, self._transcript, self._secrets
        assert profile is not None and transcript is not None and secrets is not None  # noqa: S101, PT018
        provider = self._provider
        check_sealed_len(frame.body, profile.confirm_body_len)
        plaintext = provider.unseal(profile, secrets.keys_i, 0, frame.header, frame.body)
        inner = SignedInner.decode(plaintext, profile)
        peer = IdentityBundle.decode(inner.identity)
        transcript.add(Tag.ID_I, inner.identity)
        provider.verify(profile, peer, Role.INITIATOR, self._hash("th_sig_I"), inner.signature)
        transcript.add(Tag.SIG_I, inner.signature)
        _check_finished(
            provider.hmac(profile, secrets.fk_i, self._hash("th_fin_I")), inner.finished
        )
        transcript.add(Tag.FIN_I, inner.finished)
        if peer == self._identity.bundle:
            raise ProtocolError(CloseReason.REFLECTION, "initiator proved our own identity")
        self._peer = peer
        self._deadline = now + ADMISSION_DEADLINE
        self._enter(State.WAIT_ADMISSION)
        self._emit(AdmissionRequired(peer, self._gb_request, profile))

    def accept(self, *, glass_box: bool, now: float) -> list[HandshakeEvent]:
        """Admit the initiator; ``glass_box`` only if it was requested (DESIGN §7.6, §11.3).

        Raises:
            RuntimeError: Not waiting for an admission decision.
            ValueError: ``glass_box`` without ``gb_request``.
        """
        self._require_admission()
        if glass_box and not self._gb_request:
            msg = "glass-box cannot be granted without a request"
            raise ValueError(msg)
        body = AdmitBody(Decision.ACCEPT, glass_box=glass_box, reason=AdmitReason.NONE)
        return self._run(lambda: self._admit(body, now))

    def reject(self, reason: AdmitReason, now: float) -> list[HandshakeEvent]:
        """Reject the initiator with a named reason.

        Raises:
            RuntimeError: Not waiting for an admission decision.
            ValueError: ``reason`` is ``none``.
        """
        self._require_admission()
        if reason is AdmitReason.NONE:
            msg = "a reject needs a reason"
            raise ValueError(msg)
        body = AdmitBody(Decision.REJECT, glass_box=False, reason=reason)
        return self._run(lambda: self._admit(body, now))

    def _require_admission(self) -> None:
        if self._state is not State.WAIT_ADMISSION:
            msg = "no admission decision is pending"
            raise RuntimeError(msg)

    def _admit(self, body: AdmitBody, now: float) -> None:
        if not self._check_deadline(now):
            self._send_admit(body, now)

    def _send_admit(self, body: AdmitBody, now: float) -> None:
        profile, transcript, secrets = self._profile, self._transcript, self._secrets
        assert profile is not None and transcript is not None and secrets is not None  # noqa: S101, PT018
        assert self._peer is not None  # noqa: S101
        encoded = body.encode()
        transcript.add(Tag.ADMIT_BODY, encoded)
        fin = self._provider.hmac(profile, secrets.fk_r, self._hash("th_fin_A"))
        transcript.add(Tag.FIN_A, fin)
        th_final = self._hash("th_final")
        header = frame_header(FrameType.ADMIT, profile.admit_body_len)
        sealed = self._provider.seal(profile, secrets.keys_r, 1, header, encoded + fin)
        self._send(Frame(FrameType.ADMIT, sealed))
        if body.decision is Decision.REJECT:
            self._close(CloseReason.POLICY, body.reason)
            return
        self._establish(self._peer, th_final, glass_box=body.glass_box, is_initiator=False, now=now)

    def _on_deadline(self) -> None:
        if self._state is State.WAIT_ADMISSION:
            # Expiry of the prompt is a reject with reason timeout (DESIGN §7.6).
            timeout = AdmitBody(Decision.REJECT, glass_box=False, reason=AdmitReason.TIMEOUT)
            self._send_admit(timeout, self._deadline)
            return
        super()._on_deadline()
