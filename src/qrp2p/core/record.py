"""The record layer of an established session (DESIGN §8), as a sans-I/O machine.

```text
Record body = AEAD(Keys(ap_dir).key, nonce = Keys(ap_dir).iv XOR u96(seq_dir), aad = header, Inner)
```

- ``seq_dir`` is implicit: each side keeps its own counter per direction, so a replayed, dropped
  or reordered record fails to open (``decrypt_failed``).
- The services own the writer task and its priority queue (DESIGN §8.3). They call
  :meth:`Channel.seal_next` for each message as they dequeue it, which takes the next sequence
  number at that moment. Everything the channel itself wants to send is returned as a
  :class:`~qrp2p.core.events.Queue` event, never sealed early.
- KeyUpdate and the signed PQ rekey (DESIGN §8.4) run inside the channel. Liveness and the key
  evolution timers run from :meth:`Channel.tick`.

Failures after authentication queue a ``close`` record with the named reason (the channel still
works in the sending direction) and report :class:`~qrp2p.core.events.Closed`.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from qrp2p.core.crypto.aead import MAX_SEQ, TAG_LEN
from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.kdf import TrafficKeys
from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.crypto.provider import CryptoProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError
from qrp2p.core.events import Closed, Deliver, Priority, Queue, Send, Trace
from qrp2p.core.schedule import EpochSecrets, EpochState, next_epoch, updated_traffic_secret
from qrp2p.core.trace import (
    Direction,
    FrameTraced,
    KeysSwitched,
    RecordTraced,
    RekeyStep,
    ReleaseCause,
    SecretDerived,
    SecretsReleased,
    SessionClosed,
    dissect,
)
from qrp2p.core.wire import (
    MAX_RECORD_BODY,
    Close,
    Frame,
    FrameType,
    Inner,
    KeyUpdate,
    Ping,
    Pong,
    RekeyAnswer,
    RekeyFinish,
    RekeyOffer,
    RekeySwitch,
    Tag,
    decode_inner,
    encode_inner,
    frame_header,
    inner_kind,
    transcript_entry,
)

KEY_UPDATE_RECORDS: Final = 2**16
"""Records per direction before a KeyUpdate (DESIGN §8.4)."""
KEY_UPDATE_SECONDS: Final = 600.0
REKEY_SECONDS: Final = 3600.0
"""The initiator starts a PQ rekey this long after the current epoch began."""
REKEY_MIN_INTERVAL: Final = 60.0
"""The initiator starts at most one rekey per minute (DESIGN §8.4)."""
REKEY_OFFER_MIN_GAP: Final = 30.0
"""The responder refuses a ``rekey_offer`` this soon after the previous one. Half the
initiator's interval, so network delay cannot make an honest initiator look too fast."""
PING_AFTER: Final = 30.0
IDLE_TIMEOUT: Final = 90.0

_CONTROL: Final = (KeyUpdate, RekeyOffer, RekeyAnswer, RekeyFinish, RekeySwitch, Ping, Pong, Close)

type ChannelEvent = Send | Queue | Deliver | Trace | Closed


class ChannelState(StrEnum):
    """Channel states."""

    OPEN = "open"
    CLOSING = "closing"
    """A failure or a local close queued the final ``close`` record; nothing else is sealed."""
    CLOSED = "closed"


@dataclass(slots=True)
class _Direction:
    """One direction's traffic secret, keys and counter."""

    secret: Secret
    keys: TrafficKeys
    seq: int = 0
    epoch: int = 0
    generation: int = 0
    records: int = 0
    """Records sealed under this secret (send direction only; triggers KeyUpdate)."""
    since: float = 0.0

    def secrets(self) -> tuple[Secret, ...]:
        """The traffic secret and its key and IV."""
        return (self.secret, self.keys.key, self.keys.iv)


@dataclass(slots=True)
class _Rekey:
    """A PQ rekey in progress (DESIGN §8.4)."""

    rt: bytes
    dk: Secret | None = None
    ss: Secret | None = None
    sig_r: bytes = b""
    next: EpochState | None = None
    send: Secret | None = None
    recv: Secret | None = None
    send_switched: bool = False
    recv_switched: bool = False

    def held(self) -> tuple[Secret, ...]:
        """The secrets this rekey references now (the new epoch's retained state excepted)."""
        pending = (self.dk, self.ss, self.send, self.recv)
        return tuple(secret for secret in pending if secret is not None)


class Channel:
    """An established session's record layer.

    Created by the handshake (``Established.channel``); not constructed by the services.
    """

    def __init__(  # noqa: PLR0913
        self,
        *,
        provider: CryptoProvider,
        profile: Profile,
        is_initiator: bool,
        identity: IdentityKeyPair,
        peer: IdentityBundle,
        epoch: EpochSecrets,
        glass_box: bool,
        now: float,
    ) -> None:
        self._provider = provider
        self._profile = profile
        self._is_initiator = is_initiator
        self._identity = identity
        self._peer = peer
        self._glass_box = glass_box
        self._state = ChannelState.OPEN
        self._events: list[ChannelEvent] = []
        self._epoch = epoch.retained()
        self._epoch_started = now
        send, recv = (epoch.ap_i, epoch.ap_r) if is_initiator else (epoch.ap_r, epoch.ap_i)
        self._send = self._direction(send, epoch.epoch, now)
        self._recv = self._direction(recv, epoch.epoch, now)
        self._last_sent = now
        self._last_received = now
        self._ping_queued = False
        self._key_update_queued = False
        self._rekey: _Rekey | None = None
        self._last_rekey_start = float("-inf")

    # -- public state ---------------------------------------------------------------------------

    @property
    def state(self) -> ChannelState:
        """The current state."""
        return self._state

    @property
    def profile(self) -> Profile:
        """The session's profile."""
        return self._profile

    @property
    def peer(self) -> IdentityBundle:
        """The authenticated peer."""
        return self._peer

    @property
    def is_initiator(self) -> bool:
        """Whether we initiated the session (only the initiator starts rekeys)."""
        return self._is_initiator

    @property
    def glass_box(self) -> bool:
        """Whether both users agreed to a glass-box session."""
        return self._glass_box

    @property
    def epoch(self) -> int:
        """The PQ rekey epoch; it advances once both directions have switched."""
        return self._epoch.epoch

    @property
    def rekey_in_progress(self) -> bool:
        """Whether a PQ rekey has started and not yet switched both directions."""
        return self._rekey is not None

    # -- helpers --------------------------------------------------------------------------------

    def _direction(self, secret: Secret, epoch: int, now: float) -> _Direction:
        keys = self._provider.traffic_keys(self._profile, secret)
        self._trace_secret(keys.key)
        self._trace_secret(keys.iv)
        return _Direction(secret, keys, epoch=epoch, since=now)

    def _emit(self, event: ChannelEvent) -> None:
        self._events.append(event)

    def _take(self) -> list[ChannelEvent]:
        events, self._events = self._events, []
        return events

    def take_traces(self) -> list[Trace]:
        """Trace events produced outside a call: the traffic keys derived when it was built.

        The handshake that creates the channel reports them in its own event list.
        """
        return [event for event in self._take() if isinstance(event, Trace)]

    def _release(self, cause: ReleaseCause, *secrets: Secret) -> None:
        if secrets:
            labels = tuple(secret.label for secret in secrets)
            self._emit(Trace(SecretsReleased(labels, cause)))

    def _drop_rekey(self) -> None:
        """A rekey ends unfinished (the channel failed or closed): drop what it holds."""
        rekey, self._rekey = self._rekey, None
        if rekey is not None:
            self._release(ReleaseCause.CLOSED, *rekey.held())

    def _queue(self, message: Inner) -> None:
        self._emit(Queue(message, Priority.CONTROL))

    def _trace_secret(self, secret: Secret) -> None:
        self._emit(Trace(SecretDerived(secret.label, len(secret))))

    def _run(self, step: Callable[[], None]) -> list[ChannelEvent]:
        if self._state is not ChannelState.OPEN:
            return []
        try:
            step()
        except ProtocolError as error:
            self._fail(error.reason)
        return self._take()

    def _fail(self, reason: CloseReason) -> None:
        self._drop_rekey()
        self._state = ChannelState.CLOSING
        self._queue(Close(reason=reason))
        self._emit(Trace(SessionClosed(reason, None, by_peer=False)))
        self._emit(Closed(reason))

    # -- sending --------------------------------------------------------------------------------

    def seal_next(self, message: Inner, now: float) -> list[ChannelEvent]:
        """Seal ``message`` with the next send sequence number; the writer calls this at dequeue.

        Returns ``Send`` for the record (and trace events). Sealing a ``key_update``,
        ``rekey_switch`` or ``close`` also switches the send key or ends the channel, exactly
        after that record.

        Raises:
            RuntimeError: The channel is closed, or it is closing and ``message`` is not the
                final ``close``, or ``message`` is a ``rekey_switch`` the channel did not queue.
        """
        if self._state is ChannelState.CLOSED or (
            self._state is ChannelState.CLOSING and not isinstance(message, Close)
        ):
            msg = f"cannot seal on a {self._state.value} channel"
            raise RuntimeError(msg)
        if isinstance(message, RekeySwitch) and (self._rekey is None or self._rekey.next is None):
            msg = "rekey_switch before the new keys exist"
            raise RuntimeError(msg)
        send = self._send
        if send.seq > MAX_SEQ:
            msg = "send sequence number exhausted"
            raise RuntimeError(msg)
        plaintext = encode_inner(message)
        header = frame_header(FrameType.RECORD, len(plaintext) + TAG_LEN)
        body = self._provider.seal(self._profile, send.keys, send.seq, header, plaintext)
        frame = Frame(FrameType.RECORD, body)
        kind = inner_kind(message)
        self._emit(Trace(FrameTraced(Direction.OUT, frame, dissect(frame, self._profile))))
        self._emit(
            Trace(
                RecordTraced(Direction.OUT, send.epoch, send.generation, send.seq, len(body), kind)
            )
        )
        self._emit(Send(frame))
        send.seq += 1
        send.records += 1
        self._last_sent = now
        self._ping_queued = False
        match message:
            case KeyUpdate():
                self._key_update_queued = False
                self._send = self._updated(send, Direction.OUT, now)
            case RekeySwitch():
                self._switch_send(now)
            case Close():
                self._state = ChannelState.CLOSED
            case _:
                pass
        return self._take()

    def _updated(self, direction: _Direction, which: Direction, now: float) -> _Direction:
        secret = updated_traffic_secret(self._provider, self._profile, direction.secret)
        self._trace_secret(secret)
        new = self._direction(secret, direction.epoch, now)
        new.generation = direction.generation + 1
        self._emit(Trace(KeysSwitched(which, new.epoch, new.generation, "key_update")))
        self._release(ReleaseCause.REPLACED, *direction.secrets())
        return new

    def close(self, reason: CloseReason = CloseReason.NORMAL) -> list[ChannelEvent]:
        """Close by our choice: queue ``close { reason }`` and report ``Closed``."""
        if self._state is not ChannelState.OPEN:
            return []
        self._fail(reason)
        return self._take()

    # -- receiving ------------------------------------------------------------------------------

    def receive(self, frame: Frame, now: float) -> list[ChannelEvent]:
        """Open a record from the peer and act on it."""
        return self._run(lambda: self._receive(frame, now))

    def _receive(self, frame: Frame, now: float) -> None:
        self._emit(Trace(FrameTraced(Direction.IN, frame, dissect(frame, self._profile))))
        if frame.type is not FrameType.RECORD:
            raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "handshake frame on a session")
        if len(frame.body) > MAX_RECORD_BODY:
            raise ProtocolError(CloseReason.OVERSIZE, "record exceeds the maximum size")
        recv = self._recv
        plaintext = self._provider.unseal(
            self._profile, recv.keys, recv.seq, frame.header, frame.body
        )
        seq = recv.seq
        recv.seq += 1
        self._last_received = now
        message = decode_inner(plaintext)
        self._emit(
            Trace(
                RecordTraced(
                    Direction.IN,
                    recv.epoch,
                    recv.generation,
                    seq,
                    len(frame.body),
                    inner_kind(message),
                )
            )
        )
        self._dispatch(message, now)

    def _dispatch(self, message: Inner, now: float) -> None:
        match message:
            case KeyUpdate():
                self._recv = self._updated(self._recv, Direction.IN, now)
            case RekeyOffer():
                self._on_rekey_offer(message, now)
            case RekeyAnswer():
                self._on_rekey_answer(message)
            case RekeyFinish():
                self._on_rekey_finish(message)
            case RekeySwitch():
                self._switch_recv(now)
            case Close():
                self._state = ChannelState.CLOSED
                self._drop_rekey()
                self._emit(Trace(SessionClosed(message.reason, None, by_peer=True)))
                self._emit(Closed(message.reason, by_peer=True))
            case Ping():
                self._queue(Pong())
            case Pong():
                pass
            case _:
                self._emit(Deliver(message))

    # -- timers ---------------------------------------------------------------------------------

    def tick(self, now: float) -> list[ChannelEvent]:
        """Run the liveness and key evolution timers (DESIGN §8.4, §8.5)."""
        return self._run(lambda: self._tick(now))

    def _tick(self, now: float) -> None:
        if now - self._last_received >= IDLE_TIMEOUT:
            raise ProtocolError(CloseReason.TIMEOUT, "nothing received for too long")
        if now - self._last_sent >= PING_AFTER and not self._ping_queued:
            self._ping_queued = True
            self._queue(Ping())
        send = self._send
        due = send.records >= KEY_UPDATE_RECORDS or now - send.since >= KEY_UPDATE_SECONDS
        if due and not self._key_update_queued:
            self._key_update_queued = True
            self._queue(KeyUpdate())
        if self._is_initiator and now - self._epoch_started >= REKEY_SECONDS:
            self._start_rekey(now)

    # -- PQ rekey (DESIGN §8.4) -----------------------------------------------------------------

    def start_rekey(self, now: float) -> list[ChannelEvent]:
        """Initiator: start a PQ rekey now (the user's "Rekey now").

        Does nothing while a rekey is in progress or within a minute of the previous start.

        Raises:
            RuntimeError: We are the session's responder.
        """
        if not self._is_initiator:
            msg = "only the session initiator starts a rekey"
            raise RuntimeError(msg)
        return self._run(lambda: self._start_rekey(now))

    def _start_rekey(self, now: float) -> None:
        if self._rekey is not None or now - self._last_rekey_start < REKEY_MIN_INTERVAL:
            return
        dk, ek = self._provider.kem_keygen(self._profile, epoch=self._epoch.epoch + 1)
        self._trace_secret(dk)
        self._last_rekey_start = now
        self._rekey = _Rekey(rt=transcript_entry(Tag.REKEY_EK, ek), dk=dk)
        self._emit(Trace(RekeyStep("offer", self._epoch.epoch)))
        self._queue(RekeyOffer(ek=ek))

    def _signed_hash(self, data: bytes) -> bytes:
        """``H(data ‖ exporter_n)``: binds a rekey signature to this session and epoch."""
        return self._profile.hash.digest(data + self._epoch.exporter.reveal())

    def _on_rekey_offer(self, message: RekeyOffer, now: float) -> None:
        if self._is_initiator or self._rekey is not None:
            raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "rekey_offer not expected")
        if now - self._last_rekey_start < REKEY_OFFER_MIN_GAP:
            raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "rekey_offer too soon")
        profile = self._profile
        if len(message.ek) != profile.ek_len:
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "rekey_offer.ek has the wrong size")
        shared, ct = self._provider.kem_encapsulate(
            profile, message.ek, epoch=self._epoch.epoch + 1
        )
        for secret in (*shared.components, shared.ss):
            self._trace_secret(secret)
        self._release(ReleaseCause.USED, *shared.components)  # only ss waits for rekey_finish
        rt = transcript_entry(Tag.REKEY_EK, message.ek) + transcript_entry(Tag.REKEY_CT, ct)
        sig = self._provider.sign(profile, self._identity, Role.REKEY_ANSWER, self._signed_hash(rt))
        self._last_rekey_start = now
        self._rekey = _Rekey(rt=rt, ss=shared.ss, sig_r=sig)
        self._emit(Trace(RekeyStep("answer", self._epoch.epoch)))
        self._queue(RekeyAnswer(ct=ct, sig=sig))

    def _on_rekey_answer(self, message: RekeyAnswer) -> None:
        rekey = self._rekey
        if not self._is_initiator or rekey is None or rekey.dk is None:
            raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "rekey_answer not expected")
        profile = self._profile
        if len(message.ct) != profile.ct_len or len(message.sig) != profile.sig_len:
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "rekey_answer has the wrong size")
        dk = rekey.dk
        shared = self._provider.kem_decapsulate(
            profile, dk, message.ct, epoch=self._epoch.epoch + 1
        )
        rekey.dk = None
        self._release(ReleaseCause.USED, dk)
        for secret in (*shared.components, shared.ss):
            self._trace_secret(secret)
        self._release(ReleaseCause.USED, *shared.components)
        rt = rekey.rt + transcript_entry(Tag.REKEY_CT, message.ct)
        self._provider.verify(
            profile, self._peer, Role.REKEY_ANSWER, self._signed_hash(rt), message.sig
        )
        with_sig_r = rt + transcript_entry(Tag.REKEY_SIG_R, message.sig)
        sig_i = self._provider.sign(
            profile, self._identity, Role.REKEY_FINISH, self._signed_hash(with_sig_r)
        )
        th = profile.hash.digest(with_sig_r + transcript_entry(Tag.REKEY_SIG_I, sig_i))
        self._derive_next(rekey, shared.ss, th)
        self._emit(Trace(RekeyStep("finish", self._epoch.epoch)))
        self._queue(RekeyFinish(sig=sig_i))
        self._queue(RekeySwitch())

    def _on_rekey_finish(self, message: RekeyFinish) -> None:
        rekey = self._rekey
        if self._is_initiator or rekey is None or rekey.ss is None or rekey.next is not None:
            raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "rekey_finish not expected")
        profile = self._profile
        if len(message.sig) != profile.sig_len:
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "rekey_finish.sig has the wrong size")
        with_sig_r = rekey.rt + transcript_entry(Tag.REKEY_SIG_R, rekey.sig_r)
        self._provider.verify(
            profile, self._peer, Role.REKEY_FINISH, self._signed_hash(with_sig_r), message.sig
        )
        th = profile.hash.digest(with_sig_r + transcript_entry(Tag.REKEY_SIG_I, message.sig))
        self._derive_next(rekey, rekey.ss, th)
        self._queue(RekeySwitch())

    def _derive_next(self, rekey: _Rekey, ss: Secret, th: bytes) -> None:
        new = next_epoch(self._provider, self._profile, self._epoch, ss, th)
        rekey.next = new.retained()
        rekey.send, rekey.recv = (
            (new.ap_i, new.ap_r) if self._is_initiator else (new.ap_r, new.ap_i)
        )
        rekey.ss = None
        for secret in new.all():
            self._trace_secret(secret)
        self._release(ReleaseCause.USED, ss, new.cs)  # cs_{n+1} is a root, not state

    def _switch_send(self, now: float) -> None:
        rekey = self._rekey
        assert rekey is not None and rekey.next is not None  # noqa: S101, PT018  # queued after derivation
        new = rekey.next
        assert rekey.send is not None  # noqa: S101  # consumed once at the switch
        old = self._send
        self._send = self._direction(rekey.send, new.epoch, now)
        rekey.send = None
        self._release(ReleaseCause.REPLACED, *old.secrets())
        rekey.send_switched = True
        self._emit(Trace(KeysSwitched(Direction.OUT, new.epoch, 0, "rekey")))
        self._finish_rekey_if_done(now)

    def _switch_recv(self, now: float) -> None:
        rekey = self._rekey
        if rekey is None or rekey.next is None or rekey.recv_switched:
            raise ProtocolError(CloseReason.UNEXPECTED_MESSAGE, "rekey_switch not expected")
        new = rekey.next
        assert rekey.recv is not None  # noqa: S101  # consumed once at the switch
        old = self._recv
        self._recv = self._direction(rekey.recv, new.epoch, now)
        rekey.recv = None
        self._release(ReleaseCause.REPLACED, *old.secrets())
        rekey.recv_switched = True
        self._emit(Trace(KeysSwitched(Direction.IN, new.epoch, 0, "rekey")))
        self._finish_rekey_if_done(now)

    def _finish_rekey_if_done(self, now: float) -> None:
        rekey = self._rekey
        assert rekey is not None and rekey.next is not None  # noqa: S101, PT018
        if rekey.send_switched and rekey.recv_switched:
            # Erase the old rekey salt and exporter: only the new epoch remains.
            old = self._epoch
            self._epoch = rekey.next
            self._release(ReleaseCause.EPOCH_DONE, old.rekey_salt, old.exporter)
            self._epoch_started = now
            self._rekey = None
            self._emit(Trace(RekeyStep("done", self._epoch.epoch)))


def is_control(message: Inner) -> bool:
    """Whether ``message`` belongs in the writer's control priority (DESIGN §8.3)."""
    return isinstance(message, _CONTROL)
