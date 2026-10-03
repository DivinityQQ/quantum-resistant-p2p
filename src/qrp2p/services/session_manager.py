"""Every session of this node: limits, admission prechecks, simultaneous open and replacement.

The manager creates the core machines, runs one :class:`~qrp2p.services.session.Session` per
connection and enforces what spans sessions:

- **Resource limits** (DESIGN §6.4): half-open handshakes (32, 4 per source), the Hello rate
  (20/s, burst 40) and live sessions (64). Refusals before authentication are silent.
- **Reflection** (DESIGN §7.5): responders see our outstanding ``ek_I`` values.
- **Simultaneous open** (DESIGN §7.8): when our handshake to a peer and the peer's handshake to
  us overlap, the one initiated by the lower ``peer_id`` survives; the responder rejects the other
  with ``busy`` at admission.
- **Replacement** (DESIGN §7.8): one live session per peer; a newly established one closes the
  previous one with ``replaced``.
- **Timers**: every session is ticked twice a second (deadlines, pings, KeyUpdate, rekey).
- **Exposure** (DESIGN §11.3): every session that may become glass-box gets a revealing provider
  behind an :class:`~qrp2p.services.exposure.ExposureGate`, opened only by glass-box admission.
- **Trace descriptors**: each session's role, address, profile, peer and end go to the trace bus.

Whether to admit a peer, and everything about contacts and messages, is the owner's business
(:class:`ManagerHooks`, implemented by the node).
"""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Container, Iterator
from typing import Protocol, override

from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.profiles import REAL_PROFILES, Profile
from qrp2p.core.crypto.provider import CryptoProvider, RevealingProvider
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.handshake import (
    AdmissionRequired,
    Initiator,
    KeyMismatch,
    ProfileRejected,
    Responder,
)
from qrp2p.core.trace import TraceEvent
from qrp2p.core.wire import Inner
from qrp2p.services.exposure import Exposure, ExposureGate
from qrp2p.services.limits import (
    FLUSH_TIMEOUT,
    HELLO_BURST,
    HELLO_RATE,
    MAX_LIVE_SESSIONS,
    TICK_INTERVAL,
    SlotPool,
    TokenBucket,
)
from qrp2p.services.session import Clock, Phase, Session, SessionEnd, SessionRole
from qrp2p.services.trace_bus import SessionInfo, TraceBus
from qrp2p.services.transport import FrameStream, open_stream

_log = logging.getLogger(__name__)

type ProviderFactory = Callable[[], CryptoProvider]
"""Creates the crypto provider that does one session's work (a plain one in real nodes)."""


class ManagerHooks(Protocol):
    """What the manager reports to the node. Every hook runs on the event loop."""

    def admission(self, session: Session, request: AdmissionRequired, /) -> None:
        """Decide (DESIGN §7.6) with ``session.accept`` or ``session.reject``, now or later."""
        ...

    def key_mismatch(self, session: Session, event: KeyMismatch, /) -> None:
        """Initiator: the responder is not the pinned contact."""
        ...

    def profile_rejected(self, session: Session, event: ProfileRejected, /) -> None:
        """Initiator: the responder does not serve the profile (an unauthenticated hint)."""
        ...

    def established(self, session: Session, replaced: Session | None, /) -> None:
        """A session opened; ``replaced`` is the peer's previous session, now closing."""
        ...

    def message(self, session: Session, message: Inner, /) -> Awaitable[None]:
        """An application message from an open session; the next frame waits for it."""
        ...

    def sent(self, session: Session, message: Inner, /) -> None:
        """A message was sealed and handed to TCP."""
        ...

    def ended(self, session: Session, end: SessionEnd, /, *, superseded: bool) -> None:
        """A session or handshake ended.

        ``superseded``: the session lost a simultaneous open and another session with the same
        peer exists or survives; this is not a failure to show.
        """
        ...


class _OwnEphemeralKeys(Container[bytes]):
    """A live view of our outstanding initiator ``ek_I`` values (DESIGN §7.5, ``reflection``)."""

    __slots__ = ("_sessions",)

    def __init__(self, sessions: dict[int, Session]) -> None:
        self._sessions = sessions

    @override
    def __contains__(self, key: object, /) -> bool:
        return any(s.ephemeral_key == key for s in self._sessions.values())


class SessionManager:
    """Creates, runs and supervises sessions.

    Args:
        identity: Our identity.
        hooks: The owner (the node).
        provider_factory: Creates the provider that does each session's work; real nodes build a
            :class:`~qrp2p.core.crypto.provider.PlainProvider` over the real profiles. Sessions
            that may become glass-box wrap it in a revealing provider behind an exposure gate.
        clock: The monotonic clock.
        trace: Where trace events go.
        profiles: The profiles this node serves as a responder.
    """

    def __init__(
        self,
        *,
        identity: IdentityKeyPair,
        hooks: ManagerHooks,
        provider_factory: ProviderFactory,
        clock: Clock,
        trace: TraceBus,
        profiles: tuple[Profile, ...] = REAL_PROFILES,
    ) -> None:
        self._identity = identity
        self._hooks = hooks
        self._provider_factory = provider_factory
        self._clock = clock
        self._trace = trace
        self._profiles = profiles
        self._sessions: dict[int, Session] = {}
        self._live: dict[bytes, Session] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._slots = SlotPool()
        self._slot_of: dict[int, str] = {}
        self._hellos = TokenBucket(HELLO_RATE, HELLO_BURST)
        self._own_eks = _OwnEphemeralKeys(self._sessions)
        self._ticker: asyncio.Task[None] | None = None
        self._accepting = False
        self._superseded: set[int] = set()
        """Sessions closed because another session with the same peer won a simultaneous open."""
        self._gates: dict[int, ExposureGate] = {}

    # -- lifecycle ------------------------------------------------------------------------------

    def start(self) -> None:
        """Start the timers and accept incoming connections."""
        self._accepting = True
        if self._ticker is None:
            self._ticker = asyncio.create_task(self._tick_loop(), name="qrp2p-ticker")

    async def stop(self, reason: CloseReason) -> None:
        """Close every session with ``reason``, wait for them, stop the timers."""
        self._accepting = False
        for session in list(self._sessions.values()):
            session.close(reason)
        tasks = set(self._tasks)
        if tasks:
            _, pending = await asyncio.wait(tasks, timeout=FLUSH_TIMEOUT + 1.0)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.wait(pending)
        if self._ticker is not None:
            self._ticker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._ticker
            self._ticker = None

    async def _tick_loop(self) -> None:
        while True:
            await asyncio.sleep(TICK_INTERVAL)
            self.tick()

    def tick(self) -> None:
        """Run every session's timers now."""
        now = self._clock()
        for session in list(self._sessions.values()):
            session.tick(now)

    # -- queries --------------------------------------------------------------------------------

    def sessions(self) -> Iterator[Session]:
        """Every session, in any phase."""
        return iter(tuple(self._sessions.values()))

    def live(self, peer_id: bytes) -> Session | None:
        """The open session with a peer, if any."""
        return self._live.get(peer_id)

    @property
    def half_open(self) -> int:
        """Incoming handshakes holding a slot."""
        return self._slots.in_use

    # -- creating sessions ----------------------------------------------------------------------

    async def handle_incoming(self, stream: FrameStream) -> None:
        """Run a responder session on an accepted connection (the listener's callback)."""
        if not self._accepting or not self._slots.acquire(stream.source):
            _log.info("refused a connection: %s", CloseReason.RATE_LIMITED.label)
            stream.abort()
            return
        gate = ExposureGate(self._clock)  # whether the Hello asks is not known yet
        responder = Responder(
            provider=RevealingProvider(self._provider_factory(), gate),
            profiles=self._profiles,
            identity=self._identity,
            own_ephemeral_keys=self._own_eks,
            now=self._clock(),
        )
        session = Session(machine=responder, stream=stream, hooks=self, clock=self._clock)
        self._gates[session.id] = gate
        self._slot_of[session.id] = stream.source
        self._trace.open_session(
            SessionInfo(session.id, initiator=False, address=stream.source, started=self._clock())
        )
        await self._run(session)

    async def connect(
        self,
        host: str,
        port: int,
        *,
        profile: Profile,
        pinned: IdentityBundle | None,
        glass_box: bool,
        on_created: Callable[[Session], None] | None = None,
    ) -> Session:
        """Open a connection and send Hello. The outcome arrives through the hooks.

        ``on_created`` runs before the Hello is queued, so the caller can map the session before
        any hook fires for it.

        Raises:
            ConnectFailed: No TCP connection could be opened.
        """
        stream = await open_stream(host, port)
        provider = self._provider_factory()
        gate = None
        if glass_box:  # only a session that asks can become glass-box
            gate = ExposureGate(self._clock)
            provider = RevealingProvider(provider, gate)
        initiator = Initiator(
            provider=provider,
            profile=profile,
            identity=self._identity,
            pinned=pinned,
            glass_box_request=glass_box,
            now=self._clock(),
        )
        session = Session(
            machine=initiator, stream=stream, hooks=self, clock=self._clock, expected_peer=pinned
        )
        if gate is not None:
            self._gates[session.id] = gate
        address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        self._trace.open_session(
            SessionInfo(
                session.id,
                initiator=True,
                address=address,
                started=self._clock(),
                profile=profile.name,
                glass_box_requested=glass_box,
            )
        )
        self._sessions[session.id] = session
        if on_created is not None:
            on_created(session)
        session.start()
        task = asyncio.create_task(self._run(session), name=f"qrp2p-session-{session.id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return session

    async def _run(self, session: Session) -> None:
        self._sessions[session.id] = session
        current = asyncio.current_task()
        if current is not None:
            self._tasks.add(current)
        try:
            await session.run()
        finally:
            self._sessions.pop(session.id, None)
            self._release_slot(session)
            self._close_gate(session)
            self._trace.session_ended(session.id)
            if current is not None:
                self._tasks.discard(current)

    def _release_slot(self, session: Session) -> None:
        source = self._slot_of.pop(session.id, None)
        if source is not None:
            self._slots.release(source)

    def _close_gate(self, session: Session) -> None:
        gate = self._gates.pop(session.id, None)
        if gate is not None:
            gate.close()

    def _open_gate(self, session: Session) -> None:
        """Glass-box admission: the session's revealed values go to its trace ring."""
        gate = self._gates.pop(session.id, None)
        if gate is None:
            return

        def publish(time: float, exposure: Exposure) -> None:
            self._trace.publish(session.id, time, exposure)

        gate.open(publish)

    # -- simultaneous open ----------------------------------------------------------------------

    def _overlapping_outgoing(self, incoming: Session, peer_id: bytes) -> bool:
        """Whether a handshake we initiated to ``peer_id`` overlapped ``incoming`` (DESIGN §7.8).

        It overlapped if it is still in progress, or if it was established after the incoming
        Hello arrived.
        """
        for session in self._sessions.values():
            if session is incoming or session.role is not SessionRole.INITIATOR:
                continue
            target = session.peer or session.expected_peer
            if target is None or target.peer_id != peer_id:
                continue
            if session.phase is Phase.HANDSHAKE:
                return True
            established = session.established_at
            if session.is_open and established is not None and established >= incoming.started_at:
                return True
        return False

    def _other_session_with(self, session: Session, peer_id: bytes) -> bool:
        for other in self._sessions.values():
            if other is session or other.phase is Phase.ENDED:
                continue
            known = other.peer or other.expected_peer
            if known is not None and known.peer_id == peer_id:
                return True
        return False

    # -- SessionHooks ---------------------------------------------------------------------------

    def hello_allowed(self, session: Session) -> bool:  # noqa: ARG002  # one global bucket
        """See :class:`~qrp2p.services.session.SessionHooks`."""
        allowed = self._hellos.take(self._clock())
        if not allowed:
            _log.info("dropped a Hello: %s", CloseReason.RATE_LIMITED.label)
        return allowed

    def trace(self, session: Session, event: TraceEvent) -> None:
        """See :class:`~qrp2p.services.session.SessionHooks`."""
        peer = session.peer
        if peer is not None and session.role is SessionRole.INITIATOR:
            # Reply authenticated the responder, and a pinned one also matched its pin: a
            # mismatch raises before the machine knows its peer (DESIGN §7.5).
            matched = session.expected_peer is not None
            self._trace.describe(
                session.id,
                peer_id=peer.peer_id,
                peer_short_id=peer.short_id,
                pin_result="matched" if matched else "",
            )
        self._trace.publish(session.id, self._clock(), event)

    def admission(self, session: Session, request: AdmissionRequired) -> None:
        """Busy checks first (simultaneous open, live-session cap), then the node's policy."""
        peer_id = request.peer.peer_id
        self._trace.describe(
            session.id,
            peer_id=peer_id,
            peer_short_id=request.peer.short_id,
            profile=request.profile.name,
            glass_box_requested=request.gb_request,
        )
        if not request.gb_request:
            self._close_gate(session)  # admission cannot grant what the Hello did not ask
        if self._overlapping_outgoing(session, peer_id) and self._identity.bundle.peer_id < peer_id:
            _log.info("simultaneous open with %s: ours survives", request.peer.short_id)
            self._superseded.add(session.id)
            session.reject(AdmitReason.BUSY)
            return
        if not self._capacity_available(peer_id):
            _log.warning("live-session limit reached; rejecting %s", request.peer.short_id)
            session.reject(AdmitReason.BUSY)
            return
        self._hooks.admission(session, request)

    def _capacity_available(self, peer_id: bytes) -> bool:
        return peer_id in self._live or len(self._live) < MAX_LIVE_SESSIONS

    def admission_allowed(self, session: Session) -> bool:
        """Recheck deferred admission at acceptance; replacements consume no new peer slot."""
        assert session.peer is not None  # noqa: S101  # authenticated at AdmissionRequired
        return self._capacity_available(session.peer.peer_id)

    def key_mismatch(self, session: Session, event: KeyMismatch) -> None:
        """See :class:`~qrp2p.services.session.SessionHooks`."""
        # It proved this identity, even if not the pinned one.
        self._trace.describe(
            session.id,
            peer_id=event.actual.peer_id,
            peer_short_id=event.actual.short_id,
            pin_result="mismatched",
        )
        self._hooks.key_mismatch(session, event)

    def profile_rejected(self, session: Session, event: ProfileRejected) -> None:
        """See :class:`~qrp2p.services.session.SessionHooks`."""
        self._hooks.profile_rejected(session, event)

    def _initiator_id(self, session: Session) -> bytes:
        """The ``peer_id`` of the side that opened the session."""
        if session.role is SessionRole.INITIATOR:
            return self._identity.bundle.peer_id
        assert session.peer is not None  # noqa: S101  # open sessions know their peer
        return session.peer.peer_id

    def established(self, session: Session) -> None:
        """Release the half-open slot; keep one live session per peer (DESIGN §7.8).

        A newer session replaces an older one, unless their handshakes overlapped: then this was
        a simultaneous open that admission could not see (the initiator had no pin), and the
        session opened by the lower ``peer_id`` survives, as on the other side.
        """
        self._release_slot(session)
        peer = session.peer
        assert peer is not None  # noqa: S101  # an open session has an authenticated peer
        if session.glass_box:
            self._open_gate(session)
        else:
            self._close_gate(session)
        self._trace.describe(
            session.id,
            peer_id=peer.peer_id,
            peer_short_id=peer.short_id,
            profile=session.profile.name if session.profile else "",
            glass_box=session.glass_box,
            established=True,
        )
        self._trace.handshake_done(session.id)
        if not self._capacity_available(peer.peer_id):
            # An outgoing handshake can finish after another session consumed the last slot.
            # Do not register or report it as connected; send an authenticated close instead.
            session.close(CloseReason.RATE_LIMITED)
            return
        previous = self._live.get(peer.peer_id)
        if previous is not None and previous is not session:
            overlapped = (
                previous.established_at is not None
                and session.started_at <= previous.established_at
            )
            if overlapped and self._initiator_id(previous) < self._initiator_id(session):
                _log.info("simultaneous open with %s: the earlier session survives", peer.short_id)
                self._superseded.add(session.id)
                session.close(CloseReason.REPLACED)
                return
            if overlapped:
                self._superseded.add(previous.id)
        self._live[peer.peer_id] = session
        if previous is not None and previous is not session:
            previous.close(CloseReason.REPLACED)
        _log.info(
            "session %d open with %s (%s, %s)",
            session.id,
            peer.short_id,
            session.role.value,
            session.profile.name if session.profile else "?",
        )
        self._hooks.established(session, previous)

    async def message(self, session: Session, message: Inner) -> None:
        """See :class:`~qrp2p.services.session.SessionHooks`."""
        await self._hooks.message(session, message)

    def sent(self, session: Session, message: Inner) -> None:
        """See :class:`~qrp2p.services.session.SessionHooks`."""
        self._hooks.sent(session, message)

    def ended(self, session: Session, end: SessionEnd) -> None:
        """Forget the session; tell the node whether it merely lost a simultaneous open."""
        self._release_slot(session)
        self._close_gate(session)
        self._trace.describe(
            session.id,
            end_reason=end.reason.label if end.reason is not None else "",
            admit_reason=end.admit_reason.label if end.admit_reason is not None else "",
            by_peer=end.by_peer,
        )
        peer = session.peer or session.expected_peer
        if session.peer is not None and self._live.get(session.peer.peer_id) is session:
            del self._live[session.peer.peer_id]
        superseded = session.id in self._superseded or (
            session.role is SessionRole.INITIATOR
            and end.admit_reason is AdmitReason.BUSY
            and peer is not None
            and self._other_session_with(session, peer.peer_id)
        )
        self._superseded.discard(session.id)
        _log.info(
            "session %d ended: %s%s",
            session.id,
            "connection lost" if end.reason is None else end.reason.label,
            f" ({end.admit_reason.label})" if end.admit_reason is not None else "",
        )
        self._hooks.ended(session, end, superseded=superseded)
