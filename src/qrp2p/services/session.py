"""One connection's session: it drives the core handshake, then the channel (DESIGN §7, §8.3, §8.5).

A :class:`Session` owns a :class:`~qrp2p.services.transport.FrameStream` and runs two tasks:

- The **reader** reads one frame at a time and feeds it to the handshake machine, or to the
  channel once the session is established.
- The **writer** is the connection's only writer (DESIGN §8.3). It drains a priority queue:
  handshake frames first, then control > chat > file data. Records are sealed **at dequeue** with
  :meth:`~qrp2p.core.record.Channel.seal_next`, so sequence numbers follow the order on the wire
  and frames never interleave.

Everything the core asks for arrives as events; the session acts on the transport-level ones
itself and hands the rest to :class:`SessionHooks` (the session manager). A close flushes what
the core queued (a ``close`` record, a reject, ``ProfileUnsupported``) and then drops the
connection; failures before authentication close silently.
"""

import asyncio
import contextlib
import itertools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from qrp2p.core.crypto.identity import IdentityBundle
from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.errors import AdmitReason, CloseReason, ProtocolError
from qrp2p.core.events import Closed, Deliver, Priority, Queue, Send, Trace
from qrp2p.core.handshake import (
    AdmissionRequired,
    Established,
    HandshakeEvent,
    Initiator,
    KeyMismatch,
    ProfileRejected,
    Responder,
    State,
)
from qrp2p.core.record import Channel, ChannelEvent, ChannelState
from qrp2p.core.trace import TraceEvent
from qrp2p.core.wire import Close, Frame, Inner
from qrp2p.services.limits import FILE_QUEUE_SLOTS, FLUSH_TIMEOUT, MAX_WRITE_BACKLOG, WRITE_TIMEOUT
from qrp2p.services.transport import ConnectionLost, FrameStream

type Clock = Callable[[], float]
"""A monotonic clock in seconds."""

_FRAME_PRIORITY: Final = -1
"""Handshake frames go out before anything else, in the order the core produced them."""
_STOP_PRIORITY: Final = Priority.CONTROL
"""The writer's stop marker sorts after the final ``close`` record and before chat and files."""

_log = logging.getLogger(__name__)
_ids = itertools.count(1)


class SessionRole(StrEnum):
    """Which end of the TCP connection we are."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


class Phase(StrEnum):
    """Where a session is."""

    HANDSHAKE = "handshake"
    OPEN = "open"
    ENDED = "ended"


@dataclass(frozen=True, slots=True)
class SessionEnd:
    """How a session ended.

    ``reason`` is ``None`` when the connection dropped without a named reason (the peer vanished,
    or the network failed); :attr:`lost` says so.
    """

    reason: CloseReason | None
    admit_reason: AdmitReason | None = None
    by_peer: bool = False

    @property
    def lost(self) -> bool:
        """Whether the connection dropped without a ``close``."""
        return self.reason is None


class SessionNotOpenError(Exception):
    """The session is not open, so nothing can be sent on it."""


class SessionHooks(Protocol):
    """What a session reports to its owner. Every hook runs on the event loop."""

    def hello_allowed(self, session: Session) -> bool:
        """Responder: whether the first frame (a Hello) may be processed now (rate limit)."""
        ...

    def trace(self, session: Session, event: TraceEvent) -> None:
        """A trace event from the core."""
        ...

    def admission(self, session: Session, request: AdmissionRequired) -> None:
        """Responder: decide with :meth:`Session.accept` or :meth:`Session.reject`, now or later."""
        ...

    def admission_allowed(self, session: Session) -> bool:
        """Recheck capacity immediately before a deferred admission is accepted."""
        ...

    def key_mismatch(self, session: Session, event: KeyMismatch) -> None:
        """Initiator: the responder proved a bundle other than the pinned one."""
        ...

    def profile_rejected(self, session: Session, event: ProfileRejected) -> None:
        """Initiator: the responder does not serve the offered profile (a hint)."""
        ...

    def established(self, session: Session) -> None:
        """The session is open."""
        ...

    async def message(self, session: Session, message: Inner) -> None:
        """An application message from the peer. The next frame is read after this returns."""
        ...

    def sent(self, session: Session, message: Inner) -> None:
        """``message`` was sealed and handed to TCP."""
        ...

    def ended(self, session: Session, end: SessionEnd) -> None:
        """The session ended. Called once."""
        ...


@dataclass(frozen=True, slots=True)
class _Queued:
    message: Inner
    priority: Priority


type _Item = Frame | _Queued | None
"""A handshake frame, a message to seal at dequeue, or ``None``: stop."""


class Session:
    """A handshake and, once it succeeds, the session over one TCP connection.

    Args:
        machine: A fresh :class:`~qrp2p.core.handshake.Initiator` (call :meth:`start`) or
            :class:`~qrp2p.core.handshake.Responder`.
        stream: The connection.
        hooks: The owner.
        clock: The monotonic clock the core's ``now`` comes from.
        expected_peer: Initiator: the pinned bundle, when connecting to a contact.
    """

    def __init__(
        self,
        *,
        machine: Initiator | Responder,
        stream: FrameStream,
        hooks: SessionHooks,
        clock: Clock,
        expected_peer: IdentityBundle | None = None,
    ) -> None:
        self.id = next(_ids)
        self.role = (
            SessionRole.INITIATOR if isinstance(machine, Initiator) else SessionRole.RESPONDER
        )
        self.expected_peer = expected_peer
        self._machine: Initiator | Responder | None = machine
        self._stream = stream
        self._hooks = hooks
        self._clock = clock
        self._channel: Channel | None = None
        self._peer: IdentityBundle | None = None
        self._profile: Profile | None = machine.profile
        self._glass_box = False
        self._phase = Phase.HANDSHAKE
        self._end: SessionEnd | None = None
        self.started_at = clock()
        self.established_at: float | None = None
        self._queue: asyncio.PriorityQueue[tuple[int, int, _Item]] = asyncio.PriorityQueue()
        self._order = itertools.count()
        self._first_frame = True
        self._file_queued = 0
        self._file_room = asyncio.Event()
        self._file_room.set()
        self._flush_deadline: asyncio.TimerHandle | None = None
        self._stopped = False

    # -- state ----------------------------------------------------------------------------------

    @property
    def phase(self) -> Phase:
        """Handshake, open or ended."""
        return self._phase

    @property
    def is_open(self) -> bool:
        """Whether messages can be sent."""
        return self._phase is Phase.OPEN

    @property
    def end(self) -> SessionEnd | None:
        """How the session ended, once it has."""
        return self._end

    @property
    def source(self) -> str:
        """The peer's network address."""
        return self._stream.source

    @property
    def peer(self) -> IdentityBundle | None:
        """The authenticated peer: after Reply (initiator), at admission (responder), when open."""
        machine = self._machine
        if self._peer is None and isinstance(machine, Initiator):
            return machine.peer
        return self._peer

    @property
    def profile(self) -> Profile | None:
        """The session's profile, once known."""
        return self._profile

    @property
    def glass_box(self) -> bool:
        """Whether both users agreed to a glass-box session."""
        return self._glass_box

    @property
    def channel(self) -> Channel | None:
        """The record layer, once open."""
        return self._channel

    @property
    def ephemeral_key(self) -> bytes | None:
        """Initiator: our outstanding ``ek_I``, for the responder's reflection check."""
        machine = self._machine
        return machine.ephemeral_key if isinstance(machine, Initiator) else None

    @property
    def awaiting_admission(self) -> bool:
        """Responder: the initiator is authenticated and waits for our decision."""
        machine = self._machine
        return (
            isinstance(machine, Responder)
            and self._phase is Phase.HANDSHAKE
            and machine.state is State.WAIT_ADMISSION
        )

    def __repr__(self) -> str:
        return f"Session({self.id}, {self.role.value}, {self._phase.value})"

    # -- driving --------------------------------------------------------------------------------

    def start(self) -> None:
        """Initiator: send Hello. Call once, before :meth:`run`."""
        machine = self._machine
        if not isinstance(machine, Initiator):
            msg = "only an initiator starts"
            raise TypeError(msg)
        self._dispatch(machine.start())

    async def run(self) -> SessionEnd:
        """Read and write until the session ends; return how it ended. Never raises."""
        writer = asyncio.create_task(self._write_loop(), name=f"qrp2p-writer-{self.id}")
        try:
            await self._read_loop()
        except asyncio.CancelledError:
            self._finish(SessionEnd(CloseReason.INTERNAL))
            self._stream.abort()
            writer.cancel()
            raise
        except Exception:  # noqa: BLE001  # a bug in a hook must not leave the connection half open
            _log.exception("session %d: internal error", self.id)
            self.close(CloseReason.INTERNAL)
        finally:
            with contextlib.suppress(asyncio.CancelledError):
                await writer
        assert self._end is not None  # noqa: S101  # both loops end only after _finish
        return self._end

    def tick(self, now: float) -> None:
        """Run the core's timers: handshake deadlines, pings, KeyUpdate, rekey, idle timeout."""
        if self._phase is Phase.ENDED:
            return
        if self._channel is not None:
            self._dispatch(self._channel.tick(now))
        elif self._machine is not None:
            self._dispatch(self._machine.tick(now))

    def accept(self, *, glass_box: bool) -> None:
        """Responder: admit the initiator (DESIGN §7.6).

        Raises:
            RuntimeError: No admission decision is pending.
        """
        responder = self._responder()
        if not self._hooks.admission_allowed(self):
            self.reject(AdmitReason.BUSY)
            return
        # No await between the final capacity check and Established: the event loop serializes
        # this check and the manager's registration, including decisions deferred by the UI.
        self._dispatch(responder.accept(glass_box=glass_box, now=self._clock()))

    def reject(self, reason: AdmitReason) -> None:
        """Responder: reject the initiator with a named reason.

        Raises:
            RuntimeError: No admission decision is pending.
        """
        self._dispatch(self._responder().reject(reason, self._clock()))

    def _responder(self) -> Responder:
        if not self.awaiting_admission:
            msg = "no admission decision is pending"
            raise RuntimeError(msg)
        assert isinstance(self._machine, Responder)  # noqa: S101  # checked above
        return self._machine

    def send(self, message: Inner, priority: Priority) -> None:
        """Queue an application message; the writer seals it at dequeue.

        Raises:
            SessionNotOpenError: The session is not open.
        """
        if self._phase is not Phase.OPEN:
            raise SessionNotOpenError
        self._enqueue(priority, _Queued(message, priority))
        self._check_backlog()

    async def send_bulk(self, message: Inner) -> None:
        """Queue file data at file priority, waiting while the transfer has enough queued.

        Raises:
            SessionNotOpenError: The session is not open, or it ended while waiting.
        """
        while self._file_queued >= FILE_QUEUE_SLOTS and self._phase is Phase.OPEN:
            self._file_room.clear()
            await self._file_room.wait()
        if self._phase is not Phase.OPEN:
            raise SessionNotOpenError
        self._file_queued += 1
        self._enqueue(Priority.FILE, _Queued(message, Priority.FILE))

    def start_rekey(self) -> None:
        """Initiator: start a PQ rekey now (the user's "Rekey now").

        Raises:
            SessionNotOpenError: The session is not open.
            RuntimeError: We are the session's responder.
        """
        if self._channel is None or self._phase is not Phase.OPEN:
            raise SessionNotOpenError
        self._dispatch(self._channel.start_rekey(self._clock()))

    def close(self, reason: CloseReason = CloseReason.NORMAL) -> None:
        """End the session by our choice.

        An open session sends ``close { reason }`` first; a handshake is dropped silently.
        """
        if self._phase is Phase.ENDED:
            return
        if self._channel is not None:
            self._dispatch(self._channel.close(reason))
            return
        self._finish(SessionEnd(reason))
        self._stop(flush=False)

    # -- core events ----------------------------------------------------------------------------

    def _dispatch(self, events: list[HandshakeEvent] | list[ChannelEvent]) -> list[Inner]:
        """Act on the core's events; return the application messages to deliver."""
        delivered: list[Inner] = []
        for event in events:
            match event:
                case Deliver(message=message):
                    delivered.append(message)
                case Send(frame=frame):
                    self._enqueue(_FRAME_PRIORITY, frame)
                case Queue(message=message, priority=priority):
                    self._enqueue(priority, _Queued(message, priority))
                case Trace(event=trace):
                    self._hooks.trace(self, trace)
                case Closed():
                    self._finish(SessionEnd(event.reason, event.admit_reason, event.by_peer))
                    self._stop(flush=True)
                case _:
                    self._on_handshake_event(event)
        self._check_backlog()
        return delivered

    def _on_handshake_event(
        self, event: AdmissionRequired | KeyMismatch | ProfileRejected | Established
    ) -> None:
        match event:
            case AdmissionRequired():
                self._peer = event.peer
                self._profile = event.profile
                self._hooks.admission(self, event)
            case KeyMismatch():
                self._hooks.key_mismatch(self, event)
            case ProfileRejected():
                self._hooks.profile_rejected(self, event)
            case Established():
                self._open(event)

    def _open(self, established: Established) -> None:
        self._channel = established.channel
        self._peer = established.peer
        self._profile = established.profile
        self._glass_box = established.glass_box
        self._machine = None  # the handshake machine has erased its secrets; drop it too
        self._phase = Phase.OPEN
        self.established_at = self._clock()
        self._hooks.established(self)

    def _finish(self, end: SessionEnd) -> None:
        if self._end is not None:
            return
        self._end = end
        self._phase = Phase.ENDED
        self._file_room.set()
        self._hooks.ended(self, end)

    def _check_backlog(self) -> None:
        if self._phase is Phase.OPEN and self._queue.qsize() > MAX_WRITE_BACKLOG:
            _log.warning("session %d: peer does not read; closing", self.id)
            self.close(CloseReason.RATE_LIMITED)

    # -- reading --------------------------------------------------------------------------------

    async def _read_loop(self) -> None:
        while self._phase is not Phase.ENDED:
            try:
                frame = await self._stream.read_frame()
            except ProtocolError as error:
                self._input_failed(error.reason)
                return
            except ConnectionLost:
                self._lost()
                return
            if frame is None:
                self._lost()
                return
            if self._end is not None:  # ended while we waited for the frame
                return
            if self._first_frame and self.role is SessionRole.RESPONDER:
                self._first_frame = False
                if not self._hooks.hello_allowed(self):
                    self._finish(SessionEnd(CloseReason.RATE_LIMITED))
                    self._stop(flush=False)
                    return
            await self._on_frame(frame)

    async def _on_frame(self, frame: Frame) -> None:
        now = self._clock()
        if self._channel is not None:
            delivered = self._dispatch(self._channel.receive(frame, now))
        else:
            assert self._machine is not None  # noqa: S101  # one of the two exists until the end
            delivered = self._dispatch(self._machine.receive(frame, now))
        for message in delivered:
            await self._hooks.message(self, message)

    def _input_failed(self, reason: CloseReason) -> None:
        """The frame header was invalid: oversize or unknown type."""
        if self._channel is not None and self._phase is Phase.OPEN:
            self.close(reason)  # the channel still works in the sending direction
            return
        self._finish(SessionEnd(reason))  # before authentication: silently
        self._stop(flush=False)

    def _lost(self) -> None:
        self._finish(SessionEnd(None))
        self._stop(flush=False)

    # -- writing --------------------------------------------------------------------------------

    def _enqueue(self, priority: int, item: _Item) -> None:
        if not self._stopped:
            self._queue.put_nowait((priority, next(self._order), item))

    def _stop(self, *, flush: bool) -> None:
        """Stop the writer: after the final frames (``flush``) or at once."""
        if self._stopped:
            return
        priority = _STOP_PRIORITY if flush else _FRAME_PRIORITY - 1
        self._queue.put_nowait((priority, next(self._order), None))
        self._stopped = True
        loop = asyncio.get_running_loop()
        self._flush_deadline = loop.call_later(FLUSH_TIMEOUT, self._stream.abort)

    async def _write_loop(self) -> None:
        try:
            while True:
                _, _, item = await self._queue.get()
                if item is None:
                    break
                if isinstance(item, Frame):
                    self._stream.write(item)
                else:
                    self._file_done(item)
                    if not self._seal(item):
                        continue
                await self._drain()
                if isinstance(item, _Queued):
                    self._hooks.sent(self, item.message)
        except ConnectionLost:
            self._lost()
        except TimeoutError:
            _log.info("session %d: peer stopped reading; giving up", self.id)
            self._finish(SessionEnd(CloseReason.TIMEOUT))
        finally:
            await self._shutdown()

    def _file_done(self, item: _Queued) -> None:
        if item.priority is Priority.FILE:
            self._file_queued -= 1
            self._file_room.set()

    def _seal(self, item: _Queued) -> bool:
        """Seal and write one message; ``False`` if the channel no longer sends it."""
        channel = self._channel
        if channel is None or channel.state is ChannelState.CLOSED:
            return False
        if channel.state is ChannelState.CLOSING and not isinstance(item.message, Close):
            return False  # only the final close record goes out once closing
        for event in channel.seal_next(item.message, self._clock()):
            match event:
                case Send(frame=frame):
                    self._stream.write(frame)
                case Trace(event=trace):
                    self._hooks.trace(self, trace)
                case _:  # seal_next reports nothing else
                    pass
        return True

    async def _drain(self) -> None:
        limit = WRITE_TIMEOUT if self._phase is not Phase.ENDED else FLUSH_TIMEOUT
        async with asyncio.timeout(limit):
            await self._stream.drain()

    async def _shutdown(self) -> None:
        if self._end is None:  # the writer failed on its own
            self._finish(SessionEnd(None))
        self._stopped = True
        try:
            async with asyncio.timeout(FLUSH_TIMEOUT):
                await self._stream.close()
        except TimeoutError:
            self._stream.abort()
        if self._flush_deadline is not None:
            self._flush_deadline.cancel()
