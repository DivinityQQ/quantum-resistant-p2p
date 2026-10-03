"""The solo lab: Alice and Bob, two throwaway identities, linked in memory (DESIGN §11, §11.6).

Both nodes run the real protocol core in this process. There are no sockets: a frame one node
sends waits *in flight* until a step delivers it. Every value either node derives is revealed
into the lab's own trace bus, under the same names a glass-box session uses, including the lab
identities' keys (they are throwaway, never the user's).

**What a step is.** A step is one input transition of one node (start the handshake, deliver one
frame, an admission decision, a chat, a KeyUpdate, a rekey, a close, a wait), followed by the
sealing of whatever that transition queued: the writer of a real session would seal those
records next, before reading anything else. Delivery is in order per direction, like TCP; the
default step delivers the oldest frame in flight. Browsing the trace never executes anything.

**Time** is a virtual lab clock: each step advances it by :data:`STEP_SECONDS`, a wait by
:data:`WAIT_SECONDS`, so the timers (pings, idle timeout, handshake deadline) fire as they would.
Times depend only on the steps, so a replay sees exactly the same clock.

**Replay and fork.** Each node's provider is a :class:`~qrp2p.lab.replay.LabProvider`. After
every step the controller notes how long each node's provider log is. Forking at step *N*
starts a new run from the same identities, replays the first *N* steps against the logs cut
at those marks (checking every recorded value), then continues live: from there the learner
can do something else and see what changes.
"""

import heapq
import itertools
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from msgspec import Struct

from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.crypto.provider import AeadRevealed, RandomSource, Revealed, RevealingProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.events import Closed, Deliver, Priority, Queue, Send, Trace
from qrp2p.core.handshake import (
    AdmissionRequired,
    Established,
    Initiator,
    KeyMismatch,
    ProfileRejected,
    Responder,
)
from qrp2p.core.record import Channel, ChannelState
from qrp2p.core.trace import RecordTraced
from qrp2p.core.wire import Chat, Close, Frame, FrameType, Inner, KeyUpdate
from qrp2p.lab.classical import LAB_PROFILES
from qrp2p.lab.replay import Entry, LabProvider, ReplayDivergence
from qrp2p.services.exposure import RecordRevealed, ValueRevealed
from qrp2p.services.trace_bus import SessionInfo, TraceBus

STEP_SECONDS: Final = 0.05
"""Lab-clock time one step takes."""
WAIT_SECONDS: Final = 30.0
"""Lab-clock time a wait lets pass: enough for a ping, a third of the idle timeout."""
RUN_LIMIT: Final = 200
"""Steps one Run executes at most (a run stops earlier when nothing is left to deliver)."""
SEED_LEN: Final = 32
CHAT_LIMIT: Final = 4_000
"""Characters a lab chat may have (the protocol allows 16,000 bytes; the lab needs fewer)."""
RUN_FORMAT: Final = 1


class Side(StrEnum):
    """The two lab nodes: Alice initiates, Bob responds."""

    ALICE = "alice"
    BOB = "bob"

    @property
    def other(self) -> Side:
        """The peer."""
        return Side.BOB if self is Side.ALICE else Side.ALICE

    @property
    def person(self) -> str:
        """The node's name."""
        return "Alice" if self is Side.ALICE else "Bob"


class Kind(StrEnum):
    """What a step does."""

    START = "start"
    DELIVER = "deliver"
    ADMIT = "admit"
    DECLINE = "decline"
    CHAT = "chat"
    KEY_UPDATE = "key_update"
    REKEY = "rekey"
    CLOSE = "close"
    WAIT = "wait"


class Step(Struct, frozen=True):
    """One step: what happens, at which node (for a delivery: the receiver), and chat text."""

    kind: Kind
    side: Side
    text: str = ""


class Phase(StrEnum):
    """Where the lab is."""

    READY = "ready"
    """Nothing has happened yet."""
    RUNNING = "running"
    """A step can deliver or decide something."""
    IDLE = "idle"
    """Nothing is in flight: the learner chooses what happens next."""
    ENDED = "ended"
    """Both nodes have closed: Reset starts a fresh experiment."""
    DIVERGED = "diverged"
    """A replay asked for something other than what was recorded."""


class LabRun(Struct, frozen=True):
    """Everything needed to replay a lab run: identities, profile, steps and provider logs."""

    format: int
    profile: int
    alice: tuple[bytes, bytes, bytes]
    bob: tuple[bytes, bytes, bytes]
    steps: list[Step]
    marks: list[tuple[int, int]]
    """Each node's provider-log length after each step."""
    alice_log: list[Entry]
    bob_log: list[Entry]


class LabError(Exception):
    """A step the lab cannot take now; the message says why."""


@dataclass(frozen=True, slots=True)
class InFlight:
    """A frame on its way from ``sender`` to the other node."""

    sender: Side
    frame: Frame
    label: str
    """What it is: ``Hello``, ``Record · chat``…"""


@dataclass
class _Node:
    side: Side
    seeds: tuple[bytes, bytes, bytes]
    identity: IdentityKeyPair
    provider: LabProvider
    session_id: int
    machine: Initiator | Responder | None = None
    channel: Channel | None = None
    queue: list[tuple[int, int, Inner]] = field(default_factory=list[tuple[int, int, Inner]])
    awaiting_admission: bool = False
    ended: bool = False
    received: list[str] = field(default_factory=list[str])
    """Chat text delivered to this node."""


def lab_profile(profile_id: int) -> Profile:
    """A lab profile by ID (``LAB-CLASSICAL`` included).

    Raises:
        LabError: No such profile.
    """
    for profile in LAB_PROFILES:
        if profile.id == profile_id:
            return profile
    msg = f"no lab profile 0x{profile_id:02x}"
    raise LabError(msg)


def _identity(seeds: tuple[bytes, bytes, bytes]) -> IdentityKeyPair:
    ed, m65, m87 = seeds
    return IdentityKeyPair(
        Secret(ed, "identity.ed25519"),
        Secret(m65, "identity.mldsa65"),
        Secret(m87, "identity.mldsa87"),
    )


class SoloLab:
    """One lab run: two nodes, the frames between them, and the steps taken so far.

    Use :meth:`fresh` for a new experiment and :meth:`replayed` to rebuild a recorded run.

    Args:
        profile: The profile both nodes use.
        seeds: Each node's identity seeds (Alice's, Bob's).
        bus: The lab's trace bus; this run's two sessions are opened on it.
        session_ids: The bus session IDs of Alice's and Bob's views.
        random_source: Fresh randomness once the replayed logs are used up; ``None`` for a
            strict replay.
        logs: Recorded provider logs to replay first (Alice's, Bob's).
    """

    def __init__(
        self,
        profile: Profile,
        seeds: tuple[tuple[bytes, bytes, bytes], tuple[bytes, bytes, bytes]],
        bus: TraceBus,
        session_ids: tuple[int, int],
        *,
        random_source: RandomSource | None,
        logs: tuple[Sequence[Entry], Sequence[Entry]] = ((), ()),
    ) -> None:
        self._profile = lab_profile(profile.id)  # only lab profiles, by identity
        self._bus = bus
        self._now = 0.0
        self._order = itertools.count()
        self._flight: list[InFlight] = []
        self._steps: list[Step] = []
        self._notes: list[str] = []
        self._marks: list[tuple[int, int]] = []
        self._started = False
        self._divergence = ""
        self._note = ""
        self._nodes: dict[Side, _Node] = {}
        for side, node_seeds, log, session_id in zip(Side, seeds, logs, session_ids, strict=True):
            provider = LabProvider(LAB_PROFILES, random_source=random_source, replay=log)
            self._nodes[side] = _Node(side, node_seeds, _identity(node_seeds), provider, session_id)
        alice, bob = self._nodes[Side.ALICE], self._nodes[Side.BOB]
        for node, peer in ((alice, bob), (bob, alice)):
            bus.open_session(
                SessionInfo(
                    session_id=node.session_id,
                    initiator=node.side is Side.ALICE,
                    address="in memory (lab)",
                    started=0.0,
                    profile=self._profile.name,
                    pinned=node.side is Side.ALICE,  # Alice knows Bob's identity in advance
                    peer_id=peer.identity.bundle.peer_id,
                    peer_short_id=peer.identity.bundle.short_id,
                )
            )

    @classmethod
    def fresh(
        cls,
        profile: Profile,
        bus: TraceBus,
        session_ids: tuple[int, int],
        random_source: RandomSource = os.urandom,
    ) -> SoloLab:
        """A new experiment with new throwaway identities."""
        seeds = tuple(
            (random_source(SEED_LEN), random_source(SEED_LEN), random_source(SEED_LEN))
            for _ in Side
        )
        return cls(profile, seeds, bus, session_ids, random_source=random_source)  # type: ignore[arg-type]

    @classmethod
    def replayed(
        cls,
        run: LabRun,
        bus: TraceBus,
        session_ids: tuple[int, int],
        *,
        upto: int | None = None,
        random_source: RandomSource | None = os.urandom,
    ) -> SoloLab:
        """Rebuild ``run`` by replaying its first ``upto`` steps (all by default).

        With a ``random_source`` the run continues live afterwards (a fork); without one it is a
        strict replay. A divergence leaves the lab in :attr:`Phase.DIVERGED`.

        Raises:
            LabError: ``run`` is not a run this version can replay, or ``upto`` is out of range.
        """
        count = len(run.steps) if upto is None else upto
        if run.format != RUN_FORMAT or not 0 <= count <= len(run.steps):
            msg = "this lab run cannot be replayed here"
            raise LabError(msg)
        if len(run.marks) != len(run.steps):
            msg = "the run's provider-log marks do not match its steps"
            raise LabError(msg)
        a_mark, b_mark = run.marks[count - 1] if count else (0, 0)
        lab = cls(
            lab_profile(run.profile),
            (run.alice, run.bob),
            bus,
            session_ids,
            random_source=random_source,
            logs=(run.alice_log[:a_mark], run.bob_log[:b_mark]),
        )
        for step in run.steps[:count]:
            lab.take(step)
            if lab.phase is Phase.DIVERGED:
                break
        return lab

    # -- state --------------------------------------------------------------------------------

    @property
    def profile(self) -> Profile:
        """The run's profile."""
        return self._profile

    @property
    def steps(self) -> tuple[Step, ...]:
        """The steps taken, in order."""
        return tuple(self._steps)

    @property
    def now(self) -> float:
        """The lab clock."""
        return self._now

    @property
    def in_flight(self) -> tuple[InFlight, ...]:
        """Frames sent and not yet delivered, oldest first."""
        return tuple(self._flight)

    @property
    def note(self) -> str:
        """What the last step did, in a sentence (or why it did nothing)."""
        return self._note

    @property
    def notes(self) -> tuple[str, ...]:
        """What each step did, in order."""
        return tuple(self._notes)

    def describe(self, step: Step) -> str:
        """What ``step`` would do, in a few words (for a button or a list)."""
        person = step.side.person
        match step.kind:
            case Kind.DELIVER:
                flight = next((f for f in self._flight if f.sender is step.side.other), None)
                what = flight.label if flight is not None else "the next frame"
                return f"Deliver {what} to {person}"
            case Kind.START:
                return "Start the handshake"
            case Kind.ADMIT:
                return "Bob admits Alice"
            case Kind.DECLINE:
                return "Bob declines Alice"
            case _:
                return f"{person}: {step.kind.value.replace('_', ' ')}"

    @property
    def divergence(self) -> str:
        """Why a replay stopped; empty unless :attr:`phase` is ``diverged``."""
        return self._divergence

    @property
    def session_ids(self) -> tuple[int, int]:
        """The bus session IDs of Alice's and Bob's views."""
        return self._nodes[Side.ALICE].session_id, self._nodes[Side.BOB].session_id

    def received(self, side: Side) -> tuple[str, ...]:
        """Chat text delivered to ``side`` so far."""
        return tuple(self._nodes[side].received)

    def is_open(self, side: Side) -> bool:
        """``side`` has an open channel."""
        channel = self._nodes[side].channel
        return channel is not None and channel.state is ChannelState.OPEN

    def can_rekey(self) -> bool:
        """Alice (the initiator) can start a PQ rekey now."""
        channel = self._nodes[Side.ALICE].channel
        return self.is_open(Side.ALICE) and channel is not None and not channel.rekey_in_progress

    @property
    def phase(self) -> Phase:
        """Where the lab is."""
        if self._divergence:
            return Phase.DIVERGED
        if not self._started:
            return Phase.READY
        if all(n.ended for n in self._nodes.values()) and not self._flight:
            return Phase.ENDED
        if self._flight or self._nodes[Side.BOB].awaiting_admission:
            return Phase.RUNNING
        return Phase.IDLE

    def next_step(self) -> Step | None:
        """What Step does now: deliver the oldest frame in flight, then admit, else nothing."""
        if self.phase in {Phase.ENDED, Phase.DIVERGED}:
            return None
        if not self._started:
            return Step(Kind.START, Side.ALICE)
        if self._flight:
            return Step(Kind.DELIVER, self._flight[0].sender.other)
        if self._nodes[Side.BOB].awaiting_admission:
            return Step(Kind.ADMIT, Side.BOB)
        return None

    def run(self, limit: int = RUN_LIMIT) -> int:
        """Take default steps until nothing is left to deliver or decide; return how many."""
        taken = 0
        while taken < limit and (step := self.next_step()) is not None:
            self.take(step)
            taken += 1
        return taken

    def run_record(self) -> LabRun:
        """This run as a replayable record (its steps and both provider logs)."""
        alice, bob = self._nodes[Side.ALICE], self._nodes[Side.BOB]
        return LabRun(
            format=RUN_FORMAT,
            profile=self._profile.id,
            alice=alice.seeds,
            bob=bob.seeds,
            steps=list(self._steps),
            marks=list(self._marks),
            alice_log=list(alice.provider.log),
            bob_log=list(bob.provider.log),
        )

    # -- steps --------------------------------------------------------------------------------

    def check(self, step: Step) -> None:
        """Whether ``step`` can be taken now.

        Raises:
            LabError: It cannot; the message says why.
        """
        if self.phase is Phase.DIVERGED:
            msg = "the replay diverged: reset, or fork at an earlier step"
            raise LabError(msg)
        side = step.side
        not_open = "" if self.is_open(side) else f"{side.person} has no open session"
        refusals: dict[Kind, Callable[[], str]] = {
            Kind.START: lambda: (
                "" if not self._started and side is Side.ALICE else "already started"
            ),
            Kind.DELIVER: lambda: (
                ""
                if any(f.sender is side.other for f in self._flight)
                else f"nothing is in flight to {side.person}"
            ),
            Kind.ADMIT: lambda: self._no_decision(side),
            Kind.DECLINE: lambda: self._no_decision(side),
            Kind.CHAT: lambda: (
                not_open
                or (
                    ""
                    if 0 < len(step.text) <= CHAT_LIMIT
                    else f"a lab chat has 1 to {CHAT_LIMIT} characters"
                )
            ),
            Kind.KEY_UPDATE: lambda: not_open,
            Kind.CLOSE: lambda: not_open,
            Kind.REKEY: lambda: (
                ""
                if side is Side.ALICE and self.can_rekey()
                else "only Alice starts a rekey, with an open session and none under way"
            ),
            Kind.WAIT: lambda: "" if self._started else "start the handshake first",
        }
        reason = refusals[step.kind]()
        if reason:
            raise LabError(reason)

    def _no_decision(self, side: Side) -> str:
        pending = side is Side.BOB and self._nodes[Side.BOB].awaiting_admission
        return "" if pending else "no admission decision is pending"

    def take(self, step: Step) -> None:
        """Take one step: one input transition, then seal what it queued.

        Raises:
            LabError: The step cannot be taken now (nothing changed).
        """
        self.check(step)
        self._now += WAIT_SECONDS if step.kind is Kind.WAIT else STEP_SECONDS
        self._steps.append(step)
        node = self._nodes[step.side]
        try:
            self._note = self._execute(step, node)
            for each in self._nodes.values():
                self._drain(each)
        except ReplayDivergence as divergence:
            self._divergence = str(divergence)
            self._note = self._divergence
        self._notes.append(self._note)
        alice, bob = self._nodes[Side.ALICE], self._nodes[Side.BOB]
        self._marks.append((len(alice.provider.log), len(bob.provider.log)))

    def _execute(self, step: Step, node: _Node) -> str:
        """Run the step's transition; return what it did, in a sentence."""
        handlers: dict[Kind, Callable[[Step, _Node], str]] = {
            Kind.START: self._start,
            Kind.DELIVER: lambda _, n: self._deliver(n),
            Kind.ADMIT: self._decide,
            Kind.DECLINE: self._decide,
            Kind.CHAT: self._chat,
            Kind.KEY_UPDATE: self._key_update,
            Kind.REKEY: lambda _, n: self._rekey(n),
            Kind.CLOSE: self._close,
            Kind.WAIT: lambda _, __: self._wait(),
        }
        return handlers[step.kind](step, node)

    def _start(self, _: Step, node: _Node) -> str:
        self._started = True
        bob = self._nodes[Side.BOB]
        machine = Initiator(
            provider=self._revealing(node),
            profile=self._profile,
            identity=node.identity,
            pinned=bob.identity.bundle,
            glass_box_request=False,
            now=self._now,
        )
        node.machine = machine
        bob.machine = Responder(
            provider=self._revealing(bob),
            profiles=(self._profile,),
            identity=bob.identity,
            own_ephemeral_keys=frozenset[bytes](),
            now=self._now,
        )
        self._absorb(node, machine.start())
        return "Alice starts the handshake: Hello is on its way to Bob."

    def _decide(self, step: Step, node: _Node) -> str:
        responder = node.machine
        assert isinstance(responder, Responder)  # noqa: S101  # checked: awaiting admission
        node.awaiting_admission = False
        if step.kind is Kind.ADMIT:
            self._absorb(node, responder.accept(glass_box=False, now=self._now))
            return "Bob admits Alice: Admit is on its way."
        self._absorb(node, responder.reject(AdmitReason.DECLINED, self._now))
        return "Bob declines: Alice is told so, and both sides close."

    def _chat(self, step: Step, node: _Node) -> str:
        message = Chat(id=len(self._steps).to_bytes(16, "big"), text=step.text)
        self._queue(node, message, Priority.CHAT)
        return f"{step.side.person} sends a chat message."

    def _key_update(self, step: Step, node: _Node) -> str:
        self._queue(node, KeyUpdate(), Priority.CONTROL)
        return f"{step.side.person} moves its sending direction to new keys (KeyUpdate)."

    def _rekey(self, node: _Node) -> str:
        assert node.channel is not None  # noqa: S101  # checked: open
        events = node.channel.start_rekey(self._now)
        self._absorb(node, events)
        if not any(isinstance(e, Queue) for e in events):
            return "No rekey started: the last one began less than a minute ago. Wait first."
        return "Alice starts a PQ rekey: a fresh encapsulation key is on its way."

    def _close(self, step: Step, node: _Node) -> str:
        assert node.channel is not None  # noqa: S101  # checked: open
        self._absorb(node, node.channel.close(CloseReason.NORMAL))
        return f"{step.side.person} closes the session."

    def _wait(self) -> str:
        for each in self._nodes.values():
            self._tick(each)
        return f"{WAIT_SECONDS:.0f} seconds pass on the lab clock."

    def _deliver(self, node: _Node) -> str:
        index = next(i for i, f in enumerate(self._flight) if f.sender is node.side.other)
        flight = self._flight.pop(index)
        target = node.channel if node.channel is not None else node.machine
        if node.ended or target is None:
            return (
                f"{flight.label} reaches {node.side.person}, whose connection is closed: dropped."
            )
        self._absorb(node, target.receive(flight.frame, self._now))
        return f"{flight.label} delivered to {node.side.person}."

    def _tick(self, node: _Node) -> None:
        if node.ended:
            return
        if node.channel is not None:
            self._absorb(node, node.channel.tick(self._now))
        elif node.machine is not None:
            self._absorb(node, node.machine.tick(self._now))

    def _queue(self, node: _Node, message: Inner, priority: Priority) -> None:
        heapq.heappush(node.queue, (priority, next(self._order), message))

    # -- what the core asks for ---------------------------------------------------------------

    def _revealing(self, node: _Node) -> RevealingProvider:
        return RevealingProvider(node.provider, self._revealer(node))

    def _revealer(self, node: _Node) -> Callable[[Revealed], None]:
        def reveal(value: Revealed) -> None:
            if isinstance(value, AeadRevealed):
                record = RecordRevealed(
                    value.key, value.seq, value.nonce, value.plaintext, value.opened
                )
                self._bus.publish(node.session_id, self._now, record)
            else:
                self._bus.publish(node.session_id, self._now, ValueRevealed(value))

        return reveal

    def _absorb(self, node: _Node, events: Sequence[object]) -> None:
        for event in events:
            match event:
                case Send(frame=frame):
                    self._send(node, frame, _frame_label(frame))
                case Queue(message=message, priority=priority):
                    self._queue(node, message, priority)
                case Trace(event=trace):
                    self._bus.publish(node.session_id, self._now, trace)
                case Deliver(message=Chat(text=text)):
                    node.received.append(text)
                case Closed():
                    self._ended(node, event)
                case AdmissionRequired():
                    node.awaiting_admission = True
                case Established():
                    node.channel, node.machine = event.channel, None
                    self._bus.handshake_done(node.session_id)
                    self._bus.describe(node.session_id, established=True)
                case KeyMismatch() | ProfileRejected():
                    pass  # the lab pins the true identity and serves its own profile
                case _:
                    pass  # other application messages: the lab shows chat only

    def _send(self, node: _Node, frame: Frame, label: str) -> None:
        if not self._nodes[node.side.other].ended:
            self._flight.append(InFlight(node.side, frame, label))

    def _ended(self, node: _Node, closed: Closed) -> None:
        node.ended = True
        node.awaiting_admission = False
        admit = closed.admit_reason.label if closed.admit_reason is not None else ""
        self._bus.describe(
            node.session_id,
            end_reason=closed.reason.label,
            admit_reason=admit,
            by_peer=closed.by_peer,
        )
        self._bus.session_ended(node.session_id)

    def _drain(self, node: _Node) -> None:
        """Seal what ``node`` queued, as its writer would; a closing channel sends only close."""
        while node.queue:
            _, _, message = heapq.heappop(node.queue)
            channel = node.channel
            if channel is None or channel.state is ChannelState.CLOSED:
                continue
            if channel.state is ChannelState.CLOSING and not isinstance(message, Close):
                continue
            label = "Record"
            for event in channel.seal_next(message, self._now):
                match event:
                    case Trace(event=RecordTraced(kind=kind)):
                        label = f"Record · {kind}"
                        self._bus.publish(node.session_id, self._now, event.event)
                    case Trace(event=trace):
                        self._bus.publish(node.session_id, self._now, trace)
                    case Send(frame=frame):
                        self._send(node, frame, label)
                    case _:
                        pass


def _frame_label(frame: Frame) -> str:
    names = {
        FrameType.HELLO: "Hello",
        FrameType.REPLY: "Reply",
        FrameType.CONFIRM: "Confirm",
        FrameType.ADMIT: "Admit",
        FrameType.PROFILE_UNSUPPORTED: "ProfileUnsupported",
    }
    return names.get(frame.type, "Record")
