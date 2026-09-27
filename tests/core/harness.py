"""Drive handshakes and sessions in memory: a transport, a writer queue and an attacker hook."""

import heapq
import itertools
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import cache

from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.profiles import HYBRID_1, REAL_PROFILES, Profile
from qrp2p.core.crypto.provider import CryptoProvider, PlainProvider
from qrp2p.core.events import Closed, Deliver, Priority, Queue, Send, Trace
from qrp2p.core.handshake import AdmissionRequired, Established, Initiator, Responder
from qrp2p.core.record import Channel
from qrp2p.core.trace import TraceEvent
from qrp2p.core.wire import Frame, Inner
from tests.support import DeterministicRandom, identity_from_label


@cache
def identity(name: str) -> IdentityKeyPair:
    return identity_from_label(name)


def alice() -> IdentityKeyPair:
    return identity("alice")


def bob() -> IdentityKeyPair:
    return identity("bob")


def provider(label: str, profiles: Iterable[Profile] = REAL_PROFILES) -> PlainProvider:
    return PlainProvider(DeterministicRandom(label), profiles)


def sent(events: Iterable[object]) -> list[Frame]:
    return [e.frame for e in events if isinstance(e, Send)]


def one[T](events: Iterable[object], kind: type[T]) -> T:
    found = [e for e in events if isinstance(e, kind)]
    assert len(found) == 1, f"expected one {kind.__name__}, got {found}"
    return found[0]


def none_of(events: Iterable[object], kind: type) -> bool:
    return not any(isinstance(e, kind) for e in events)


def traces(events: Iterable[object]) -> list[TraceEvent]:
    return [e.event for e in events if isinstance(e, Trace)]


def initiator(
    *,
    profile: Profile = HYBRID_1,
    me: IdentityKeyPair | None = None,
    pinned: IdentityBundle | None = None,
    pin: bool = True,
    gb: bool = False,
    prov: CryptoProvider | None = None,
    now: float = 0.0,
) -> Initiator:
    me = me or alice()
    return Initiator(
        provider=prov or provider("initiator"),
        profile=profile,
        identity=me,
        pinned=(pinned or bob().bundle) if pin else None,
        glass_box_request=gb,
        now=now,
    )


def responder(
    *,
    profiles: Sequence[Profile] = REAL_PROFILES,
    me: IdentityKeyPair | None = None,
    own_eks: frozenset[bytes] = frozenset(),
    prov: CryptoProvider | None = None,
    now: float = 0.0,
) -> Responder:
    return Responder(
        provider=prov or provider("responder", profiles),
        profiles=profiles,
        identity=me or bob(),
        own_ephemeral_keys=own_eks,
        now=now,
    )


@dataclass
class Run:
    """A handshake driven step by step; each field holds the events of one step."""

    i: Initiator
    r: Responder
    start: Sequence[object] = field(default_factory=list)
    on_hello: Sequence[object] = field(default_factory=list)
    on_reply: Sequence[object] = field(default_factory=list)
    on_confirm: Sequence[object] = field(default_factory=list)
    on_decision: Sequence[object] = field(default_factory=list)
    on_admit: Sequence[object] = field(default_factory=list)

    @property
    def hello(self) -> Frame:
        return sent(self.start)[0]

    @property
    def reply(self) -> Frame:
        return sent(self.on_hello)[0]

    @property
    def confirm(self) -> Frame:
        return sent(self.on_reply)[0]

    @property
    def admit(self) -> Frame:
        return sent(self.on_decision)[0]

    def channels(self) -> tuple[Channel, Channel]:
        return one(self.on_admit, Established).channel, one(self.on_decision, Established).channel


type Tamper = Callable[[str, Frame], Frame]


def handshake(
    i: Initiator | None = None,
    r: Responder | None = None,
    *,
    until: str = "admit",
    glass_box: bool = False,
    tamper: Tamper | None = None,
) -> Run:
    """Run a handshake up to and including step ``until``; ``tamper`` may rewrite frames."""
    run = Run(i or initiator(), r or responder())

    def via(name: str, frame: Frame) -> Frame:
        return tamper(name, frame) if tamper else frame

    steps = ["hello", "reply", "confirm", "decision", "admit"]
    run.start = list(run.i.start())
    if until == "start":
        return run
    run.on_hello = list(run.r.receive(via("hello", run.hello), 1.0))
    if until == "hello" or not sent(run.on_hello):
        return run
    run.on_reply = list(run.i.receive(via("reply", run.reply), 2.0))
    if until == "reply" or not sent(run.on_reply):
        return run
    run.on_confirm = list(run.r.receive(via("confirm", run.confirm), 3.0))
    if until == "confirm" or none_of(run.on_confirm, AdmissionRequired):
        return run
    run.on_decision = list(run.r.accept(glass_box=glass_box, now=4.0))
    if until == "decision":
        return run
    run.on_admit = list(run.i.receive(via("admit", run.admit), 5.0))
    assert until in steps
    return run


def session(**kwargs: object) -> tuple[Channel, Channel]:
    """A completed handshake: (initiator's channel, responder's channel)."""
    return handshake(**kwargs).channels()  # type: ignore[arg-type]


# --- a session over an in-memory link with one writer queue per side ------------------------


@dataclass
class Side:
    channel: Channel
    queue: list[tuple[int, int, Inner]] = field(default_factory=list)
    delivered: list[Inner] = field(default_factory=list)
    closed: list[Closed] = field(default_factory=list)
    events: list[object] = field(default_factory=list)
    wire: list[Frame] = field(default_factory=list)


class Link:
    """Two channels, a writer queue each (control > chat > file, FIFO within a priority)."""

    def __init__(self, i: Channel, r: Channel, tamper: Tamper | None = None) -> None:
        self.sides = {"i": Side(i), "r": Side(r)}
        self._order = itertools.count()
        self.tamper = tamper
        self.now = 10.0

    def __getitem__(self, name: str) -> Side:
        return self.sides[name]

    def other(self, name: str) -> str:
        return "r" if name == "i" else "i"

    def push(self, name: str, message: Inner, priority: Priority = Priority.CHAT) -> None:
        heapq.heappush(self.sides[name].queue, (priority, next(self._order), message))

    def absorb(self, name: str, events: Iterable[object]) -> None:
        side = self.sides[name]
        for event in events:
            side.events.append(event)
            match event:
                case Queue(message=message, priority=priority):
                    self.push(name, message, priority)
                case Deliver(message=message):
                    side.delivered.append(message)
                case Closed():
                    side.closed.append(event)
                case _:
                    pass

    def step(self, name: str) -> bool:
        """Dequeue, seal and deliver one message from ``name``; False if its queue is empty."""
        side = self.sides[name]
        if not side.queue:
            return False
        _, _, message = heapq.heappop(side.queue)
        events = side.channel.seal_next(message, self.now)
        self.absorb(name, [e for e in events if not isinstance(e, Send)])
        for frame in sent(events):
            side.wire.append(frame)
            out = self.tamper(name, frame) if self.tamper else frame
            self.absorb(
                self.other(name), self.sides[self.other(name)].channel.receive(out, self.now)
            )
        return True

    def run(self, limit: int = 1000) -> None:
        """Alternate the two writers until both queues are empty."""
        for _ in range(limit):
            progressed = self.step("i")
            progressed = self.step("r") or progressed
            if not progressed:
                return
        msg = "link did not settle"
        raise AssertionError(msg)

    def tick(self, now: float) -> None:
        self.now = now
        for name, side in self.sides.items():
            self.absorb(name, side.channel.tick(now))
