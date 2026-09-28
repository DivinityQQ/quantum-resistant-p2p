"""Helpers for service tests: a controllable clock, recording hooks, peers on loopback."""

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.profiles import HYBRID_1, Profile
from qrp2p.core.crypto.provider import CryptoProvider, PlainProvider
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.handshake import AdmissionRequired, KeyMismatch, ProfileRejected
from qrp2p.core.wire import Inner
from qrp2p.services.events import AdmissionPrompt, NodeEvent, SessionOpened
from qrp2p.services.node import Node
from qrp2p.services.session import Session, SessionEnd
from qrp2p.services.session_manager import SessionManager
from qrp2p.services.trace_bus import TraceBus
from qrp2p.services.transport import Listener
from qrp2p.services.vault import KdfParams, KdfPolicy
from tests.support import DeterministicRandom, identity_from_label

LOOPBACK = "127.0.0.1"


class Clock:
    """Monotonic time that tests can move forward."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return time.monotonic() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds


async def until(condition: Callable[[], bool], timeout: float = 10.0) -> None:  # noqa: ASYNC109
    """Wait until ``condition()`` holds."""
    async with asyncio.timeout(timeout):
        while not condition():  # noqa: ASYNC110  # polls state that has no event
            await asyncio.sleep(0.005)


@dataclass
class Recorded:
    """Everything a manager reported."""

    admissions: list[AdmissionRequired] = field(default_factory=list)
    mismatches: list[KeyMismatch] = field(default_factory=list)
    rejected_profiles: list[ProfileRejected] = field(default_factory=list)
    established: list[tuple[Session, Session | None]] = field(default_factory=list)
    messages: list[tuple[Session, Inner]] = field(default_factory=list)
    sent: list[tuple[Session, Inner]] = field(default_factory=list)
    ended: list[tuple[Session, SessionEnd, bool]] = field(default_factory=list)

    def ended_for(self, session: Session) -> SessionEnd | None:
        return next((end for s, end, _ in self.ended if s is session), None)


class RecordingHooks:
    """Manager hooks that record everything and admit per a simple rule."""

    def __init__(self) -> None:
        self.record = Recorded()
        self.decide: Callable[[Session, AdmissionRequired], AdmitReason | None] = lambda _s, _r: (
            None
        )
        """Return ``None`` to accept, a reason to reject; set ``defer`` to decide later."""
        self.defer = False
        self.glass_box = False

    def admission(self, session: Session, request: AdmissionRequired) -> None:
        self.record.admissions.append(request)
        if self.defer:
            return
        reason = self.decide(session, request)
        if reason is None:
            session.accept(glass_box=self.glass_box and request.gb_request)
        else:
            session.reject(reason)

    def key_mismatch(self, session: Session, event: KeyMismatch) -> None:  # noqa: ARG002
        self.record.mismatches.append(event)

    def profile_rejected(self, session: Session, event: ProfileRejected) -> None:  # noqa: ARG002
        self.record.rejected_profiles.append(event)

    def established(self, session: Session, replaced: Session | None) -> None:
        self.record.established.append((session, replaced))

    async def message(self, session: Session, message: Inner) -> None:
        self.record.messages.append((session, message))

    def sent(self, session: Session, message: Inner) -> None:
        self.record.sent.append((session, message))

    def ended(self, session: Session, end: SessionEnd, *, superseded: bool) -> None:
        self.record.ended.append((session, end, superseded))


class Peer:
    """A session manager with a listener on loopback."""

    def __init__(self, name: str, clock: Clock | None = None) -> None:
        self.name = name
        self.identity: IdentityKeyPair = identity_from_label(name)
        self.hooks = RecordingHooks()
        self.clock = clock or Clock()
        self.trace = TraceBus()
        rng = DeterministicRandom(f"peer:{name}")
        self.manager = SessionManager(
            identity=self.identity,
            hooks=self.hooks,
            provider_factory=lambda: self.provider(rng),
            clock=self.clock,
            trace=self.trace,
        )
        self.listener = Listener(self.manager.handle_incoming)
        self.port = 0

    def provider(self, rng: DeterministicRandom) -> CryptoProvider:
        return PlainProvider(rng)

    @property
    def record(self) -> Recorded:
        return self.hooks.record

    async def start(self) -> Peer:
        self.manager.start()
        self.port = await self.listener.start(LOOPBACK, 0)
        return self

    async def stop(self) -> None:
        await self.listener.close()
        await self.manager.stop(CloseReason.NORMAL)

    async def connect(
        self,
        other: Peer,
        *,
        pin: bool = True,
        profile: Profile = HYBRID_1,
        glass_box: bool = False,
    ) -> Session:
        return await self.manager.connect(
            LOOPBACK,
            other.port,
            profile=profile,
            pinned=other.identity.bundle if pin else None,
            glass_box=glass_box,
        )


# --- whole nodes ----------------------------------------------------------------------------------


class NodeHarness:
    """A :class:`~qrp2p.services.node.Node` on loopback with its events recorded."""

    def __init__(self, directory: Path, name: str, **kwargs: object) -> None:
        self.name = name
        self.clock = Clock()
        self.events: list[NodeEvent] = []
        self.node = Node(
            directory / name,
            kdf=CHEAP_KDF,
            listen_host=LOOPBACK,
            port=0,
            discovery=False,
            clock=self.clock,
            **kwargs,  # type: ignore[arg-type]
        )
        self.node.subscribe(self.events.append)

    async def start(self, password: str = "pw") -> NodeHarness:
        await self.node.create(password, display_name=self.name.title())
        return self

    @property
    def port(self) -> int:
        port = self.node.port
        assert port is not None
        return port

    def of[E](self, kind: type[E]) -> list[E]:
        return [e for e in self.events if isinstance(e, kind)]

    async def next[E](self, kind: type[E], where: Callable[[E], bool] = lambda _: True) -> E:
        """Wait for the first recorded event of ``kind`` matching ``where``."""
        found: list[E] = []

        def match() -> bool:
            found[:] = [e for e in self.of(kind) if where(e)]
            return bool(found)

        await until(match)
        return found[0]


CHEAP_KDF = KdfPolicy(floor=KdfParams(t=1, m_kib=64, p=1), target_seconds=0)
"""Argon2id far below the floor, for tests only."""


async def befriend(alice: NodeHarness, bob: NodeHarness) -> tuple[bytes, bytes]:
    """Alice connects to Bob by address; Bob accepts the contact request.

    Returns (Bob's contact ID at Alice, Alice's contact ID at Bob).
    """
    connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port, name="Bob"))
    prompt = await bob.next(AdmissionPrompt)
    await bob.node.answer_prompt(prompt.prompt_id, accept=True, name="Alice")
    bob_at_alice = await connecting
    opened = await bob.next(SessionOpened)
    return bob_at_alice, opened.contact_id
