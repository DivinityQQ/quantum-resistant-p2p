"""A fake services side for view-model tests: requests are recorded and answered by hand.

Requests are closures built by :mod:`qrp2p.ui.ops`; :func:`describe` reads one's name and captured
arguments, so a test can find "the send_chat request for this contact" and answer it.
"""

import itertools
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from PySide6.QtCore import QCoreApplication

from qrp2p.ui.bridge import Bridge
from qrp2p.ui.host import LabOp, Op, Post, TapOp
from qrp2p.ui.snapshots import (
    Batch,
    ContactSnap,
    ErrorInfo,
    IdentitySnap,
    Lifecycle,
    MessageSnap,
    NetworkSnap,
    Reply,
    SessionSnap,
    SettingsSnap,
    Update,
    WorkspaceSnap,
)

_ids = itertools.count(1)


def describe(op: Op) -> tuple[str, dict[str, object]]:
    """An op's name (the ops function that built it) and the values it captured."""
    fn = op.run if isinstance(op, TapOp | LabOp) else op
    name = fn.__qualname__.split(".<locals>")[0]
    cells = fn.__closure__ or ()
    values = {
        var: cell.cell_contents for var, cell in zip(fn.__code__.co_freevars, cells, strict=True)
    }
    return name, values


@dataclass
class Request:
    gen: int
    request_id: int
    name: str
    args: dict[str, object]
    scoped: bool
    op: Op | None = None
    """The op itself, for a test that runs it against a real lab host."""


@dataclass
class FakeBackend:
    """Stands in for the services host; owns the bridge built on it."""

    requests: list[Request] = field(default_factory=list)
    answered: set[int] = field(default_factory=set)
    gen: int = 0
    post: Post | None = None
    bridge: Bridge = field(init=False)

    def __post_init__(self) -> None:
        self.bridge = Bridge(self._make)
        self.bridge.start()

    def _make(self, post: Post) -> FakeBackend:
        self.post = post
        return self

    # Host protocol
    def start(self) -> None:
        pass

    def submit(self, gen: int, request_id: int, op: Op, *, scoped: bool) -> None:
        name, args = describe(op)
        self.requests.append(Request(gen, request_id, name, args, scoped, op))

    def stop(self, timeout: float = 0.0) -> bool:  # noqa: ARG002
        return True

    # Test controls
    def send(self, delivery: Lifecycle | Batch | Reply) -> None:
        assert self.post is not None
        self.post(delivery)
        settle()

    def lifecycle(
        self, state: str, workspace: WorkspaceSnap | None = None, error: str = ""
    ) -> None:
        self.gen += 1
        self.send(Lifecycle(self.gen, state, workspace, error))

    def updates(self, *updates: Update) -> None:
        self.send(Batch(self.gen, tuple(updates)))

    def pending(
        self, name: str, where: Callable[[Request], bool] = lambda _: True
    ) -> list[Request]:
        """Unanswered requests of an ops function."""
        return [
            r
            for r in self.requests
            if r.name == name and r.request_id not in self.answered and where(r)
        ]

    def one(self, name: str, where: Callable[[Request], bool] = lambda _: True) -> Request:
        found = self.pending(name, where)
        assert len(found) == 1, (name, [r.name for r in self.requests])
        return found[0]

    def reply(
        self, request: Request, value: object = None, *, error: ErrorInfo | None = None
    ) -> None:
        self.answered.add(request.request_id)
        self.send(Reply(request.gen, request.request_id, value, error))


def settle() -> None:
    """Deliver queued signals (the bridge's queued connection)."""
    for _ in range(3):
        QCoreApplication.processEvents()


# -- snapshot builders --------------------------------------------------------------------------------


def hex_id(label: str) -> str:
    """A stable 32-digit hex ID for a label."""
    return label.encode().hex().ljust(32, "0")[:32]


def contact(
    name: str,
    *,
    trust: str = "pinned",
    online: bool = False,
    glass_box: bool = False,
    initiator: bool = True,
    created: float = 1000.0,
) -> ContactSnap:
    session = (
        SessionSnap(session_id=7, profile="HYBRID-1", glass_box=glass_box, initiator=initiator)
        if online
        else None
    )
    return ContactSnap(
        contact_id=hex_id(name),
        name=name,
        short_id=f"{name[:4].upper():X<4}-0000",
        fingerprint="abcd " * 24,
        trust=trust,
        profile="HYBRID-1",
        retention="forever",
        auto_accept_files=False,
        auto_accept_limit=0,
        address="10.0.0.2:47470",
        created=created,
        session=session,
    )


def online(snap: ContactSnap, *, glass_box: bool = False) -> ContactSnap:
    return replace(
        snap,
        session=SessionSnap(session_id=7, profile="HYBRID-1", glass_box=glass_box, initiator=True),
    )


def offline(snap: ContactSnap) -> ContactSnap:
    return replace(snap, session=None)


SETTINGS = SettingsSnap(
    display_name="Me",
    announce_name=True,
    default_profile="HYBRID-1",
    default_retention="forever",
    auto_lock_minutes=15,
    port=47470,
    downloads_dir="/home/me/Downloads",
    downloads_custom=False,
    max_file_size=4 * 2**30,
    appearance="system",
    reduced_motion=False,
    text_scale=100,
)


def workspace(*contacts: ContactSnap, settings: SettingsSnap = SETTINGS) -> WorkspaceSnap:
    return WorkspaceSnap(
        identity=IdentitySnap(
            short_id="MEME-0000",
            fingerprint="0000 " * 24,
            bundle_bytes=4577,
            parts=(
                ("Ed25519 public key", 32),
                ("ML-DSA-65 public key", 1952),
                ("ML-DSA-87 public key", 2592),
            ),
        ),
        network=NetworkSnap(port=47470, addresses=("10.0.0.1",), discovery=True),
        settings=settings,
        contacts=contacts,
        nearby=(),
        prompts=(),
    )


def chat(
    text: str,
    *,
    direction: str = "in",
    status: str = "received",
    time: float = 2_000_000_000.0,
    entry: str | None = None,
    glass_box: bool = False,
) -> MessageSnap:
    return MessageSnap(
        entry_id=entry or hex_id(f"e{next(_ids)}"),
        kind="chat",
        direction=direction,
        time=time,
        status=status,
        text=text,
        glass_box=glass_box,
        file=None,
    )
