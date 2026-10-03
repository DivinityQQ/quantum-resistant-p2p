"""The bridge's generation filter: nothing stale reaches the views (UI_DESIGN §11.2, §13.1)."""

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest
from PySide6.QtCore import QCoreApplication

from qrp2p.ui.bridge import STARTING, Bridge
from qrp2p.ui.host import Op, Post, Services
from qrp2p.ui.snapshots import Batch, Lifecycle, NoticePosted, Reply, Update


@dataclass
class FakeHost:
    """Records requests; the test posts deliveries as the services thread would."""

    post: Post
    submitted: list[tuple[int, int, Op, bool]] = field(default_factory=list)
    started: bool = False
    stopped: bool = False

    def start(self) -> None:
        self.started = True

    def submit(self, gen: int, request_id: int, op: Op, *, scoped: bool) -> None:
        self.submitted.append((gen, request_id, op, scoped))

    def stop(self, timeout: float = 0.0) -> bool:  # noqa: ARG002
        self.stopped = True
        return True


class Probe:
    def __init__(self, bridge: Bridge) -> None:
        self.lifecycles: list[Lifecycle] = []
        self.updates: list[Update] = []
        bridge.lifecycle.connect(self.lifecycles.append)
        bridge.updates.connect(self.updates.extend)


@pytest.fixture
def setup(qapp: QCoreApplication) -> tuple[Bridge, FakeHost, Probe]:  # noqa: ARG001
    hosts: list[FakeHost] = []

    def make(post: Post) -> FakeHost:
        hosts.append(FakeHost(post))
        return hosts[0]

    bridge = Bridge(make)
    bridge.start()
    return bridge, hosts[0], Probe(bridge)


def settle() -> None:
    """Deliver the queued signals."""
    QCoreApplication.processEvents()


def notice(text: str) -> tuple[Update, ...]:
    return (NoticePosted(text),)


async def noop(_: Services) -> None:
    pass


def test_lifecycles_set_the_generation(setup: tuple[Bridge, FakeHost, Probe]) -> None:
    bridge, host, probe = setup
    assert host.started
    assert bridge.state == STARTING
    host.post(Lifecycle(1, "locked"))
    assert probe.lifecycles == []  # queued: nothing happens inside the services thread's call
    settle()
    assert [d.state for d in probe.lifecycles] == ["locked"]
    assert (bridge.gen, bridge.state, bridge.accepting) == (1, "locked", False)
    host.post(Lifecycle(2, "unlocked"))
    settle()
    assert bridge.accepting


def test_updates_pass_only_for_the_current_unlocked_generation(
    setup: tuple[Bridge, FakeHost, Probe],
) -> None:
    _, host, probe = setup
    host.post(Batch(1, notice("before any lifecycle")))
    host.post(Lifecycle(1, "locked"))
    host.post(Batch(1, notice("while locked")))
    host.post(Lifecycle(2, "unlocked"))
    host.post(Batch(1, notice("an older generation")))
    host.post(Batch(2, notice("current")))
    host.post(Lifecycle(3, "locked"))
    host.post(Batch(2, notice("after the lock")))
    settle()
    assert probe.updates == list(notice("current"))


def test_a_lock_drops_what_is_already_queued(setup: tuple[Bridge, FakeHost, Probe]) -> None:
    bridge, host, probe = setup
    host.post(Lifecycle(1, "unlocked"))
    settle()
    host.post(Batch(1, notice("queued before the lock")))  # e.g. a chat line on its way
    bridge.lock()  # the user locks before the queue is delivered
    settle()
    assert probe.updates == []
    assert not bridge.accepting
    gen, _, _, scoped = host.submitted[-1]
    assert (gen, scoped) == (1, False)  # the lock itself is unscoped
    assert not bridge.request(noop)  # scoped requests are refused while locking
    host.post(Lifecycle(2, "locked"))
    host.post(Lifecycle(3, "unlocked"))
    host.post(Batch(3, notice("new session")))
    settle()
    assert probe.updates == list(notice("new session"))


def test_replies_to_scoped_requests_do_not_outlive_their_generation(
    setup: tuple[Bridge, FakeHost, Probe],
) -> None:
    bridge, host, _ = setup
    host.post(Lifecycle(1, "unlocked"))
    settle()
    got: list[str] = []

    def record(label: str) -> Callable[[Reply], None]:
        return lambda reply: got.append(f"{label}:{reply.value}")

    assert bridge.request(noop, record("scoped"))
    assert bridge.request(noop, record("unscoped"), scoped=False)
    (_, scoped_id, _, _), (_, unscoped_id, _, _) = host.submitted
    host.post(Lifecycle(2, "locked"))  # an auto-lock, say
    host.post(Lifecycle(3, "unlocked"))
    host.post(Reply(1, scoped_id, "late"))
    host.post(Reply(1, unscoped_id, "late"))
    settle()
    assert got == ["unscoped:late"]


def test_replies_reach_their_requester_once(setup: tuple[Bridge, FakeHost, Probe]) -> None:
    bridge, host, _ = setup
    host.post(Lifecycle(1, "unlocked"))
    settle()
    got: list[object] = []
    bridge.request(noop, lambda reply: got.append(reply.value))
    request_id = host.submitted[-1][1]
    host.post(Reply(1, request_id, "first"))
    host.post(Reply(1, request_id, "again"))
    host.post(Reply(1, 999, "unknown"))
    settle()
    assert got == ["first"]


def test_scoped_requests_wait_for_an_unlocked_node(setup: tuple[Bridge, FakeHost, Probe]) -> None:
    bridge, host, _ = setup
    assert not bridge.request(noop)
    host.post(Lifecycle(1, "locked"))
    settle()
    assert not bridge.request(noop)
    assert bridge.request(noop, scoped=False)
    assert len(host.submitted) == 1


def test_nothing_is_dispatched_after_stop(setup: tuple[Bridge, FakeHost, Probe]) -> None:
    bridge, host, probe = setup
    host.post(Lifecycle(1, "unlocked"))
    assert bridge.stop(1.0)
    assert host.stopped
    host.post(Lifecycle(2, "locked"))
    settle()
    assert probe.lifecycles == []
    assert not bridge.request(noop, scoped=False)


def test_a_scope_ends_with_its_generation(setup: tuple[Bridge, FakeHost, Probe]) -> None:
    bridge, host, _ = setup
    host.post(Lifecycle(1, "unlocked"))
    settle()
    scope = bridge.scope()
    assert scope.request(noop)
    assert host.submitted[-1][0] == 1
    host.post(Lifecycle(2, "locked"))
    host.post(Lifecycle(3, "unlocked"))
    settle()
    assert bridge.accepting
    assert not scope.request(noop)  # the bridge accepts again, but not for this scope
    assert bridge.scope().request(noop)
    assert [gen for gen, *_ in host.submitted] == [1, 3]
