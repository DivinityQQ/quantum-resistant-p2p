"""Helpers for desktop-app tests: a service host with its deliveries recorded."""

import asyncio
import itertools
import threading
from collections.abc import Callable
from pathlib import Path

from qrp2p.services.node import Node
from qrp2p.ui.host import Op, ServiceHost
from qrp2p.ui.snapshots import Batch, Delivery, Lifecycle, Reply, Update
from tests.services.support import CHEAP_KDF, LOOPBACK


def make_node(directory: Path, **kwargs: object) -> Callable[[], Node]:
    """A node on loopback with a cheap KDF and no mDNS, built when the host starts."""

    def build() -> Node:
        return Node(
            directory,
            kdf=CHEAP_KDF,
            listen_host=LOOPBACK,
            port=0,
            discovery=False,
            **kwargs,  # type: ignore[arg-type]
        )

    return build


class HostHarness:
    """A :class:`ServiceHost` whose deliveries are recorded, driven from a test's event loop.

    The host's node runs on the host's own thread and loop, as in the app; waiting here polls,
    so other nodes on the test's loop keep running meanwhile.
    """

    def __init__(self, directory: Path, **kwargs: object) -> None:
        self.deliveries: list[Delivery] = []
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self.host = ServiceHost(make_node(directory, **kwargs), self._post, batch_interval=0.01)

    def _post(self, delivery: Delivery) -> None:
        with self._lock:
            self.deliveries.append(delivery)

    def snapshot(self) -> list[Delivery]:
        with self._lock:
            return list(self.deliveries)

    def lifecycles(self) -> list[Lifecycle]:
        return [d for d in self.snapshot() if isinstance(d, Lifecycle)]

    def mark(self) -> int:
        """A position in the deliveries: pass it as ``after`` to wait only for newer ones."""
        with self._lock:
            return len(self.deliveries)

    def updates(self, after: int = 0) -> list[Update]:
        return [u for d in self.snapshot()[after:] if isinstance(d, Batch) for u in d.updates]

    @property
    def gen(self) -> int:
        lifecycles = self.lifecycles()
        return lifecycles[-1].gen if lifecycles else 0

    async def wait(self, condition: Callable[[], bool], timeout: float = 10.0) -> None:  # noqa: ASYNC109
        async with asyncio.timeout(timeout):
            while not condition():  # noqa: ASYNC110  # the host posts from another thread
                await asyncio.sleep(0.005)

    async def lifecycle(self, state: str) -> Lifecycle:
        """Wait for the latest lifecycle delivery to have ``state``."""
        await self.wait(lambda: bool(self.lifecycles()) and self.lifecycles()[-1].state == state)
        return self.lifecycles()[-1]

    async def update[U](
        self, kind: type[U], where: Callable[[U], bool] = lambda _: True, *, after: int = 0
    ) -> U:
        """Wait for an update of ``kind`` matching ``where``, delivered after ``after``."""
        found: list[U] = []

        def match() -> bool:
            found[:] = [u for u in self.updates(after) if isinstance(u, kind) and where(u)]
            return bool(found)

        await self.wait(match)
        return found[0]

    def submit(self, op: Op, *, gen: int | None = None, scoped: bool = True) -> int:
        request_id = next(self._ids)
        self.host.submit(self.gen if gen is None else gen, request_id, op, scoped=scoped)
        return request_id

    async def reply(self, request_id: int) -> Reply:
        found: list[Reply] = []

        def match() -> bool:
            found[:] = [
                d for d in self.snapshot() if isinstance(d, Reply) and d.request_id == request_id
            ]
            return bool(found)

        await self.wait(match)
        return found[0]

    async def call(self, op: Op, *, gen: int | None = None, scoped: bool = True) -> Reply:
        return await self.reply(self.submit(op, gen=gen, scoped=scoped))

    async def ok(self, op: Op, *, scoped: bool = True) -> object:
        reply = await self.call(op, scoped=scoped)
        assert reply.error is None, reply.error
        return reply.value
