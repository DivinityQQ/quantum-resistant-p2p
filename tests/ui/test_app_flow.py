"""The desktop app's view models over a real node and a real peer: the M3 flows end to end.

Alice is the app (controller, bridge, services thread, node); Bob is a headless node on the test's
event loop. Waiting pumps both the Qt events (deliveries are queued signals) and asyncio.
"""

import asyncio
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
from PySide6.QtCore import QCoreApplication

from qrp2p.services.events import HistoryChanged, SessionEnded
from qrp2p.services.models import FileStatus
from qrp2p.ui.bridge import Bridge
from qrp2p.ui.host import ServiceHost
from qrp2p.ui.viewmodels.application import AppController
from qrp2p.ui.viewmodels.conversation import Conversation
from qrp2p.ui.viewmodels.workspace import Workspace
from tests.services.support import LOOPBACK, NodeHarness
from tests.ui.support import make_node

PASSWORD = "correct horse"


async def until(condition: Callable[[], bool], timeout: float = 10.0) -> None:  # noqa: ASYNC109
    async with asyncio.timeout(timeout):
        while not condition():  # Qt events have no awaitable
            QCoreApplication.processEvents()
            await asyncio.sleep(0.005)


@pytest.fixture
async def alice(tmp_path: Path, qapp: QCoreApplication) -> AsyncIterator[AppController]:  # noqa: ARG001
    bridge = Bridge(
        lambda post: ServiceHost(make_node(tmp_path / "alice"), post, batch_interval=0.01)
    )
    controller = AppController(bridge, data_dir=str(tmp_path / "alice"))
    bridge.start()
    yield controller
    assert await asyncio.to_thread(bridge.stop, 20.0)
    controller.deleteLater()
    QCoreApplication.processEvents()


@pytest.fixture
async def bob(tmp_path: Path) -> AsyncIterator[NodeHarness]:
    harness = await NodeHarness(tmp_path, "bob").start()
    yield harness
    await harness.node.close()


def workspace(app: AppController) -> Workspace:
    ws = app.property("workspace")
    assert isinstance(ws, Workspace)
    return ws


def conversation(ws: Workspace) -> Conversation:
    current = ws.conversation_model
    assert current is not None
    return current


def texts(conv: Conversation) -> list[tuple[str, str]]:
    return [(r.text, r.status_text) for r in conv.messages.rows() if r.kind == "chat"]


async def test_first_contact_chat_files_lock_and_unlock(  # noqa: PLR0915  # one story
    alice: AppController, bob: NodeHarness, tmp_path: Path
) -> None:
    await until(lambda: alice.property("phase") == "noVault")
    alice.createVault("Alice", PASSWORD, PASSWORD)
    await until(lambda: alice.property("phase") == "unlocked")
    assert alice.property("welcome")
    ws = workspace(alice)
    assert ws.property("shortId") != ""
    assert ws.property("bundleBytes") == 4577

    # Bob asks to become a contact; Alice accepts and the conversation opens.
    port = ws.property("port")
    connecting = asyncio.create_task(bob.node.connect_address(LOOPBACK, port, name="Alice"))
    prompts = ws.prompts_model
    await until(lambda: prompts.property("kind") == "contact_request")
    assert prompts.property("shortId") == bob.node.identity.short_id
    prompts.accept("Bob")
    alice_id = await connecting
    await until(
        lambda: ws.conversation_model is not None and ws.conversation_model.property("online")
    )
    conv = conversation(ws)
    assert conv.property("name") == "Bob"
    assert conv.property("trust") == "pinned"
    await until(lambda: not conv.property("loading"))

    # Chat both ways; the receipt makes Alice's message Delivered.
    assert conv.send("hello bob")
    await bob.next(HistoryChanged, lambda e: e.entry.text == "hello bob")
    await until(lambda: texts(conv) == [("hello bob", "Delivered")])
    await bob.node.send_chat(alice_id, "hi alice")
    await until(lambda: ("hi alice", "") in texts(conv))
    assert ws.strip.rows()[0].unread == 0  # type: ignore[attr-defined]  # selected and active

    # The safety numbers match on both sides.
    conv.loadSafetyNumber()
    await until(lambda: bool(conv.property("safetyNumber")))
    assert tuple(conv.property("safetyNumber")) == bob.node.safety_number(alice_id)

    # Bob offers a file; Alice accepts it into a folder of her choice.
    source = tmp_path / "notes.txt"
    source.write_bytes(b"quantum notes\n" * 1000)
    await bob.node.send_file(alice_id, source)
    await until(lambda: any(r.file_status == "offered" for r in conv.messages.rows()))
    offer = next(r for r in conv.messages.rows() if r.file_status == "offered")
    assert offer.file_state_text == "Wants to send you this file"
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    conv.acceptFileTo(offer.file_id, downloads.as_uri())
    await until(lambda: any(r.file_status == "complete" for r in conv.messages.rows()))
    done = next(r for r in conv.messages.rows() if r.file_status == "complete")
    received = await asyncio.to_thread(Path(done.file_path).read_bytes)
    assert received == source.read_bytes()  # a test fixture file
    await bob.next(
        HistoryChanged,
        lambda e: e.entry.file is not None and e.entry.file.status is FileStatus.COMPLETE,
    )

    # Lock: the workspace goes at once; Bob sees the session end.
    conv.setDraft("unsent draft")
    alice.lock()
    assert alice.property("workspace") is None
    await until(lambda: alice.property("phase") == "locked")
    ended = await bob.next(SessionEnded)
    assert ended.reason is not None
    assert ended.reason.label == "locked"

    # Unlock: history is back, the draft is not (drafts never outlive a lock).
    alice.unlock("wrong password")
    await until(lambda: alice.property("error") == "Wrong password.")
    alice.unlock(PASSWORD)
    await until(lambda: alice.property("phase") == "unlocked")
    again = conversation(workspace(alice))
    await until(lambda: not again.property("loading"))
    assert texts(again) == [("hello bob", "Delivered"), ("hi alice", "")]
    assert again.property("draft") == ""
    assert not again.property("online")

    # Bob only ever dialled Alice, so she knows no address for him (and mDNS is off here).
    again.connectSession()
    await until(lambda: again.property("banner") == "error")
    assert "no address known" in again.property("bannerText")
    # Bob reconnects (tests listen on a fresh port each unlock); a pinned contact is admitted
    # without asking.
    await bob.node.connect_address(LOOPBACK, workspace(alice).property("port"))
    await until(lambda: again.property("online"))
    assert again.property("banner") == ""
    assert workspace(alice).prompts_model.property("kind") == ""
