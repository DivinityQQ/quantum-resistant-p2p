"""The M4 gate: the canary leak test end to end, through the desktop app (DESIGN §15, UI_DESIGN §13.2).

Alice is the app: controller, bridge, services thread, node. Bob is a headless node. Both nodes'
providers record every secret they create; the test adds the identity seeds and the vault keys.
After a normal session (first contact, chat both ways, a PQ rekey), Alice opens the Inspector
and walks every view: every timeline row, frame, field and key node, copying what can be
copied. She runs the solo lab and saves its run, and tries to save the normal session (refused).
Then every view-model string of the Inspector, every clipboard text, every message the app
showed, every log record and every file in both data directories is searched for each secret
in raw, hex, base64 and base32 form. Chat text must not reach the logs. A lock leaves no view
model behind.

The same walk over a glass-box session MUST find its secrets in the Inspector's strings: that
proves the search can see what it is looking for.
"""

import asyncio
import logging
import os
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest
from PySide6.QtCore import QCoreApplication
from PySide6.QtGui import QGuiApplication

from qrp2p.core.crypto.provider import PlainProvider, RevealingProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.services.events import HistoryChanged
from qrp2p.services.node import Node
from qrp2p.ui.bridge import Bridge
from qrp2p.ui.host import ServiceHost
from qrp2p.ui.viewmodels.application import AppController
from qrp2p.ui.viewmodels.inspector import Inspector
from qrp2p.ui.viewmodels.workspace import Workspace
from tests.services.support import NodeHarness, until
from tests.services.test_canary_services import Recorder, forms, leaks, live_keys
from tests.ui.support import make_node

PASSWORD = "correct horse"
CHATS = ("canary through the app", "canary back to the app")


async def pumped(condition: Callable[[], bool], timeout: float = 15.0) -> None:  # noqa: ASYNC109
    """Wait for ``condition``, processing Qt events (deliveries are queued signals) meanwhile."""
    async with asyncio.timeout(timeout):
        while not condition():  # Qt events have no awaitable
            QCoreApplication.processEvents()
            await asyncio.sleep(0.005)


class App:
    """Alice's app, with her node kept for its live keys."""

    def __init__(self, directory: Path, recorder: Recorder) -> None:
        self.directory = directory
        self.node: Node | None = None

        def build() -> Node:
            node = make_node(directory, provider_factory=lambda: recording(recorder))()
            self.node = node
            return node

        self.bridge = Bridge(lambda post: ServiceHost(build, post, batch_interval=0.01))
        self.controller = AppController(self.bridge, data_dir=str(directory))
        self.bridge.start()

    @property
    def workspace(self) -> Workspace:
        ws = self.controller.property("workspace")
        assert isinstance(ws, Workspace)
        return ws


def recording(recorder: Recorder) -> RevealingProvider:
    return RevealingProvider(PlainProvider(os.urandom), recorder)


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
async def app(tmp_path: Path, qapp: QCoreApplication, recorder: Recorder) -> AsyncIterator[App]:
    del qapp
    alice = App(tmp_path / "alice", recorder)
    yield alice
    assert await asyncio.to_thread(alice.bridge.stop, 20.0)
    alice.controller.deleteLater()
    QCoreApplication.processEvents()


@pytest.fixture
async def bob(tmp_path: Path, recorder: Recorder) -> AsyncIterator[NodeHarness]:
    harness = await NodeHarness(
        tmp_path, "bob", provider_factory=lambda: recording(recorder)
    ).start()
    yield harness
    await harness.node.close()


def every_file(root: Path) -> tuple[list[Path], bytes]:
    """Every file in both data directories (vault.json, database, WAL, recordings, log)."""
    files = [p for p in root.rglob("*") if p.is_file()]
    return files, b"".join(p.read_bytes() for p in files)


def strings_of(inspector: Inspector) -> list[str]:
    """Every string the Inspector's view model holds for QML."""
    models = [
        inspector._timeline_model,
        inspector._frames,
        inspector._fields,
        inspector._nodes,
        inspector._edges,
        inspector._facts,
        inspector._sessions,
    ]
    found = [str(row) for model in models for row in model.rows()]
    for hexes in (inspector._hex, inspector._plaintext):
        found += [
            "".join(hexes.data(hexes.index(r, 0), role) or "" for role in (257, 259))
            for r in range(hexes.rowCount())
        ]
    for name in ("title", "subtitle", "frameTitle", "frameDetail", "error"):
        found.append(str(inspector.property(name)))
    return found


async def walk(inspector: Inspector) -> list[str]:
    """Open every view, select every row, frame, field and key; copy what can be copied."""
    clipboard = QGuiApplication.clipboard()
    seen: list[str] = []
    for view in ("timeline", "messages", "keys", "security"):
        inspector.setView(view)
        QCoreApplication.processEvents()
        seen += strings_of(inspector)
    for row in inspector._timeline_model.rows():
        inspector.selectRow(row.key)
        if row.kind == "group":
            inspector.toggleGroup(row.key)
    for frame in inspector._frames.rows():
        inspector.selectFrame(frame.ordinal)
        for field in inspector._fields.rows():
            inspector.selectField(field.key)
            clipboard.setText("")
            inspector.copyField(field.key)
            seen.append(clipboard.text())
        seen += strings_of(inspector)
    inspector.setView("keys")
    for node in inspector._nodes.rows():
        inspector.selectNode(node.key)
        clipboard.setText("")
        inspector.copyNodeValue(node.key)
        seen.append(clipboard.text())
    seen += strings_of(inspector)
    return seen


async def connected(app: App, bob: NodeHarness) -> bytes:
    """Bob asks Alice to be a contact; Alice accepts; returns Alice's contact ID at Bob."""
    await pumped(lambda: app.controller.property("phase") == "noVault")
    app.controller.createVault("Alice", PASSWORD, PASSWORD)
    await pumped(lambda: app.controller.property("phase") == "unlocked")
    ws = app.workspace
    connecting = asyncio.create_task(
        bob.node.connect_address("127.0.0.1", ws.property("port"), name="Alice")
    )
    prompts = ws.prompts_model
    await pumped(lambda: prompts.property("kind") == "contact_request")
    prompts.accept("Bob")
    alice_id = await connecting
    await pumped(
        lambda: ws.conversation_model is not None and ws.conversation_model.property("online")
    )
    return alice_id


async def inspected(ws: Workspace) -> Inspector:
    inspector = ws.inspector_model
    inspector.setOpen(True)
    await pumped(lambda: inspector.property("sessionId") >= 0 and not inspector.property("loading"))
    await pumped(lambda: len(inspector.trace_items) > 0)
    return inspector


async def test_no_secret_of_a_normal_session_reaches_the_app(  # noqa: PLR0915  # one story
    app: App, bob: NodeHarness, recorder: Recorder, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    shown: list[str] = []
    alice_id = await connected(app, bob)
    ws = app.workspace
    ws.noticePosted.connect(shown.append)
    lab = ws.lab_model
    lab.failed.connect(shown.append)
    lab.saved.connect(shown.append)
    conv = ws.conversation_model
    assert conv is not None
    conv.actionFailed.connect(shown.append)

    # A normal session: chat both ways and a PQ rekey (Bob initiated, so Bob rekeys).
    assert conv.send(CHATS[0])
    await bob.next(HistoryChanged, lambda e: e.entry.text == CHATS[0])
    await bob.node.send_chat(alice_id, CHATS[1])
    await pumped(lambda: any(r.text == CHATS[1] for r in conv.messages.rows()))
    bob.clock.advance(61)
    await bob.node.rekey(alice_id)
    session = bob.node.session_info(alice_id)
    assert session is not None
    await until(lambda: session.channel is not None and session.channel.epoch == 1)

    # The Inspector, every view and selection, every permitted copy.
    inspector = await inspected(ws)
    await pumped(lambda: any("rekey" in r.title for r in inspector._timeline_model.rows()))
    seen = await walk(inspector)
    assert len(seen) > 500  # the walk covered real content: frames, fields, keys, facts
    assert any("Reply" in s for s in seen)
    assert any("rekey_offer" in s for s in seen)
    assert sum(len(s) == 64 and s.isalnum() for s in seen) > 5  # copied 32-byte public fields
    inspector.saveRecording("must not exist")  # not glass-box: nothing is even asked
    shown.append(str(inspector.property("exposure")))

    # The lab, with a saved run; a normal session cannot be saved.
    lab.enter()
    await pumped(lambda: lab.property("active") and not lab.property("busy"))
    lab.run()
    await pumped(lambda: lab.property("phase") == "idle")
    lab.save("canary lab run")
    await pumped(lambda: any("canary lab run" in s for s in shown))

    assert app.node is not None
    bob_keys = live_keys(bob)
    alice_keys = [*app.node._identity.seeds]  # type: ignore[union-attr]
    vault = app.node._vault._open
    assert vault is not None
    alice_keys += [vault.kek, *vault.keys.values(), *vault.conv_keys.values()]
    secrets: list[Secret] = [*recorder.secrets, *bob_keys, *alice_keys]
    labels = {s.label for s in secrets}
    assert {"hs", "cs_0", "cs_1", "ap_I[0]", "identity.mldsa65", "vault.k_lab"} <= labels

    # A lock leaves no view model of the period behind.
    app.controller.lock()
    await pumped(lambda: app.controller.property("phase") == "locked")
    assert app.controller.property("workspace") is None

    files, binary = await asyncio.to_thread(every_file, tmp_path)
    assert any(p.suffix == ".qrlab" for p in files)  # the lab run, sealed
    text = "\n".join([*seen, *shown, *(r.getMessage() for r in caplog.records)])
    assert leaks(secrets, binary, text) == []
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert not any(chat in log_text for chat in CHATS)
    assert not any(chat in "\n".join(seen) for chat in CHATS)  # sealed records stay sealed


async def test_a_glass_box_sessions_secrets_are_found_by_the_same_search(
    app: App, bob: NodeHarness, recorder: Recorder
) -> None:
    alice_id = await connected(app, bob)
    ws = app.workspace
    conv = ws.conversation_model
    assert conv is not None
    await bob.node.disconnect(alice_id)
    await pumped(lambda: not conv.property("online"))
    # Bob dialled Alice, so Bob asks for glass-box; Alice consents in the app.
    connecting = asyncio.create_task(bob.node.connect_contact(alice_id, glass_box=True))
    prompts = ws.prompts_model
    await pumped(lambda: prompts.property("kind") == "glass_box")
    prompts.accept("")
    await connecting
    await pumped(lambda: conv.property("glassBox"))
    await bob.node.send_chat(alice_id, CHATS[1])
    await pumped(lambda: any(r.text == CHATS[1] for r in conv.messages.rows()))
    inspector = await inspected(ws)
    assert inspector.property("exposure") == "glass_box"
    seen = await walk(inspector)
    text = "\n".join(seen).lower()
    found = [s.label for s in recorder.secrets if any(f.lower() in text for f in forms(s.reveal()))]
    assert {"hs", "cs_0", "ap_I[0]"} <= set(found)  # the search sees what it looks for
