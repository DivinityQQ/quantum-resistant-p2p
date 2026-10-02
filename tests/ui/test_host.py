"""The services host: generations, atomic snapshots, stale requests, ordering (UI_DESIGN §11.2)."""

import asyncio
import dataclasses
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from qrp2p.services.events import AdmissionPrompt, SessionOpened
from qrp2p.services.node import Node, NodeError
from qrp2p.ui import ops
from qrp2p.ui.host import CLOSED, IN_USE, STALE, ServiceHost
from qrp2p.ui.snapshots import (
    Batch,
    ConnectStage,
    ContactChanged,
    FileSnap,
    Lifecycle,
    MessageChanged,
    MessageSnap,
    NetworkSnap,
    PromptClosed,
    PromptOpened,
    Reply,
    SessionEnded,
    SettingsSnap,
)
from tests.services.support import LOOPBACK, NodeHarness, until
from tests.ui.support import HostHarness

PASSWORD = "correct horse"


@pytest.fixture
async def alice(tmp_path: Path) -> AsyncIterator[HostHarness]:
    harness = HostHarness(tmp_path / "alice")
    harness.host.start()
    await harness.lifecycle("no_vault")
    yield harness
    assert await asyncio.to_thread(harness.host.stop)


@pytest.fixture
async def bob(tmp_path: Path) -> AsyncIterator[NodeHarness]:
    harness = await NodeHarness(tmp_path, "bob").start()
    yield harness
    await harness.node.close()


async def unlocked(alice: HostHarness) -> Lifecycle:
    await alice.ok(ops.create_vault(PASSWORD, "Alice"), scoped=False)
    return await alice.lifecycle("unlocked")


async def contact_request(alice: HostHarness, bob: NodeHarness) -> tuple[asyncio.Task[bytes], int]:
    """Bob connects to Alice's host; returns his connect task and Alice's prompt ID."""
    network = await alice.ok(ops.network())
    assert isinstance(network, NetworkSnap)
    mark = alice.mark()
    connecting = asyncio.create_task(bob.node.connect_address(LOOPBACK, network.port, name="Alice"))
    opened = await alice.update(PromptOpened, after=mark)
    return connecting, opened.prompt.prompt_id


async def befriended(alice: HostHarness, bob: NodeHarness) -> str:
    """Bob becomes Alice's contact with an open session; returns his contact ID at Alice."""
    connecting, prompt_id = await contact_request(alice, bob)
    mark = alice.mark()
    outcome = await alice.ok(ops.answer_prompt(prompt_id, accept=True, name="Bob"))
    assert outcome == "accepted"
    await connecting
    changed = await alice.update(
        ContactChanged, lambda u: u.contact.session is not None, after=mark
    )
    return changed.contact.contact_id


# -- life cycle -------------------------------------------------------------------------------------


async def test_each_state_change_starts_a_generation(alice: HostHarness) -> None:
    first = alice.lifecycles()[-1]
    assert first.workspace is None
    opened = await unlocked(alice)
    assert opened.gen > first.gen
    assert opened.workspace is not None
    await alice.ok(ops.lock(), scoped=False)
    locked = await alice.lifecycle("locked")
    assert locked.gen > opened.gen
    assert locked.workspace is None
    await alice.ok(ops.unlock(PASSWORD), scoped=False)
    again = await alice.lifecycle("unlocked")
    assert again.gen > locked.gen
    gens = [d.gen for d in alice.lifecycles()]
    assert gens == sorted(set(gens))


async def test_the_unlocked_snapshot_is_complete(alice: HostHarness, bob: NodeHarness) -> None:
    opened = await unlocked(alice)
    workspace = opened.workspace
    assert workspace is not None
    assert workspace.contacts == ()
    assert workspace.settings.display_name == "Alice"
    assert workspace.network.port > 0
    assert workspace.identity.bundle_bytes == 4577
    assert sum(size for _, size in workspace.identity.parts) == 4577 - 1
    await befriended(alice, bob)
    await alice.ok(ops.lock(), scoped=False)
    await alice.lifecycle("locked")
    await alice.ok(ops.unlock(PASSWORD), scoped=False)
    again = (await alice.lifecycle("unlocked")).workspace
    assert again is not None
    assert [c.name for c in again.contacts] == ["Bob"]
    assert again.contacts[0].session is None  # the lock closed it
    assert again.contacts[0].short_id == bob.node.identity.short_id


@pytest.mark.usefixtures("alice")
async def test_another_process_on_the_directory(tmp_path: Path) -> None:
    second = HostHarness(tmp_path / "alice")
    second.host.start()
    try:
        state = await second.lifecycle(IN_USE)
        assert state.workspace is None
    finally:
        assert await asyncio.to_thread(second.host.stop)


async def test_stop_releases_the_directory(tmp_path: Path) -> None:
    first = HostHarness(tmp_path / "carol")
    first.host.start()
    await first.lifecycle("no_vault")
    await unlocked(first)
    assert await asyncio.to_thread(first.host.stop)
    assert (await first.call(ops.lock(), scoped=False)).error == CLOSED
    second = HostHarness(tmp_path / "carol")
    second.host.start()
    try:
        await second.lifecycle("locked")
    finally:
        assert await asyncio.to_thread(second.host.stop)


# -- requests ---------------------------------------------------------------------------------------


async def test_a_request_of_an_earlier_generation_is_refused(
    alice: HostHarness, bob: NodeHarness
) -> None:
    await unlocked(alice)
    connecting, old_prompt = await contact_request(alice, bob)
    old_gen = alice.gen
    await alice.ok(ops.lock(), scoped=False)
    with pytest.raises(NodeError):  # the lock ended Bob's handshake
        await connecting
    await alice.ok(ops.unlock(PASSWORD), scoped=False)
    await alice.lifecycle("unlocked")
    # The node numbers prompts afresh after unlock: Bob's new request may reuse the old ID.
    mark = alice.mark()
    connecting, new_prompt = await contact_request(alice, bob)
    assert new_prompt == old_prompt
    reply = await alice.call(ops.answer_prompt(old_prompt, accept=True), gen=old_gen)
    assert reply.error == STALE
    assert not connecting.done()
    assert not [u for u in alice.updates(mark) if isinstance(u, PromptClosed)]
    assert await alice.ok(ops.answer_prompt(new_prompt, accept=False)) == "declined"
    with pytest.raises(NodeError, match="declined"):
        await connecting


async def test_an_unscoped_request_runs_in_any_generation(alice: HostHarness) -> None:
    await unlocked(alice)
    reply = await alice.call(ops.lock(), gen=0, scoped=False)
    assert reply.error is None
    await alice.lifecycle("locked")


async def test_a_reply_follows_the_updates_before_it(alice: HostHarness, bob: NodeHarness) -> None:
    await unlocked(alice)
    bob_id = await befriended(alice, bob)
    request_id = alice.submit(ops.send_chat(bob_id, "hello"))
    await alice.reply(request_id)
    deliveries = alice.snapshot()
    reply_at = next(
        i for i, d in enumerate(deliveries) if isinstance(d, Reply) and d.request_id == request_id
    )
    added = [
        i
        for i, d in enumerate(deliveries)
        if isinstance(d, Batch)
        for u in d.updates
        if isinstance(u, MessageChanged) and u.added and u.message.text == "hello"
    ]
    assert added
    assert added[0] < reply_at


async def test_failures_reach_the_requester_as_text(alice: HostHarness) -> None:
    reply = await alice.call(ops.unlock("wrong"), scoped=False)
    assert reply.error is not None  # no vault yet
    await unlocked(alice)
    await alice.ok(ops.lock(), scoped=False)
    await alice.lifecycle("locked")
    wrong = await alice.call(ops.unlock("wrong"), scoped=False)
    assert wrong.error is not None
    assert wrong.error.kind == "wrong_password"
    await alice.ok(ops.unlock(PASSWORD), scoped=False)
    await alice.lifecycle("unlocked")
    unknown = await alice.call(ops.connect_contact("00" * 16, glass_box=False))
    assert unknown.error is not None
    assert (unknown.error.kind, unknown.error.message) == ("node", "no such contact")
    malformed = await alice.call(ops.disconnect("not hex"))
    assert malformed.error is not None
    assert malformed.error.kind == "value"

    async def broken(_: Node) -> None:
        msg = "a bug"
        raise RuntimeError(msg)

    internal = await alice.call(broken)
    assert internal.error is not None
    assert internal.error.kind == "internal"
    assert "a bug" not in internal.error.message  # details go to the log, not the user


async def test_every_delivery_is_an_immutable_value(alice: HostHarness, bob: NodeHarness) -> None:
    await unlocked(alice)
    bob_id = await befriended(alice, bob)
    await alice.ok(ops.send_chat(bob_id, "hi"))
    await alice.ok(ops.safety_number(bob_id))
    await alice.ok(ops.history(bob_id))
    await alice.ok(ops.lock(), scoped=False)
    await alice.lifecycle("locked")

    def check(value: object) -> None:
        if value is None or isinstance(value, str | int | float | bool):
            return
        if isinstance(value, tuple):
            for item in value:
                check(item)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                check(key)
                check(item)
            return
        assert dataclasses.is_dataclass(value), type(value)
        assert type(value).__dataclass_params__.frozen, type(value)  # type: ignore[attr-defined]
        for field in dataclasses.fields(value):
            check(getattr(value, field.name))

    for delivery in alice.snapshot():
        check(delivery)


# -- updates ----------------------------------------------------------------------------------------


async def test_session_end_names_its_reason(alice: HostHarness, bob: NodeHarness) -> None:
    await unlocked(alice)
    bob_id = await befriended(alice, bob)
    alice_id = (await bob.next(SessionOpened)).contact_id
    await bob.node.disconnect(alice_id)
    ended = await alice.update(SessionEnded)
    assert ended == SessionEnded(bob_id, "normal", by_peer=True)
    offline = await alice.update(ContactChanged, lambda u: u.contact.session is None)
    assert offline.contact.contact_id == bob_id


async def test_waiting_for_admission_is_reported(alice: HostHarness, bob: NodeHarness) -> None:
    await unlocked(alice)
    request_id = alice.submit(ops.connect_address(LOOPBACK, bob.port, "Bob", ""))
    prompt = await bob.next(AdmissionPrompt)
    stage = await alice.update(ConnectStage)
    assert stage == ConnectStage("", f"{LOOPBACK}:{bob.port}", "waiting_for_admission")
    await bob.node.answer_prompt(prompt.prompt_id, accept=True, name="Alice")
    contact_id = (await alice.reply(request_id)).value
    assert isinstance(contact_id, str)
    assert len(contact_id) == 32


async def test_peer_text_is_made_safe_before_it_crosses(
    alice: HostHarness, bob: NodeHarness
) -> None:
    await unlocked(alice)
    bob_id = await befriended(alice, bob)
    alice_id = (await bob.next(SessionOpened)).contact_id
    await bob.node.send_chat(alice_id, "line one\nline two \u202eevil\x1b[2J")
    received = await alice.update(MessageChanged, lambda u: u.message.direction == "in")
    assert received.contact_id == bob_id
    assert received.message.text == "line one\nline two \ufffdevil\ufffd[2J"


async def test_transfer_progress_is_coalesced(tmp_path: Path) -> None:
    posted: list[object] = []
    host = ServiceHost(lambda: Node(tmp_path), posted.append, batch_interval=3600)

    def progress(entry: str, done: int | None, status: str = "transferring") -> MessageChanged:
        file = FileSnap(
            file_id=entry, name="f", size=10, status=status, path="", reason="", transferred=done
        )
        message = MessageSnap(
            entry_id=entry,
            kind="file",
            direction="out",
            time=0.0,
            status="received",
            text="",
            glass_box=False,
            file=file,
        )
        return MessageChanged("c", message, added=False)

    updates = [
        progress("a", 1),
        progress("b", 1),
        progress("a", 2),
        progress("a", None, "complete"),  # a status change is never dropped or moved
        progress("a", 3),
        progress("a", 4),
    ]
    for update in updates:
        host._queue(update)
    host._flush()
    assert posted == [Batch(0, (updates[2], updates[1], updates[3], updates[5]))]


async def test_updates_wait_for_the_batch_interval(tmp_path: Path) -> None:
    posted: list[object] = []
    host = ServiceHost(lambda: Node(tmp_path), posted.append, batch_interval=0.05)
    chats = [
        MessageChanged(
            "c",
            MessageSnap(
                entry_id=entry,
                kind="chat",
                direction="in",
                time=0.0,
                status="received",
                text="x",
                glass_box=False,
                file=None,
            ),
            added=True,
        )
        for entry in ("e1", "e2")
    ]
    for chat in chats:
        host._queue(chat)
    assert posted == []
    await until(lambda: bool(posted))
    assert posted == [Batch(0, tuple(chats))]


@pytest.mark.parametrize(
    ("name", "value", "stored"),
    [
        ("max_file_size", 4294967296.0, 4294967296),  # QML numbers are doubles
        ("auto_lock_minutes", 15.0, 15),
        ("auto_lock_minutes", 0, 0),
        ("text_scale", 130.0, 130),
        ("appearance", "dark", "dark"),
        ("announce_name", False, False),
        ("default_profile", "PQ-CNSA-1", "PQ-CNSA-1"),
        ("default_retention", "30d", "30d"),
    ],
)
async def test_settings_accept_values_as_qml_sends_them(
    alice: HostHarness, name: str, value: object, stored: object
) -> None:
    await unlocked(alice)
    settings = await alice.ok(ops.update_setting(name, value))
    assert getattr(settings, name) == stored


async def test_the_downloads_folder_is_custom_or_the_os_one(
    alice: HostHarness, tmp_path: Path
) -> None:
    await unlocked(alice)
    custom = await alice.ok(ops.update_setting("downloads_dir", str(tmp_path)))
    assert isinstance(custom, SettingsSnap)
    assert (custom.downloads_dir, custom.downloads_custom) == (str(tmp_path), True)
    default = await alice.ok(ops.update_setting("downloads_dir", ""))
    assert isinstance(default, SettingsSnap)
    assert not default.downloads_custom
    assert default.downloads_dir  # the OS downloads folder, shown as the one in use


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("auto_lock_minutes", 1.5),
        ("auto_lock_minutes", -1),
        ("announce_name", "false"),  # bool("false") would be True
        ("reduced_motion", 1),
        ("text_scale", 120),
        ("port", 70000),
        ("max_file_size", 0),
        ("downloads_dir", "relative/folder"),
        ("default_profile", "LAB-CLASSICAL"),  # never reachable from real-session controls
        ("appearance", "neon"),
        ("no_such_setting", 1),
    ],
)
async def test_settings_refuse_invalid_values(alice: HostHarness, name: str, value: object) -> None:
    await unlocked(alice)
    reply = await alice.call(ops.update_setting(name, value))
    assert reply.error is not None
    assert reply.error.kind in {"value", "node"}
