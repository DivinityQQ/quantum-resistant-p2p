"""Two whole nodes over loopback: contacts, admission, chat, trust, lock (DESIGN §5, §7.6, §10)."""

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from qrp2p.core.crypto.profiles import PQ_CNSA_1
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.services import node as node_module
from qrp2p.services import session_manager as session_manager_module
from qrp2p.services import transport
from qrp2p.services.admission import PromptKind
from qrp2p.services.discovery import SERVICE_TYPE, NearbyPeer
from qrp2p.services.events import (
    AdmissionPrompt,
    ConnectFailed,
    ConnectProgress,
    HistoryChanged,
    KeyMismatchDetected,
    NodeState,
    PromptClosed,
    PromptOutcome,
    SessionEnded,
    SessionOpened,
    StateChanged,
)
from qrp2p.services.models import (
    Direction,
    FileInfo,
    FileStatus,
    HistoryEntry,
    MessageKind,
    MessageStatus,
    Retention,
    TrustState,
)
from qrp2p.services.node import NodeError, NotConnectedError, profile_by_name
from qrp2p.services.transport import ConnectFailed as TransportConnectFailed
from qrp2p.services.transport import FrameStream
from qrp2p.services.vault import WrongPasswordError
from tests.services.support import LOOPBACK, NodeHarness, befriend, until
from tests.services.test_vault import MemoryKeychain


@pytest.fixture
async def nodes(tmp_path: Path) -> AsyncIterator[tuple[NodeHarness, NodeHarness]]:
    alice = await NodeHarness(tmp_path, "alice").start()
    bob = await NodeHarness(tmp_path, "bob").start()
    yield alice, bob
    await alice.node.close()
    await bob.node.close()


async def test_first_contact_by_address(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    bob_contact = alice.node.contact(bob_id)
    alice_contact = bob.node.contact(alice_id)
    assert bob_contact.bundle == bob.node.identity
    assert alice_contact.bundle == alice.node.identity
    assert bob_contact.name == "Bob"
    assert alice_contact.name == "Alice"
    assert bob_contact.trust is alice_contact.trust is TrustState.PINNED
    assert bob_contact.address == (LOOPBACK, bob.port)
    prompt = bob.of(AdmissionPrompt)[0]
    assert prompt.kind is PromptKind.CONTACT_REQUEST
    assert prompt.short_id == alice.node.identity.short_id
    assert alice.node.safety_number(bob_id) == bob.node.safety_number(alice_id)


async def test_chat_is_stored_and_delivered(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    sent = await alice.node.send_chat(bob_id, "hello Bob")
    received = await bob.next(HistoryChanged, lambda e: e.added and e.entry.text == "hello Bob")
    assert received.contact_id == alice_id
    assert received.entry.status is MessageStatus.RECEIVED
    await alice.next(
        HistoryChanged,
        lambda e: e.entry.entry_id == sent.entry_id and e.entry.status is MessageStatus.DELIVERED,
    )
    statuses = [
        e.entry.status for e in alice.of(HistoryChanged) if e.entry.entry_id == sent.entry_id
    ]
    assert statuses == [MessageStatus.SENDING, MessageStatus.SENT, MessageStatus.DELIVERED]
    history = await alice.node.history(bob_id)
    assert [(e.text, e.status) for e in history] == [("hello Bob", MessageStatus.DELIVERED)]


async def test_history_survives_lock_and_unlock(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.send_chat(bob_id, "kept")
    await bob.next(HistoryChanged, lambda e: e.entry.text == "kept")
    await alice.node.lock()
    with pytest.raises(WrongPasswordError):
        await alice.node.unlock("wrong")
    await alice.node.unlock("pw")
    assert [e.text for e in await alice.node.history(bob_id)] == ["kept"]


async def test_pinned_contact_is_admitted_without_a_prompt(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await bob.next(SessionEnded)
    await until(lambda: not alice.node.is_online(bob_id))
    await alice.node.connect_contact(bob_id)
    assert len(bob.of(AdmissionPrompt)) == 1  # only the first contact request
    await until(lambda: bob.node.is_online(alice_id))


async def test_profile_policy(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not bob.node.is_online(alice_id))
    await bob.node.update_contact(alice_id, profile_id=PQ_CNSA_1.id)
    with pytest.raises(NodeError, match="profile_policy"):
        await alice.node.connect_contact(bob_id)  # Alice still offers HYBRID-1
    failed = await alice.next(ConnectFailed)
    assert failed.admit_reason is AdmitReason.PROFILE_POLICY
    await alice.node.update_contact(bob_id, profile_id=profile_by_name("pq-cnsa-1").id)
    await alice.node.connect_contact(bob_id)
    session = alice.node.session_info(bob_id)
    assert session is not None
    assert session.profile is PQ_CNSA_1


async def test_blocked_contact_declined(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await bob.node.set_trust(alice_id, TrustState.BLOCKED)
    await alice.next(SessionEnded)  # blocking closes the open session
    await until(lambda: not alice.node.is_online(bob_id))
    with pytest.raises(NodeError, match="declined"):
        await alice.node.connect_contact(bob_id)
    assert len(bob.of(AdmissionPrompt)) == 1  # no prompt for a blocked contact


async def test_declined_contact_request(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port))
    prompt = await bob.next(AdmissionPrompt)
    outcome = await bob.node.answer_prompt(prompt.prompt_id, accept=False)
    assert outcome is PromptOutcome.DECLINED
    with pytest.raises(NodeError, match="declined"):
        await connecting
    assert alice.node.contacts() == []
    assert bob.node.contacts() == []
    closed = await bob.next(PromptClosed)
    assert closed == PromptClosed(prompt.prompt_id, PromptOutcome.DECLINED)


async def test_accepted_contact_request_reports_its_outcome(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = nodes
    await befriend(alice, bob)
    closed = await bob.next(PromptClosed)
    assert closed.outcome is PromptOutcome.ACCEPTED


async def test_initiator_hears_that_the_peer_decides(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = nodes
    connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port))
    prompt = await bob.next(AdmissionPrompt)
    progress = await alice.next(ConnectProgress)
    assert progress == ConnectProgress(f"{LOOPBACK}:{bob.port}", None, "waiting_for_admission")
    await bob.node.answer_prompt(prompt.prompt_id, accept=True, name="Alice")
    bob_id = await connecting
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id))
    # A pinned contact is admitted at once: the progress names the contact.
    await alice.node.connect_contact(bob_id)
    progress = await alice.next(ConnectProgress, lambda e: e.contact_id is not None)
    assert progress.contact_id == bob_id
    assert len(alice.of(ConnectProgress)) == 2


async def test_acceptance_reports_busy_when_capacity_ran_out(
    tmp_path: Path, nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    monkeypatch.setattr(session_manager_module, "MAX_LIVE_SESSIONS", 1)
    carol = await NodeHarness(tmp_path, "carol").start()
    try:
        connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port))
        prompt = await bob.next(AdmissionPrompt)
        # Carol takes Bob's only live slot while Alice's prompt is open.
        carol_connecting = asyncio.create_task(carol.node.connect_address(LOOPBACK, bob.port))
        carol_prompt = await bob.next(AdmissionPrompt, lambda e: e.prompt_id != prompt.prompt_id)
        await bob.node.answer_prompt(carol_prompt.prompt_id, accept=True, name="Carol")
        await carol_connecting
        outcome = await bob.node.answer_prompt(prompt.prompt_id, accept=True, name="Alice")
        assert outcome is PromptOutcome.BUSY
        with pytest.raises(NodeError, match="busy"):
            await connecting
        closed = await bob.next(PromptClosed, lambda e: e.prompt_id == prompt.prompt_id)
        assert closed.outcome is PromptOutcome.BUSY
        # The user accepted the contact; only the session was refused.
        assert [c.name for c in bob.node.contacts()] == ["Alice", "Carol"]
    finally:
        await carol.node.close()


async def test_acceptance_reports_an_initiator_that_left(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port))
    prompt = await bob.next(AdmissionPrompt)
    real_new_contact = bob.node._new_contact
    alice_manager, bob_manager = alice.node._manager, bob.node._manager
    assert alice_manager is not None
    assert bob_manager is not None

    async def leave_while_saving(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        for session in list(alice_manager.sessions()):  # Alice gives up while Bob saves
            session.close()
        await until(lambda: not any(s.awaiting_admission for s in bob_manager.sessions()))
        return await real_new_contact(*args, **kwargs)

    monkeypatch.setattr(bob.node, "_new_contact", leave_while_saving)
    outcome = await bob.node.answer_prompt(prompt.prompt_id, accept=True, name="Alice")
    assert outcome is PromptOutcome.GONE
    assert [c.name for c in bob.node.contacts()] == ["Alice"]
    with pytest.raises(NodeError):
        await connecting


async def test_unanswered_prompt_expires(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port))
    prompt = await bob.next(AdmissionPrompt)
    bob.clock.advance(61.0)
    closed = await bob.next(PromptClosed, lambda e: e.prompt_id == prompt.prompt_id)
    assert closed.outcome is PromptOutcome.EXPIRED
    with pytest.raises(NodeError, match="timeout"):
        await connecting
    with pytest.raises(NodeError):
        await bob.node.answer_prompt(prompt.prompt_id, accept=True)


async def test_glass_box_consent(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not bob.node.is_online(alice_id))
    connecting = asyncio.create_task(alice.node.connect_contact(bob_id, glass_box=True))
    prompt = await bob.next(AdmissionPrompt, lambda e: e.kind is PromptKind.GLASS_BOX)
    assert prompt.contact_id == alice_id
    assert await bob.node.answer_prompt(prompt.prompt_id, accept=True) is PromptOutcome.GLASS_BOX
    await connecting
    opened = await alice.next(SessionOpened, lambda e: e.glass_box)
    assert opened.contact_id == bob_id
    entry = await alice.node.send_chat(bob_id, "visible")
    assert entry.glass_box
    received = await bob.next(HistoryChanged, lambda e: e.entry.text == "visible")
    assert received.entry.glass_box


async def test_declined_glass_box_gives_a_normal_session_and_rate_limits(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not bob.node.is_online(alice_id))
    connecting = asyncio.create_task(alice.node.connect_contact(bob_id, glass_box=True))
    prompt = await bob.next(AdmissionPrompt, lambda e: e.kind is PromptKind.GLASS_BOX)
    assert await bob.node.answer_prompt(prompt.prompt_id, accept=False) is PromptOutcome.NORMAL
    await connecting
    session = alice.node.session_info(bob_id)
    assert session is not None
    assert not session.glass_box
    await alice.node.disconnect(bob_id)
    await until(lambda: not bob.node.is_online(alice_id))
    # Within a minute of the last prompt: no prompt, a normal session.
    await alice.node.connect_contact(bob_id, glass_box=True)
    glass_prompts = [p for p in bob.of(AdmissionPrompt) if p.kind is PromptKind.GLASS_BOX]
    assert len(glass_prompts) == 1


async def test_key_mismatch_and_repin(
    tmp_path: Path, nodes: tuple[NodeHarness, NodeHarness]
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id))
    impostor = await NodeHarness(tmp_path, "mallory").start()
    try:
        # Bob's address now leads to Mallory (a spoofed mDNS record would do the same).
        old = alice.node.contact(bob_id)
        alice.node._contacts[bob_id] = replace(old, address=(LOOPBACK, impostor.port))
        with pytest.raises(NodeError, match="pin_mismatch"):
            await alice.node.connect_contact(bob_id)
        mismatch = await alice.next(KeyMismatchDetected)
        assert mismatch.expected_short_id == bob.node.identity.short_id
        assert mismatch.actual_short_id == impostor.node.identity.short_id
        assert mismatch.expected_peer_id == bob.node.identity.peer_id
        assert mismatch.actual_peer_id == impostor.node.identity.peer_id
        assert impostor.of(AdmissionPrompt) == []  # Alice never revealed herself
        await alice.node.resolve_mismatch(mismatch.mismatch_id, repin=True)
        contact = alice.node.contact(bob_id)
        assert contact.bundle == impostor.node.identity
        assert contact.trust is TrustState.PINNED
        history = await alice.node.history(bob_id)
        assert history[-1].kind is MessageKind.IDENTITY_CHANGED
    finally:
        await impostor.node.close()


async def test_lock_closes_sessions(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    _, alice_id = await befriend(alice, bob)
    await alice.node.lock()
    ended = await bob.next(SessionEnded)
    assert ended.contact_id == alice_id
    assert ended.reason is CloseReason.LOCKED
    assert ended.by_peer
    assert alice.of(StateChanged)[-1].state is NodeState.LOCKED
    with pytest.raises(NodeError, match="locked"):
        alice.node.contacts()


async def test_auto_lock(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, _ = nodes
    await alice.node.update_settings(auto_lock_minutes=1)
    alice.node.check_auto_lock()
    assert alice.node.state is NodeState.UNLOCKED
    alice.clock.advance(61)
    alice.node.check_auto_lock()
    await until(lambda: alice.node.state is NodeState.LOCKED)


async def test_sending_needs_a_session(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id))
    with pytest.raises(NotConnectedError):
        await alice.node.send_chat(bob_id, "nobody listens")


async def test_unreachable_address(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    port = bob.port
    await bob.node.lock()  # stops listening
    with pytest.raises(NodeError, match="reach"):
        await alice.node.connect_address(LOOPBACK, port)
    assert alice.of(ConnectFailed)


async def test_rekey_through_the_node(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    with pytest.raises(NodeError, match="opened the session"):
        await bob.node.rekey(alice_id)
    alice.clock.advance(61)
    bob.clock.advance(61)
    await alice.node.rekey(bob_id)
    session = alice.node.session_info(bob_id)
    assert session is not None
    await until(lambda: session.channel is not None and session.channel.epoch == 1)
    await alice.node.send_chat(bob_id, "after rekey")
    await bob.next(HistoryChanged, lambda e: e.entry.text == "after rekey")


async def test_contact_settings_and_retention(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    with pytest.raises(NodeError, match="verified"):
        await alice.node.update_contact(bob_id, auto_accept_files=True)
    await alice.node.set_trust(bob_id, TrustState.VERIFIED)
    await alice.node.update_contact(bob_id, auto_accept_files=True, auto_accept_limit=10)
    await alice.node.set_trust(bob_id, TrustState.PINNED)
    assert not alice.node.contact(bob_id).auto_accept_files
    await alice.node.update_contact(bob_id, retention=Retention.SESSION, name="B.")
    await alice.node.send_chat(bob_id, "gone at lock")
    await alice.node.lock()
    await alice.node.unlock("pw")
    assert await alice.node.history(bob_id) == []
    assert alice.node.contact(bob_id).name == "B."
    with pytest.raises(NodeError):
        await alice.node.update_contact(bob_id, trust=TrustState.VERIFIED)


async def test_delete_conversation_and_contact(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.send_chat(bob_id, "to be deleted")
    await alice.node.delete_conversation(bob_id)
    assert await alice.node.history(bob_id) == []
    await alice.node.delete_contact(bob_id)
    assert alice.node.contacts() == []


async def test_change_password(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, _ = nodes
    await alice.node.change_password("pw", "better password")
    await alice.node.lock()
    with pytest.raises(WrongPasswordError):
        await alice.node.unlock("pw")
    await alice.node.unlock("better password")


async def test_rotation_storage_lock_also_locks_node(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    _, alice_id = await befriend(alice, bob)

    def uncertain_commit(*_: object) -> None:
        alice.node._vault.lock()  # the vault rejects further use after an uncertain commit
        msg = "injected commit failure"
        raise sqlite3.OperationalError(msg)

    monkeypatch.setattr(alice.node._vault, "_rekey_database", uncertain_commit)
    with pytest.raises(sqlite3.OperationalError, match="injected commit failure"):
        await alice.node.change_password("pw", "new")
    assert alice.node.state is NodeState.LOCKED
    assert alice.node._identity is None
    await until(lambda: bob.node.session_info(alice_id) is None)
    await alice.node.unlock("pw")


async def test_a_second_node_on_the_same_directory_is_refused(tmp_path: Path) -> None:
    from qrp2p.services.vault import VaultInUseError  # noqa: PLC0415

    first = await NodeHarness(tmp_path, "solo").start()
    second = NodeHarness(tmp_path, "solo")
    try:
        with pytest.raises(VaultInUseError):
            await second.node.open()
    finally:
        await first.node.close()
        await second.node.close()


async def test_connecting_both_ways_at_once_keeps_one_session(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    """Alice dials Bob's address (no pin) while Bob dials his contact Alice."""
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not bob.node.is_online(alice_id))
    # Bob learns where Alice listens (from mDNS in real life).
    bob.node._contacts[alice_id] = replace(
        bob.node.contact(alice_id), address=(LOOPBACK, alice.port)
    )
    alice.events.clear()
    bob.events.clear()
    results = await asyncio.gather(
        alice.node.connect_address(LOOPBACK, bob.port), bob.node.connect_contact(alice_id)
    )
    assert results[0] == bob_id
    await until(lambda: alice.node.is_online(bob_id) and bob.node.is_online(alice_id))
    await asyncio.sleep(0.2)  # the loser has closed on both sides by now
    a = alice.node.session_info(bob_id)
    b = bob.node.session_info(alice_id)
    assert a is not None
    assert b is not None
    assert a.channel is not None
    assert b.channel is not None
    assert a.channel._epoch.exporter == b.channel._epoch.exporter
    for harness in (alice, bob):
        assert harness.of(ConnectFailed) == []
        assert harness.of(SessionEnded) == []  # the loser was replaced, nobody disconnected
    await alice.node.send_chat(bob_id, "one session")
    await bob.next(HistoryChanged, lambda e: e.entry.text == "one session")


async def test_device_unlock_through_the_node(tmp_path: Path) -> None:
    keychain = MemoryKeychain()
    harness = NodeHarness(tmp_path, "solo", keychain=lambda: keychain)
    await harness.start()
    try:
        assert not await harness.node.device_unlock_available()
        await harness.node.set_device_unlock(enabled=True)
        assert await harness.node.device_unlock_enabled()
        await harness.node.change_password("pw", "new password")  # keeps device unlock
        await harness.node.lock()
        assert await harness.node.device_unlock_available()
        await harness.node.unlock_with_device()
        assert harness.node.state is NodeState.UNLOCKED
        await harness.node.set_device_unlock(enabled=False)
        await harness.node.lock()
        assert not await harness.node.device_unlock_available()
        with pytest.raises(WrongPasswordError):
            await harness.node.unlock_with_device()
        await harness.node.unlock("new password")
    finally:
        await harness.node.close()


async def test_expired_history_is_purged_while_running(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.update_contact(bob_id, retention=Retention.DAYS_30)
    await alice.node.send_chat(bob_id, "old news")
    alice.wall.advance(31 * 86_400)
    await alice.node.send_chat(bob_id, "fresh")
    monkeypatch.setattr(node_module, "RETENTION_CHECK", 0.01)
    alice.node._timers.append(asyncio.create_task(alice.node._retention_loop()))
    await until_async(lambda: history_texts(alice, bob_id), ["fresh"])


async def history_texts(harness: NodeHarness, contact_id: bytes) -> list[str]:
    return [e.text for e in await harness.node.history(contact_id)]


async def until_async[T](read: Callable[[], Awaitable[T]], expected: T) -> None:
    async with asyncio.timeout(10):
        while await read() != expected:  # noqa: ASYNC110  # polls the vault
            await asyncio.sleep(0.01)


# --- found on the LAN test --------------------------------------------------------------------------


def announced(harness: NodeHarness, *addresses: str) -> NearbyPeer:
    """What mDNS would show for ``harness``."""
    bundle = harness.node.identity
    label = f"{harness.name.title()} ({bundle.short_id})"
    return NearbyPeer(
        instance=f"{label}.{SERVICE_TYPE}",
        label=label,
        id_hint=bundle.peer_id[:8],
        profiles=1,
        addresses=addresses,
        port=harness.port,
    )


def record_dials(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    dialled: list[str] = []

    async def open_stream(host: str, port: int) -> FrameStream:
        dialled.append(host)
        return await transport.open_stream(host, port)

    monkeypatch.setattr(session_manager_module, "open_stream", open_stream)
    return dialled


async def test_first_contact_through_mdns(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    connecting = asyncio.create_task(alice.node.connect_nearby(announced(bob, LOOPBACK)))
    prompt = await bob.next(AdmissionPrompt)
    await bob.node.answer_prompt(prompt.prompt_id, accept=True, name="Alice")
    bob_id = await connecting
    assert alice.node.contact(bob_id).name == "Bob"  # the label without its short ID
    assert alice.node.contact_for_nearby(announced(bob)) == alice.node.contact(bob_id)


async def test_a_contact_is_dialled_at_its_last_address_first(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id))
    # mDNS lists an unreachable address first (a Docker bridge, say) and the working one again.
    monkeypatch.setattr(alice.node, "nearby", lambda: [announced(bob, "192.0.2.1", LOOPBACK)])
    dialled = record_dials(monkeypatch)
    await alice.node.connect_nearby(announced(bob, "192.0.2.1", LOOPBACK))  # a known contact
    assert dialled == [LOOPBACK]
    assert alice.node.is_online(bob_id)


@pytest.mark.parametrize("more", [(), ("192.0.2.1",)])
async def test_a_pending_connect_succeeds_when_the_peer_connects_first(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch, more: tuple[str, ...]
) -> None:
    alice, bob = nodes
    bob_id, alice_id = await befriend(alice, bob)
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id) and not bob.node.is_online(alice_id))

    async def blocked(host: str, port: int) -> FrameStream:
        if port == alice.port:  # Bob dials us
            return await transport.open_stream(host, port)
        # Bob's firewall drops every connection of ours; meanwhile Bob connects to us.
        if not alice.node.is_online(bob_id):
            await bob.node.connect_address(LOOPBACK, alice.port)
            await until(lambda: alice.node.is_online(bob_id))
        raise TransportConnectFailed

    monkeypatch.setattr(alice.node, "nearby", lambda: [announced(bob, *more)])
    monkeypatch.setattr(session_manager_module, "open_stream", blocked)
    await alice.node.connect_contact(bob_id)
    assert alice.node.is_online(bob_id)
    assert not alice.of(ConnectFailed)


async def test_a_connection_dropped_in_the_handshake_is_named(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, _ = nodes

    async def hang_up(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(hang_up, LOOPBACK, 0)
    port = server.sockets[0].getsockname()[1]
    try:
        with pytest.raises(NodeError, match="dropped during the handshake"):
            await alice.node.connect_address(LOOPBACK, port)
    finally:
        server.close()
        await server.wait_closed()
    (failed,) = alice.of(ConnectFailed)
    assert (failed.reason, failed.detail) == (None, "connection lost")


async def test_unreachable_hints_at_a_firewall(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    port = bob.port
    await bob.node.lock()
    with pytest.raises(NodeError, match="firewall"):
        await alice.node.connect_address(LOOPBACK, port)
    (failed,) = alice.of(ConnectFailed)
    assert failed.detail == "unreachable"


async def test_unlock_clears_what_a_crash_left_in_flight(
    nodes: tuple[NodeHarness, NodeHarness], tmp_path: Path
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    final = tmp_path / "downloads" / "big.bin"
    final.parent.mkdir()
    part = final.with_name("big.bin.part")
    part.write_bytes(b"half a file")
    unrelated = final.with_name("big.bin")  # a finished file of the same name stays
    unrelated.write_bytes(b"keep me")
    vault = alice.node._vault
    entry = HistoryEntry(
        entry_id=vault.new_entry_id(),
        kind=MessageKind.FILE,
        direction=Direction.IN,
        time=3000.0,
        file=FileInfo(
            file_id=bytes(16),
            name="big.bin",
            size=1 << 30,
            media_type="application/octet-stream",
            status=FileStatus.TRANSFERRING,
            path=str(final),
        ),
    )
    await alice.node._db(vault.add_entry, alice.node.contact(bob_id).conv_id, entry)
    await alice.node.lock()
    await alice.node.unlock("pw")
    assert not part.exists()
    assert unrelated.read_bytes() == b"keep me"
    (after,) = [e for e in await alice.node.history(bob_id) if e.entry_id == entry.entry_id]
    assert after.file is not None
    assert after.file.status is FileStatus.FAILED
