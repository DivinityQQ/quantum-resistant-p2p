"""Two whole nodes over loopback: contacts, admission, chat, trust, lock (DESIGN §5, §7.6, §10)."""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import replace
from pathlib import Path

import pytest

from qrp2p.core.crypto.profiles import PQ_CNSA_1
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.services import node as node_module
from qrp2p.services.admission import PromptKind
from qrp2p.services.events import (
    AdmissionPrompt,
    ConnectFailed,
    HistoryChanged,
    KeyMismatchDetected,
    NodeState,
    PromptClosed,
    SessionEnded,
    SessionOpened,
    StateChanged,
)
from qrp2p.services.models import MessageKind, MessageStatus, Retention, TrustState
from qrp2p.services.node import NodeError, NotConnectedError, profile_by_name
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
    await bob.node.answer_prompt(prompt.prompt_id, accept=False)
    with pytest.raises(NodeError, match="declined"):
        await connecting
    assert alice.node.contacts() == []
    assert bob.node.contacts() == []


async def test_unanswered_prompt_expires(nodes: tuple[NodeHarness, NodeHarness]) -> None:
    alice, bob = nodes
    connecting = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port))
    prompt = await bob.next(AdmissionPrompt)
    bob.clock.advance(61.0)
    await bob.next(PromptClosed, lambda e: e.prompt_id == prompt.prompt_id)
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
    await bob.node.answer_prompt(prompt.prompt_id, accept=True)
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
    await bob.node.answer_prompt(prompt.prompt_id, accept=False)
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
    await asyncio.sleep(0.2)
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
