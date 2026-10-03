"""Concurrent requests on one node: read-modify-write is atomic and ordered per resource.

Front ends send requests without waiting for the previous answer, and each request awaits the
vault between reading a record and storing it. These tests slow the vault down so the requests
overlap for certain; without the node's ordering, a later request stores a stale copy.
"""

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import pytest

from qrp2p.core.crypto.profiles import PQ_CNSA_1
from qrp2p.services.events import AdmissionPrompt, HistoryChanged
from qrp2p.services.models import FileStatus, Retention, TrustState
from qrp2p.services.node import NodeError
from qrp2p.services.vault import Vault
from tests.services.support import LOOPBACK, NodeHarness, befriend, until


@pytest.fixture
async def nodes(tmp_path: Path) -> AsyncIterator[tuple[NodeHarness, NodeHarness]]:
    alice = await NodeHarness(tmp_path, "alice").start()
    bob = await NodeHarness(tmp_path, "bob").start()
    yield alice, bob
    await alice.node.close()
    await bob.node.close()


def slow(vault: Vault, monkeypatch: pytest.MonkeyPatch, name: str, seconds: float = 0.05) -> None:
    """Make one vault write slow (it runs on the vault thread)."""
    real: Callable[..., object] = getattr(vault, name)

    def slowed(*args: object, **kwargs: object) -> object:
        time.sleep(seconds)
        return real(*args, **kwargs)

    monkeypatch.setattr(vault, name, slowed)


async def relock(harness: NodeHarness) -> None:
    await harness.node.lock()
    await harness.node.unlock("pw")


async def test_a_profile_edit_does_not_undo_a_block(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    await alice.node.set_trust(bob_id, TrustState.VERIFIED)
    slow(alice.node._vault, monkeypatch, "save_contact")
    await asyncio.gather(
        alice.node.set_trust(bob_id, TrustState.BLOCKED),
        alice.node.update_contact(bob_id, profile_id=PQ_CNSA_1.id),
        alice.node.update_contact(bob_id, retention=Retention.DAYS_30),
    )
    for _ in range(2):  # in memory, and as stored
        contact = alice.node.contact(bob_id)
        assert contact.trust is TrustState.BLOCKED
        assert contact.profile_id == PQ_CNSA_1.id
        assert contact.retention is Retention.DAYS_30
        await relock(alice)


async def test_concurrent_setting_changes_all_apply(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, _ = nodes
    slow(alice.node._vault, monkeypatch, "save_settings")
    await asyncio.gather(
        alice.node.update_settings(display_name="Alicia"),
        alice.node.update_settings(auto_lock_minutes=120),
        alice.node.update_settings(reduced_motion=True),
    )
    for _ in range(2):
        settings = alice.node.settings
        assert (settings.display_name, settings.auto_lock_minutes, settings.reduced_motion) == (
            "Alicia",
            120,
            True,
        )
        await relock(alice)


async def test_verifying_names_the_identity_that_was_compared(
    nodes: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    peer_id, groups = alice.node.safety_number_of(bob_id)
    assert peer_id == bob.node.identity.peer_id
    assert groups == alice.node.safety_number(bob_id)
    with pytest.raises(NodeError, match="identity changed"):
        await alice.node.set_trust(bob_id, TrustState.VERIFIED, compared_peer_id=b"\0" * 48)
    assert alice.node.contact(bob_id).trust is TrustState.PINNED
    await alice.node.set_trust(bob_id, TrustState.VERIFIED, compared_peer_id=peer_id)
    assert alice.node.contact(bob_id).trust is TrustState.VERIFIED


async def test_an_offer_is_accepted_once(
    tmp_path: Path, nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    bob_id, _ = await befriend(alice, bob)
    source = tmp_path / "notes.txt"
    source.write_bytes(b"x" * 100_000)
    await alice.node.send_file(bob_id, source)
    offer = await bob.next(
        HistoryChanged,
        lambda e: e.entry.file is not None and e.entry.file.status is FileStatus.OFFERED,
    )
    assert offer.entry.file is not None
    file_id = offer.entry.file.file_id
    transfers = bob.node._transfers
    assert transfers is not None
    real_create = transfers._create_part

    def slow_create(directory: Path, name: str) -> object:
        time.sleep(0.1)
        return real_create(directory, name)

    monkeypatch.setattr(transfers, "_create_part", slow_create)
    downloads = tmp_path / "downloads"
    results = await asyncio.gather(
        bob.node.accept_file(file_id, downloads),
        bob.node.accept_file(file_id, downloads),
        bob.node.decline_file(file_id),
        return_exceptions=True,
    )
    assert results[0] is None
    assert all(isinstance(r, NodeError) for r in results[1:])
    await bob.next(
        HistoryChanged,
        lambda e: e.entry.file is not None and e.entry.file.status is FileStatus.COMPLETE,
    )
    assert sorted(p.name for p in downloads.iterdir()) == ["notes.txt"]  # one file, no .part


async def test_two_requests_from_one_new_identity_make_one_contact(
    nodes: tuple[NodeHarness, NodeHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, bob = nodes
    first = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port, name="Bob"))
    await bob.next(AdmissionPrompt)
    second = asyncio.create_task(alice.node.connect_address(LOOPBACK, bob.port, name="Bob"))
    await until(lambda: len(bob.of(AdmissionPrompt)) == 2)
    slow(bob.node._vault, monkeypatch, "save_contact")
    prompts = bob.of(AdmissionPrompt)
    await asyncio.gather(
        *(bob.node.answer_prompt(p.prompt_id, accept=True, name="Alice") for p in prompts)
    )
    await asyncio.gather(first, second, return_exceptions=True)
    assert [c.name for c in bob.node.contacts()] == ["Alice"]
