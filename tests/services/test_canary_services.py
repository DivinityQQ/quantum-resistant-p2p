"""Canary leak test through the services (DESIGN §15): no secret reaches a log, event, trace or file.

Two nodes record every secret their sessions create (through a recording provider), and the test
adds the identity seeds and the vault's own keys. After a scripted run (first contact, chat both
ways, a file transfer, a PQ rekey, lock) every log record, node event, trace event, file in both
data directories and the received file are searched for each secret in raw, hex and base64 form.
Chat text must not appear in the logs either.
"""

import base64
import dataclasses
import logging
import os
from collections.abc import Sequence
from pathlib import Path

import pytest

from qrp2p.core.crypto.provider import PlainProvider, RevealingProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.wire import Frame
from qrp2p.services.events import HistoryChanged
from qrp2p.services.models import FileStatus
from qrp2p.services.trace_bus import TraceRecord
from tests.services.support import NodeHarness, befriend, until

CHATS = ("canary chat one", "canary chat two")


class Recorder:
    def __init__(self) -> None:
        self.secrets: list[Secret] = []

    def __call__(self, secret: Secret) -> None:
        self.secrets.append(secret)


def public_bytes(obj: object) -> list[bytes]:
    if isinstance(obj, bytes):
        return [obj]
    if isinstance(obj, Frame):
        return [obj.encode()]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return [b for f in dataclasses.fields(obj) for b in public_bytes(getattr(obj, f.name))]
    if isinstance(obj, tuple | list):
        return [b for item in obj for b in public_bytes(item)]
    return []


def forms(value: bytes) -> list[str]:
    return [value.hex(), base64.b64encode(value).decode(), base64.b32encode(value).decode()]


def leaks(secrets: list[Secret], binary: bytes, text: str) -> list[str]:
    lowered = text.lower()
    return [
        s.label
        for s in secrets
        if s.reveal() in binary or any(f.lower() in lowered for f in forms(s.reveal()))
    ]


def live_keys(harness: NodeHarness) -> list[Secret]:
    """The identity seeds and the vault's keys of an unlocked node."""
    identity = harness.node._identity
    vault = harness.node._vault._open
    assert identity is not None
    assert vault is not None
    return [*identity.seeds, vault.kek, *vault.keys.values(), *vault.conv_keys.values()]


def evidence(
    root: Path,
    source: Path,
    traces: list[TraceRecord],
    events: Sequence[object],
    records: list[logging.LogRecord],
) -> tuple[bytes, str]:
    """Everything that could leak: public bytes and text of events and traces, every file
    (vault.json, database, WAL, received file) and every log record."""
    files = [p for p in root.rglob("*") if p.is_file() and p != source]
    binary = b"".join(
        [
            *(b for record in traces for b in public_bytes(record.event)),
            *(b for event in events for b in public_bytes(event)),
            *(path.read_bytes() for path in files),
        ]
    )
    text = "\n".join(
        [*(r.getMessage() for r in records), *(repr(e) for e in events), *(repr(r) for r in traces)]
    )
    return binary, text


async def test_services_leak_no_secret(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    recorder = Recorder()

    def recording() -> RevealingProvider:
        return RevealingProvider(PlainProvider(os.urandom), recorder)

    alice = NodeHarness(tmp_path, "alice", provider_factory=recording)
    bob = NodeHarness(tmp_path, "bob", provider_factory=recording)
    traces: list[TraceRecord] = []
    for harness in (alice, bob):
        await harness.start()
        harness.node.trace.subscribe(traces.append)
    secrets = list(recorder.secrets)
    try:
        bob_id, alice_id = await befriend(alice, bob)
        await alice.node.send_chat(bob_id, CHATS[0])
        await bob.node.send_chat(alice_id, CHATS[1])
        await alice.next(HistoryChanged, lambda e: e.entry.text == CHATS[1])
        source = tmp_path / "payload.bin"
        source.write_bytes(os.urandom(300_000))
        await alice.node.send_file(bob_id, source)
        offer = await bob.next(
            HistoryChanged,
            lambda e: e.entry.file is not None and e.entry.file.status is FileStatus.OFFERED,
        )
        assert offer.entry.file is not None
        downloads = tmp_path / "downloads"
        await bob.node.accept_file(offer.entry.file.file_id, downloads)
        await bob.next(
            HistoryChanged,
            lambda e: e.entry.file is not None and e.entry.file.status is FileStatus.COMPLETE,
        )
        alice.clock.advance(61)
        bob.clock.advance(61)
        await alice.node.rekey(bob_id)
        session = alice.node.session_info(bob_id)
        assert session is not None
        await until(lambda: session.channel is not None and session.channel.epoch == 1)
        secrets += live_keys(alice) + live_keys(bob)
        await alice.node.lock()
        await bob.node.lock()
    finally:
        await alice.node.close()
        await bob.node.close()
    secrets += recorder.secrets

    labels = {s.label for s in secrets}
    assert {"hs", "cs_0", "cs_1", "ap_I[0]", "exporter_1", "identity.mldsa65"} <= labels
    assert {"vault.kek", "vault.k_contacts", "vault.ck"} <= labels

    events = [*alice.events, *bob.events]
    binary, text = evidence(tmp_path, source, traces, events, caplog.records)
    assert leaks(secrets, binary, text) == []
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    assert not any(chat in log_text for chat in CHATS)
    # The search works: a planted secret is found in each form.
    planted = secrets[0]
    assert leaks([planted], planted.reveal(), "") == [planted.label]
    assert leaks([planted], b"", forms(planted.reveal())[1]) == [planted.label]
