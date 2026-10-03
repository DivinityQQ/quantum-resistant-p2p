"""Saved recordings (DESIGN §10.1, §11.5): sealed with k_lab, opened only by their vault.

A lab run and a glass-box session save and open again exactly; a normal session cannot be
saved; a recording's title never shows on disk; a file of another vault, an altered file and a
file of another version are listed as unreadable and refused when opened; a locked node has no
recordings.
"""

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from qrp2p.core.crypto.profiles import HYBRID_1
from qrp2p.lab.recording import GlassBoxRecording, LabRecording, Opened, RecordingError, Value
from qrp2p.lab.solo import SoloLab
from qrp2p.services.events import AdmissionPrompt, SessionOpened
from qrp2p.services.exposure import RecordRevealed
from qrp2p.services.node import NodeError
from qrp2p.services.recordings import DIRECTORY
from qrp2p.services.trace_bus import TraceBus
from qrp2p.services.vault import VaultError
from tests.services.support import NodeHarness, befriend, until
from tests.support import DeterministicRandom


@pytest.fixture
async def pair(tmp_path: Path) -> AsyncIterator[tuple[NodeHarness, NodeHarness]]:
    alice = await NodeHarness(tmp_path, "alice").start()
    bob = await NodeHarness(tmp_path, "bob").start()
    yield alice, bob
    await alice.node.close()
    await bob.node.close()


def lab_run() -> object:
    lab = SoloLab.fresh(HYBRID_1, TraceBus(), (1, 2), DeterministicRandom("saved"))
    lab.run()
    return lab.run_record()


async def test_a_lab_run_saves_and_opens_again_exactly(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, _ = pair
    run = lab_run()
    info = await alice.node.save_lab_recording("first handshake", run)  # type: ignore[arg-type]
    assert (info.title, info.kind, info.profile) == ("first handshake", "lab", "HYBRID-1")
    listed = await alice.node.recordings()
    assert [r.file_id for r in listed] == [info.file_id]
    opened = await alice.node.open_recording(info.file_id)
    assert isinstance(opened, LabRecording)
    assert opened.run == run
    files = list((alice.node.data_dir / DIRECTORY).iterdir())
    assert [f.name for f in files] == [f"{info.file_id}.qrlab"]  # a random name
    assert b"first handshake" not in files[0].read_bytes()  # the title is sealed
    await alice.node.delete_recording(info.file_id)
    assert await alice.node.recordings() == []
    with pytest.raises(RecordingError, match="no longer exists"):
        await alice.node.open_recording(info.file_id)


async def test_a_glass_box_session_saves_with_its_values_and_a_normal_one_cannot(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = pair
    bob_id, _ = await befriend(alice, bob)
    normal = alice.node.session_info(bob_id)
    assert normal is not None
    with pytest.raises(RecordingError, match="only a glass-box session"):
        await alice.node.save_session_recording(normal.id, "should not exist")
    await alice.node.disconnect(bob_id)
    await until(lambda: not alice.node.is_online(bob_id))
    session_id = await glass_box_session(alice, bob, bob_id)
    info = await alice.node.save_session_recording(session_id, "a glass-box chat")
    assert info.kind == "glass_box"
    opened = await alice.node.open_recording(info.file_id)
    assert isinstance(opened, GlassBoxRecording)
    assert opened.exposed
    assert opened.session.established
    labels = {e.label for e in opened.events if isinstance(e, Value)}
    assert {"ss", "hs", "cs_0"} <= labels
    plaintexts = [e.plaintext for e in opened.events if isinstance(e, Opened)]
    assert any(b"seen by both of us" in p for p in plaintexts)
    retained = [r.ordinal for r in alice.node.trace.events(session_id)]
    assert [e.ordinal for e in opened.events] == retained[: len(opened.events)]


async def glass_box_session(alice: NodeHarness, bob: NodeHarness, bob_id: bytes) -> int:
    connecting = asyncio.create_task(alice.node.connect_contact(bob_id, glass_box=True))
    prompt = await bob.next(AdmissionPrompt, lambda p: p.kind.value == "glass_box")
    await bob.node.answer_prompt(prompt.prompt_id, accept=True)
    await connecting
    await alice.next(SessionOpened, lambda e: e.glass_box)
    await alice.node.send_chat(bob_id, "seen by both of us")
    session = alice.node.session_info(bob_id)
    assert session is not None

    def sealed() -> bool:  # the writer seals it after send_chat returns
        return any(
            isinstance(r.event, RecordRevealed) and b"seen by both" in r.event.plaintext.reveal()
            for r in alice.node.trace.events(session.id)
        )

    await until(sealed)
    return session.id


async def test_files_that_do_not_open_are_listed_as_unreadable(
    pair: tuple[NodeHarness, NodeHarness],
) -> None:
    alice, bob = pair
    saved = await alice.node.save_lab_recording("mine", lab_run())  # type: ignore[arg-type]
    theirs = await bob.node.save_lab_recording("theirs", lab_run())  # type: ignore[arg-type]
    folder = alice.node.data_dir / DIRECTORY
    copied = folder / f"{theirs.file_id}.qrlab"
    copied.write_bytes((bob.node.data_dir / DIRECTORY / f"{theirs.file_id}.qrlab").read_bytes())
    altered = folder / ("ab" * 16 + ".qrlab")
    data = bytearray((folder / f"{saved.file_id}.qrlab").read_bytes())
    data[-1] ^= 1
    altered.write_bytes(bytes(data))
    other_version = folder / ("cd" * 16 + ".qrlab")
    other_version.write_bytes(b"QRLAB\0\x07" + bytes(64))
    (folder / "notes.txt").write_text("not a recording")
    listed = {r.file_id: r for r in await alice.node.recordings()}
    assert listed[saved.file_id].kind == "lab"
    for file_id in (theirs.file_id, "ab" * 16, "cd" * 16):
        assert listed[file_id].kind == "unreadable"
        assert listed[file_id].title == ""
    assert "another version" in listed["cd" * 16].problem
    assert len(listed) == 4  # notes.txt is not a recording
    with pytest.raises(VaultError, match="does not open with this vault"):
        await alice.node.open_recording(theirs.file_id)
    with pytest.raises(RecordingError, match="no such recording"):
        await alice.node.open_recording("../vault")


async def test_a_locked_node_has_no_recordings(pair: tuple[NodeHarness, NodeHarness]) -> None:
    alice, _ = pair
    await alice.node.save_lab_recording("before the lock", lab_run())  # type: ignore[arg-type]
    await alice.node.lock()
    with pytest.raises(NodeError, match="locked"):
        await alice.node.recordings()
