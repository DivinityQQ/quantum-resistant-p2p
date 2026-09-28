"""File transfer (DESIGN §9): names, limits, integrity checks and full transfers between nodes."""

import asyncio
import hashlib
import os
import shutil
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import cast

import pytest

from qrp2p.core.errors import CloseReason, FileCancelReason
from qrp2p.core.events import Priority
from qrp2p.core.wire import (
    MAX_CHUNK_BYTES,
    FileAccept,
    FileCancel,
    FileChunk,
    FileDone,
    FileOffer,
    FileProgress,
    Inner,
)
from qrp2p.services import files as files_module
from qrp2p.services.events import HistoryChanged
from qrp2p.services.files import (
    NAME_BUDGET,
    PART_SUFFIX,
    FileTransfers,
    PeerMisbehavedError,
    Transfer,
    mark_downloaded,
    rename_no_replace,
    sanitize_name,
    unique_path,
)
from qrp2p.services.models import FileStatus, MessageKind, TrustState
from qrp2p.services.session import Session, SessionNotOpenError
from tests.services.support import LOOPBACK, NodeHarness, befriend, until
from tests.support import identity_from_label

# --- names ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("offered", "saved"),
    [
        ("report.pdf", "report.pdf"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\System32\\evil.exe", "evil.exe"),
        ("..", "file"),
        ("...", "file"),
        ("", "file"),
        (".bashrc", "_bashrc"),
        ("a:b.txt", "a_b.txt"),
        ('x<>"|?*.txt', "x______.txt"),
        ("name. . ", "name"),
        ("  spaced  ", "spaced"),
        ("\x1b[31mred", "_[31mred"),
        ("invoice\u202efdp.exe", "invoice_fdp.exe"),
        ("e\u0301t\u00e9", "\u00e9t\u00e9"),  # NFC
        ("CON", "_CON"),
        ("con.txt", "_con.txt"),
        ("COM1.log", "_COM1.log"),
        ("LPT\u00b9", "_LPT\u00b9"),
        ("CONTACTS.txt", "CONTACTS.txt"),
    ],
)
def test_sanitize_name(offered: str, saved: str) -> None:
    assert sanitize_name(offered) == saved


def test_long_names_are_cut_keeping_the_extension() -> None:
    name = sanitize_name("\u00e9" * 300 + ".tar.gz")
    assert len(name.encode("utf-8")) <= NAME_BUDGET
    assert name.endswith(".gz")
    assert len((name + " (99999)" + PART_SUFFIX).encode("utf-8")) <= 255


def test_unique_path_is_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "Report.PDF").write_bytes(b"")
    (tmp_path / "report (2).pdf.part").write_bytes(b"")
    assert unique_path(tmp_path, "report.pdf").name == "report (3).pdf"
    assert unique_path(tmp_path, "other.pdf").name == "other.pdf"


def test_rename_never_overwrites(tmp_path: Path) -> None:
    source, target = tmp_path / "a.part", tmp_path / "a"
    source.write_bytes(b"new")
    target.write_bytes(b"old")
    with pytest.raises(FileExistsError):
        rename_no_replace(source, target)
    assert target.read_bytes() == b"old"
    assert source.exists()
    target.unlink()
    rename_no_replace(source, target)
    assert target.read_bytes() == b"new"
    assert not source.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="Mark of the Web is Windows-only")
def test_mark_of_the_web(tmp_path: Path) -> None:
    path = tmp_path / "x.exe"
    path.write_bytes(b"")
    assert mark_downloaded(path)
    assert "ZoneId=3" in Path(f"{path}:Zone.Identifier").read_text()


@pytest.mark.skipif(sys.platform != "darwin", reason="quarantine is macOS-only")
def test_quarantine_attribute(tmp_path: Path) -> None:
    path = tmp_path / "x.app"
    path.write_bytes(b"")
    assert mark_downloaded(path)


@pytest.mark.skipif(sys.platform in {"win32", "darwin"}, reason="Linux has no download mark")
def test_no_mark_on_linux(tmp_path: Path) -> None:
    path = tmp_path / "x"
    path.write_bytes(b"")
    assert not mark_downloaded(path)


# --- the transfer state machine, against a stub session -------------------------------------------


class StubSession:
    """What FileTransfers needs from a session: an ID, the peer, and sending."""

    def __init__(self, session_id: int = 1) -> None:
        self.id = session_id
        self.peer = identity_from_label("peer").bundle
        self.glass_box = False
        self.is_open = True
        self.sent: list[Inner] = []

    def send(self, message: Inner, priority: Priority) -> None:  # noqa: ARG002
        if not self.is_open:
            raise SessionNotOpenError
        self.sent.append(message)

    async def send_bulk(self, message: Inner) -> None:
        self.send(message, Priority.FILE)


class Hooks:
    def __init__(self) -> None:
        self.offers: list[Transfer] = []
        self.changes: list[Transfer] = []

    def offered(self, transfer: Transfer) -> None:
        self.offers.append(transfer)

    def changed(self, transfer: Transfer) -> None:
        self.changes.append(transfer)


FID = b"\x01" * 16


def receiver(max_size: int = 2**30) -> tuple[FileTransfers, Hooks, StubSession, Session]:
    hooks = Hooks()
    transfers = FileTransfers(hooks, max_size=max_size)
    stub = StubSession()
    return transfers, hooks, stub, cast("Session", stub)


async def offered(
    transfers: FileTransfers, session: Session, data: bytes, name: str = "f.bin"
) -> None:
    await transfers.handle(
        session, FileOffer(file_id=FID, name=name, size=len(data), media_type="x/y")
    )


async def accepted(tmp_path: Path, data: bytes) -> tuple[FileTransfers, StubSession, Session]:
    transfers, _, stub, session = receiver()
    await offered(transfers, session, data)
    await transfers.accept(FID, tmp_path)
    assert stub.sent == [FileAccept(file_id=FID)]
    return transfers, stub, session


async def feed(transfers: FileTransfers, session: Session, data: bytes) -> None:
    for start in range(0, len(data), MAX_CHUNK_BYTES):
        await transfers.handle(
            session, FileChunk(file_id=FID, data=data[start : start + MAX_CHUNK_BYTES])
        )


def parts(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.name.endswith(PART_SUFFIX)]


async def test_receive_verifies_and_renames(tmp_path: Path) -> None:
    data = os.urandom(3 * 2**20 + 123)
    transfers, stub, session = await accepted(tmp_path, data)
    assert len(parts(tmp_path)) == 1
    await feed(transfers, session, data)
    await transfers.handle(session, FileDone(file_id=FID, sha256=hashlib.sha256(data).digest()))
    assert (tmp_path / "f.bin").read_bytes() == data
    assert parts(tmp_path) == []
    progress = [m.received for m in stub.sent if isinstance(m, FileProgress)]
    # One report per MiB written (the receiver writes in 1 MiB blocks), then the final ack
    # (the last partial block is written on file_done and needs no report of its own).
    assert [n // 2**20 for n in progress[:-1]] == [1, 2]
    assert progress[-1] == len(data)


async def test_hash_mismatch_aborts(tmp_path: Path) -> None:
    data = os.urandom(50_000)
    transfers, stub, session = await accepted(tmp_path, data)
    await feed(transfers, session, data)
    await transfers.handle(session, FileDone(file_id=FID, sha256=bytes(32)))
    assert FileCancel(file_id=FID, reason=FileCancelReason.HASH_MISMATCH) in stub.sent
    await until(lambda: not any(tmp_path.iterdir()))


async def test_size_mismatch_aborts(tmp_path: Path) -> None:
    data = os.urandom(20_000)
    transfers, stub, session = await accepted(tmp_path, data)
    await feed(transfers, session, data + b"extra")  # more than offered
    assert FileCancel(file_id=FID, reason=FileCancelReason.SIZE_MISMATCH) in stub.sent
    await until(lambda: not any(tmp_path.iterdir()))


async def test_short_file_is_a_size_mismatch(tmp_path: Path) -> None:
    data = os.urandom(20_000)
    transfers, stub, session = await accepted(tmp_path, data)
    await feed(transfers, session, data[:-1])
    await transfers.handle(session, FileDone(file_id=FID, sha256=hashlib.sha256(data).digest()))
    assert FileCancel(file_id=FID, reason=FileCancelReason.SIZE_MISMATCH) in stub.sent
    await until(lambda: not any(tmp_path.iterdir()))


async def test_user_cancel_deletes_part_file(tmp_path: Path) -> None:
    data = os.urandom(3 * 2**20)
    transfers, stub, session = await accepted(tmp_path, data)
    await feed(transfers, session, data[: 2**20 + 5])
    await transfers.cancel(FID)
    assert FileCancel(file_id=FID, reason=FileCancelReason.USER) in stub.sent
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240
    # Chunks already in flight are ignored, not fatal.
    await transfers.handle(session, FileChunk(file_id=FID, data=b"late"))


async def test_peer_cancel_deletes_part_file(tmp_path: Path) -> None:
    data = os.urandom(100_000)
    transfers, _, session = await accepted(tmp_path, data)
    await feed(transfers, session, data[:40_000])
    await transfers.handle(session, FileCancel(file_id=FID, reason=FileCancelReason.USER))
    await until(lambda: not any(tmp_path.iterdir()))


async def test_disk_full_cancels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    transfers, _, stub, session = receiver()
    await offered(transfers, session, b"x" * 1000)
    monkeypatch.setattr(
        files_module.shutil,
        "disk_usage",
        lambda _: shutil._ntuple_diskusage(10, 10, 10),
    )
    transfer = await transfers.accept(FID, tmp_path)
    assert transfer.status is FileStatus.CANCELLED
    assert stub.sent == [FileCancel(file_id=FID, reason=FileCancelReason.DISK_FULL)]
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240


async def test_size_limit_cancels() -> None:
    transfers, hooks, stub, session = receiver(max_size=1000)
    await offered(transfers, session, b"x" * 1001)
    assert stub.sent == [FileCancel(file_id=FID, reason=FileCancelReason.LIMIT)]
    assert hooks.offers == []


async def test_pending_offers_are_limited() -> None:
    transfers, hooks, stub, session = receiver()
    for n in range(4):
        fid = bytes([n]) * 16
        await transfers.handle(session, FileOffer(file_id=fid, name="a", size=1, media_type="x/y"))
    assert len(hooks.offers) == 3
    assert stub.sent == [FileCancel(file_id=b"\x03" * 16, reason=FileCancelReason.LIMIT)]


@pytest.mark.parametrize(
    "message",
    [
        FileChunk(file_id=b"\x09" * 16, data=b"x"),
        FileDone(file_id=b"\x09" * 16, sha256=bytes(32)),
        FileAccept(file_id=b"\x09" * 16),
        FileProgress(file_id=b"\x09" * 16, received=0),
        FileCancel(file_id=b"\x09" * 16, reason=FileCancelReason.USER),
    ],
)
async def test_messages_for_unknown_transfers_close_the_session(message: Inner) -> None:
    transfers, _, _, session = receiver()
    with pytest.raises(PeerMisbehavedError) as caught:
        await transfers.handle(session, message)  # type: ignore[arg-type]
    assert caught.value.reason is CloseReason.UNEXPECTED_MESSAGE


async def test_chunk_before_accept_closes_the_session() -> None:
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x" * 10)
    with pytest.raises(PeerMisbehavedError):
        await transfers.handle(session, FileChunk(file_id=FID, data=b"x"))


async def test_duplicate_offer_closes_the_session() -> None:
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x")
    with pytest.raises(PeerMisbehavedError):
        await offered(transfers, session, b"x")


async def test_progress_beyond_what_was_sent_closes_the_session(tmp_path: Path) -> None:
    hooks = Hooks()
    transfers = FileTransfers(hooks, max_size=2**30)
    stub = StubSession()
    session = cast("Session", stub)
    source = tmp_path / "src.bin"
    source.write_bytes(os.urandom(10))
    transfer = transfers.offer(session, source)
    with pytest.raises(PeerMisbehavedError):
        await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=5))


async def test_sender_waits_for_acknowledgements(tmp_path: Path) -> None:
    """At most 4 MiB go out unacknowledged."""
    hooks = Hooks()
    transfers = FileTransfers(hooks, max_size=2**30)
    stub = StubSession()
    session = cast("Session", stub)
    source = tmp_path / "big.bin"
    source.write_bytes(os.urandom(6 * 2**20))
    transfer = transfers.offer(session, source)
    await transfers.handle(session, FileAccept(file_id=transfer.file_id))
    await until(lambda: transfer.transferred >= 4 * 2**20)
    await asyncio.sleep(0.05)
    assert transfer.transferred == 4 * 2**20  # the window is full
    await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=2**20))
    await until(lambda: transfer.transferred == 5 * 2**20)
    await asyncio.sleep(0.05)
    assert transfer.transferred == 5 * 2**20
    await transfers.cancel(transfer.file_id)


# --- whole nodes ----------------------------------------------------------------------------------


@pytest.fixture
async def friends(tmp_path: Path) -> AsyncIterator[tuple[NodeHarness, NodeHarness, bytes, bytes]]:
    alice = await NodeHarness(tmp_path, "alice").start()
    bob = await NodeHarness(tmp_path, "bob").start()
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    await bob.node.update_settings(downloads_dir=str(downloads))
    bob_id, alice_id = await befriend(alice, bob)
    yield alice, bob, bob_id, alice_id
    await alice.node.close()
    await bob.node.close()


def file_event(harness: NodeHarness, status: FileStatus) -> HistoryChanged | None:
    for event in harness.of(HistoryChanged):
        if event.entry.file is not None and event.entry.file.status is status:
            return event
    return None


async def test_file_transfer_between_nodes(
    tmp_path: Path, friends: tuple[NodeHarness, NodeHarness, bytes, bytes]
) -> None:
    alice, bob, bob_id, alice_id = friends
    data = os.urandom(5 * 2**20 + 7)
    source = tmp_path / "holiday photos.zip"
    source.write_bytes(data)
    await alice.node.send_file(bob_id, source)
    await until(lambda: file_event(bob, FileStatus.OFFERED) is not None)
    offer = file_event(bob, FileStatus.OFFERED)
    assert offer is not None
    assert offer.contact_id == alice_id
    info = offer.entry.file
    assert info is not None
    assert (info.name, info.size) == ("holiday photos.zip", len(data))
    await bob.node.accept_file(info.file_id)
    # A chat sent during the transfer arrives intact (v1 regression 3: interleaved frames).
    await alice.node.send_chat(bob_id, "sending you the photos")
    await until(lambda: file_event(alice, FileStatus.COMPLETE) is not None)
    await until(lambda: file_event(bob, FileStatus.COMPLETE) is not None)
    done = file_event(bob, FileStatus.COMPLETE)
    assert done is not None
    assert done.entry.file is not None
    received = Path(done.entry.file.path)
    assert received.read_bytes() == data  # noqa: ASYNC240
    assert received.parent == tmp_path / "downloads"
    assert done.entry.file.sha256 == hashlib.sha256(data).digest()
    await bob.next(HistoryChanged, lambda e: e.entry.text == "sending you the photos")
    history = await bob.node.history(alice_id)
    assert [e.kind for e in history] == [MessageKind.FILE, MessageKind.CHAT]
    assert history[0].file is not None
    assert history[0].file.status is FileStatus.COMPLETE


async def test_declined_file(
    tmp_path: Path, friends: tuple[NodeHarness, NodeHarness, bytes, bytes]
) -> None:
    alice, bob, bob_id, _ = friends
    source = tmp_path / "x.txt"
    source.write_bytes(b"no thanks")
    await alice.node.send_file(bob_id, source)
    await until(lambda: file_event(bob, FileStatus.OFFERED) is not None)
    offer = file_event(bob, FileStatus.OFFERED)
    assert offer is not None
    assert offer.entry.file is not None
    await bob.node.decline_file(offer.entry.file.file_id)
    await until(lambda: file_event(alice, FileStatus.DECLINED) is not None)


async def test_auto_accept_from_a_verified_contact(
    tmp_path: Path, friends: tuple[NodeHarness, NodeHarness, bytes, bytes]
) -> None:
    alice, bob, bob_id, alice_id = friends
    await bob.node.set_trust(alice_id, TrustState.VERIFIED)
    await bob.node.update_contact(alice_id, auto_accept_files=True, auto_accept_limit=1000)
    small, large = tmp_path / "small.txt", tmp_path / "large.bin"
    small.write_bytes(b"s" * 1000)
    large.write_bytes(b"l" * 1001)
    await alice.node.send_file(bob_id, small)
    await until(lambda: file_event(alice, FileStatus.COMPLETE) is not None)
    await alice.node.send_file(bob_id, large)
    await until(
        lambda: any(
            e.entry.file is not None
            and e.entry.file.name == "large.bin"
            and e.entry.file.status is FileStatus.OFFERED
            for e in bob.of(HistoryChanged)
        )
    )
    await asyncio.sleep(0.05)
    assert (tmp_path / "downloads" / "small.txt").exists()
    assert not (tmp_path / "downloads" / "large.bin").exists()


async def test_session_end_fails_the_transfer(
    tmp_path: Path, friends: tuple[NodeHarness, NodeHarness, bytes, bytes]
) -> None:
    alice, bob, bob_id, _ = friends
    source = tmp_path / "x.bin"
    source.write_bytes(b"x" * 100)
    await alice.node.send_file(bob_id, source)
    await until(lambda: file_event(bob, FileStatus.OFFERED) is not None)
    await alice.node.disconnect(bob_id)
    await until(lambda: file_event(alice, FileStatus.FAILED) is not None)
    await until(lambda: file_event(bob, FileStatus.FAILED) is not None)


def test_window_leaves_room_for_the_receivers_reports() -> None:
    """Liveness: the receiver reports only after writing a whole block, so the sender's window
    must hold more than a block plus one report interval, or both sides would wait forever."""
    assert files_module.WINDOW >= files_module.READ_BLOCK + files_module.PROGRESS_EVERY


@pytest.fixture
def slow_disk(monkeypatch: pytest.MonkeyPatch) -> None:
    """Receivers write slowly, so a transfer is still running when the test acts."""
    original = FileTransfers._flush

    async def slow_flush(self: FileTransfers, transfer: Transfer) -> None:
        await asyncio.sleep(0.05)
        await original(self, transfer)

    monkeypatch.setattr(FileTransfers, "_flush", slow_flush)


async def start_big_transfer(
    tmp_path: Path, alice: NodeHarness, bob: NodeHarness, bob_id: bytes
) -> Path:
    source = tmp_path / "big.bin"
    source.write_bytes(os.urandom(16 * 2**20))
    await alice.node.send_file(bob_id, source)
    await until(lambda: file_event(bob, FileStatus.OFFERED) is not None)
    offer = file_event(bob, FileStatus.OFFERED)
    assert offer is not None
    assert offer.entry.file is not None
    downloads = tmp_path / "downloads"
    await bob.node.accept_file(offer.entry.file.file_id, downloads)
    await until(lambda: any(p.name.endswith(PART_SUFFIX) for p in downloads.iterdir()))
    await until(lambda: any(t.transferred > 0 for t in bob.node.transfers()))
    return downloads


@pytest.mark.usefixtures("slow_disk")
async def test_lock_during_a_transfer_deletes_the_partial_file(
    tmp_path: Path, friends: tuple[NodeHarness, NodeHarness, bytes, bytes]
) -> None:
    alice, bob, bob_id, _ = friends
    downloads = await start_big_transfer(tmp_path, alice, bob, bob_id)
    await bob.node.lock()
    assert list(downloads.iterdir()) == []
    await until(lambda: file_event(alice, FileStatus.FAILED) is not None)
    assert alice.node.transfers() == []


@pytest.mark.usefixtures("slow_disk")
async def test_replacing_the_session_fails_its_transfers(
    tmp_path: Path, friends: tuple[NodeHarness, NodeHarness, bytes, bytes]
) -> None:
    alice, bob, bob_id, _ = friends
    downloads = await start_big_transfer(tmp_path, alice, bob, bob_id)
    await alice.node.connect_address(LOOPBACK, bob.port)  # a new session replaces the old one
    await until(lambda: file_event(alice, FileStatus.FAILED) is not None)
    await until(lambda: file_event(bob, FileStatus.FAILED) is not None)
    await until(lambda: not any(downloads.iterdir()))
    assert alice.node.is_online(bob_id)  # the new session carries on
