"""File transfer (DESIGN §9): names, limits, integrity checks and full transfers between nodes."""

import asyncio
import errno
import hashlib
import os
import shutil
import sys
import threading
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
    FileDecline,
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
    TransferDirection,
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

    def __init__(self, session_id: int = 1, peer: str = "peer") -> None:
        self.id = session_id
        self.peer = identity_from_label(peer).bundle
        self.glass_box = False
        self.is_open = True
        self.sent: list[Inner] = []
        self.priorities: list[tuple[str, Priority]] = []
        self.yield_on_bulk = False

    def send(self, message: Inner, priority: Priority) -> None:
        if not self.is_open:
            raise SessionNotOpenError
        self.sent.append(message)
        self.priorities.append((type(message).__name__, priority))

    async def send_bulk(self, message: Inner) -> None:
        if self.yield_on_bulk:
            await asyncio.sleep(0)  # like a real writer queue with room: others get a turn
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


async def test_peer_cancel_while_accepting_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The offer is cancelled while accept() waits for the disk: no .part file survives."""
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x" * 100)
    gate = threading.Event()
    real_usage = shutil.disk_usage

    def slow_usage(path: object) -> object:
        gate.wait(5)
        return real_usage(path)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(files_module.shutil, "disk_usage", slow_usage)
    accepting = asyncio.create_task(transfers.accept(FID, tmp_path))
    await asyncio.sleep(0.01)
    await transfers.handle(session, FileCancel(file_id=FID, reason=FileCancelReason.USER))
    gate.set()
    with pytest.raises(KeyError):
        await accepting
    await asyncio.sleep(0.01)
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240


async def test_work_finished_after_cancellation_is_released() -> None:
    """A file a worker thread opens after its waiter was cancelled still gets closed."""
    gate = threading.Event()
    released: list[str] = []

    def open_slowly() -> str:
        gate.wait(5)
        return "handle"

    waiter = asyncio.create_task(files_module._owned_in_thread(open_slowly, released.append))
    await asyncio.sleep(0.01)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    gate.set()
    await until(lambda: released == ["handle"])


# --- found by mutation testing of the services ----------------------------------------------------


@pytest.mark.parametrize(
    ("offered", "saved"),
    [
        ("CON .txt", "_CON .txt"),  # Windows ignores the space: still the console device
        ("con.tar.gz", "_con.tar.gz"),  # the stem is what precedes the first dot
        ("\u2003doc.txt\u3000", "doc.txt"),  # any Unicode space at the ends
    ],
)
def test_sanitize_more_names(offered: str, saved: str) -> None:
    assert sanitize_name(offered) == saved


def test_names_at_the_length_limits() -> None:
    exact = "a" * NAME_BUDGET
    assert sanitize_name(exact) == exact
    assert len(sanitize_name(exact + "a").encode("utf-8")) == NAME_BUDGET
    long_ext = "b" * 40
    cut = sanitize_name("a" * 300 + "." + long_ext)
    assert len(cut.encode("utf-8")) <= NAME_BUDGET
    assert not cut.endswith("." + long_ext)  # a long "extension" is not kept whole
    kept = sanitize_name("a" * 300 + "." + "c" * 31)
    assert kept.endswith("." + "c" * 31)
    dotted = sanitize_name("a" * (NAME_BUDGET - 5) + "." + "b" * 20 + ".txt")
    assert ".." not in dotted
    assert dotted.endswith("a.txt")


def test_clash_suffix_goes_before_the_last_extension(tmp_path: Path) -> None:
    for name in ("archive.tar.gz", "a.txt", "plain"):
        (tmp_path / name).write_bytes(b"")
    assert unique_path(tmp_path, "archive.tar.gz").name == "archive.tar (2).gz"
    assert unique_path(tmp_path, "a.txt").name == "a (2).txt"
    assert unique_path(tmp_path, "plain").name == "plain (2)"


@pytest.mark.skipif(sys.platform == "win32", reason="the hard-link path is POSIX-only")
def test_rename_falls_back_where_hard_links_are_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_links(_self: Path, _target: Path) -> None:
        raise OSError(errno.EPERM, "operation not permitted")

    monkeypatch.setattr(Path, "hardlink_to", no_links)
    source, target = tmp_path / "a.part", tmp_path / "a"
    source.write_bytes(b"data")
    rename_no_replace(source, target)
    assert target.read_bytes() == b"data"
    source.write_bytes(b"new")
    with pytest.raises(FileExistsError) as caught:
        rename_no_replace(source, target)
    assert caught.value.errno == errno.EEXIST
    assert target.read_bytes() == b"data"

    def broken(_self: Path, _target: Path) -> None:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(Path, "hardlink_to", broken)
    with pytest.raises(OSError, match="I/O error"):
        rename_no_replace(source, tmp_path / "b")


def test_media_types() -> None:
    assert files_module.media_type_of(Path("photo.jpg")) == "image/jpeg"
    assert files_module.media_type_of(Path("x.no-such-extension")) == "application/octet-stream"
    assert files_module.media_type_of(Path("x.pict")) == "image/pict"  # a non-strict type


async def test_messages_travel_at_their_priorities(tmp_path: Path) -> None:
    data = os.urandom(20_000)
    transfers, stub, session = await accepted(tmp_path, data)
    await feed(transfers, session, data)
    await transfers.handle(session, FileDone(file_id=FID, sha256=hashlib.sha256(data).digest()))
    await transfers.handle(
        session, FileOffer(file_id=b"\x02" * 16, name="n", size=1, media_type="x/y")
    )
    transfers.decline(b"\x02" * 16)
    source = tmp_path / "out.bin"
    source.write_bytes(b"x" * 10)
    ours = transfers.offer(session, source)
    await transfers.handle(session, FileAccept(file_id=ours.file_id))
    await until(lambda: any(kind == "FileDone" for kind, _ in stub.priorities))
    await transfers.cancel(ours.file_id)
    expected = {
        "FileAccept": Priority.CHAT,
        "FileDecline": Priority.CHAT,
        "FileOffer": Priority.CHAT,
        "FileCancel": Priority.CHAT,
        "FileProgress": Priority.CONTROL,
        "FileChunk": Priority.FILE,
        "FileDone": Priority.FILE,
    }
    assert dict(stub.priorities) == expected


async def sender(tmp_path: Path, size: int) -> tuple[FileTransfers, StubSession, Transfer, Path]:
    transfers = FileTransfers(Hooks(), max_size=2**30)
    stub = StubSession()
    source = tmp_path / "source.bin"
    source.write_bytes(os.urandom(size))
    transfer = transfers.offer(cast("Session", stub), source)
    return transfers, stub, transfer, source


@pytest.mark.parametrize("change", ["shrink", "grow"])
async def test_a_source_that_changed_since_the_offer_is_cancelled(
    tmp_path: Path, change: str
) -> None:
    transfers, stub, transfer, source = await sender(tmp_path, 50_000)
    with source.open("r+b") as stream:
        if change == "shrink":
            stream.truncate(30_000)
        else:
            stream.seek(0, os.SEEK_END)
            stream.write(b"extra")
    await transfers.handle(cast("Session", stub), FileAccept(file_id=transfer.file_id))
    await until(lambda: transfer.finished)
    assert transfer.status is FileStatus.CANCELLED
    assert FileCancel(file_id=transfer.file_id, reason=FileCancelReason.SIZE_MISMATCH) in stub.sent
    assert not any(isinstance(m, FileDone) for m in stub.sent)


async def test_an_unreadable_source_fails_the_transfer(tmp_path: Path) -> None:
    transfers, stub, transfer, source = await sender(tmp_path, 100)
    source.unlink()
    await transfers.handle(cast("Session", stub), FileAccept(file_id=transfer.file_id))
    await until(lambda: transfer.finished)
    assert transfer.status is FileStatus.FAILED
    assert FileCancel(file_id=transfer.file_id, reason=FileCancelReason.USER) in stub.sent


async def test_sender_stops_when_the_peer_cancels(tmp_path: Path) -> None:
    transfers, stub, transfer, _ = await sender(tmp_path, 3 * 2**20)
    stub.yield_on_bulk = True
    session = cast("Session", stub)
    await transfers.handle(session, FileAccept(file_id=transfer.file_id))
    await until(lambda: transfer.transferred > 0)
    await transfers.handle(
        session, FileCancel(file_id=transfer.file_id, reason=FileCancelReason.USER)
    )
    chunks = sum(isinstance(m, FileChunk) for m in stub.sent)
    await asyncio.sleep(0.1)
    assert sum(isinstance(m, FileChunk) for m in stub.sent) == chunks  # nothing more was sent
    assert transfer.status is FileStatus.CANCELLED
    assert transfer.by_peer
    assert not any(isinstance(m, FileCancel) for m in stub.sent)  # no cancel echoed back


async def test_peer_cancels_or_declines_our_offer(tmp_path: Path) -> None:
    transfers, stub, first, _ = await sender(tmp_path, 10)
    session = cast("Session", stub)
    await transfers.handle(session, FileCancel(file_id=first.file_id, reason=FileCancelReason.USER))
    assert first.status is FileStatus.CANCELLED
    second = transfers.offer(session, tmp_path / "source.bin")
    await transfers.handle(session, FileDecline(file_id=second.file_id))
    assert second.status is FileStatus.DECLINED
    assert second.by_peer


async def test_delivered_only_after_the_final_acknowledgement(tmp_path: Path) -> None:
    transfers, stub, transfer, _ = await sender(tmp_path, 30_000)
    session = cast("Session", stub)
    await transfers.handle(session, FileAccept(file_id=transfer.file_id))
    await until(lambda: any(isinstance(m, FileDone) for m in stub.sent))
    await asyncio.sleep(0.01)
    assert transfer.status is FileStatus.TRANSFERRING  # sent, not yet verified by the peer
    await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=30_000))
    assert transfer.status is FileStatus.COMPLETE


async def test_progress_must_move_forward_while_transferring(tmp_path: Path) -> None:
    transfers, stub, transfer, _ = await sender(tmp_path, 30_000)
    session = cast("Session", stub)
    with pytest.raises(PeerMisbehavedError):  # before our offer was accepted
        await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=0))
    transfers, stub, transfer, _ = await sender(tmp_path, 30_000)
    session = cast("Session", stub)
    await transfers.handle(session, FileAccept(file_id=transfer.file_id))
    await until(lambda: transfer.transferred == 30_000)
    await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=20_000))
    with pytest.raises(PeerMisbehavedError):
        await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=10_000))


async def test_an_offer_may_not_reuse_a_finished_id() -> None:
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x")
    transfers.decline(FID)
    with pytest.raises(PeerMisbehavedError):
        await offered(transfers, session, b"x")


async def test_limits_are_inclusive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    transfers, hooks, stub, session = receiver(max_size=1000)
    await offered(transfers, session, b"x" * 1000)  # exactly the limit
    assert len(hooks.offers) == 1
    need = 1000 + files_module.FREE_SPACE_MARGIN
    monkeypatch.setattr(
        files_module.shutil,
        "disk_usage",
        lambda _: shutil._ntuple_diskusage(need, 0, need),
    )
    transfer = await transfers.accept(FID, tmp_path / "a" / "b")  # nested, not yet created
    assert transfer.status is FileStatus.TRANSFERRING
    assert FileAccept(file_id=FID) in stub.sent
    await transfers.session_ended(session)


@pytest.mark.parametrize(
    ("error", "reason"),
    [(errno.ENOSPC, FileCancelReason.DISK_FULL), (errno.EIO, FileCancelReason.USER)],
)
async def test_write_failures_fail_the_transfer(
    tmp_path: Path, error: int, reason: FileCancelReason
) -> None:
    data = os.urandom(2 * 2**20)
    transfers, stub, session = await accepted(tmp_path, data)
    transfer = transfers.get(FID)
    assert transfer is not None
    stream = transfer.io.stream
    assert stream is not None

    class FailingStream:
        def write(self, _: bytes) -> int:
            raise OSError(error, "write failed")

        def close(self) -> None:
            stream.close()

    transfer.io.stream = FailingStream()  # type: ignore[assignment]
    await feed(transfers, session, data)
    assert transfer.status is FileStatus.FAILED
    assert FileCancel(file_id=FID, reason=reason) in stub.sent
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240


async def test_a_file_that_appears_meanwhile_is_not_overwritten(tmp_path: Path) -> None:
    data = os.urandom(10_000)
    transfers, _, session = await accepted(tmp_path, data)
    (tmp_path / "f.bin").write_bytes(b"someone else's")
    await feed(transfers, session, data)
    await transfers.handle(session, FileDone(file_id=FID, sha256=hashlib.sha256(data).digest()))
    assert (tmp_path / "f.bin").read_bytes() == b"someone else's"
    assert (tmp_path / "f (2).bin").read_bytes() == data


async def test_a_part_file_name_taken_at_the_last_moment_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "f.bin.part").write_bytes(b"another writer's")
    names = iter([tmp_path / "f.bin", tmp_path / "f (2).bin"])
    monkeypatch.setattr(files_module, "unique_path", lambda *_: next(names))
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x" * 10)
    transfer = await transfers.accept(FID, tmp_path)
    assert transfer.path == tmp_path / "f (2).bin"
    assert (tmp_path / "f.bin.part").read_bytes() == b"another writer's"
    await transfers.session_ended(session)


async def test_pending_offers_are_counted_per_peer() -> None:
    hooks = Hooks()
    transfers = FileTransfers(hooks, max_size=2**30)
    carol = cast("Session", StubSession(1, "carol"))
    dave = cast("Session", StubSession(2, "dave"))
    for n in range(3):
        await transfers.handle(
            carol, FileOffer(file_id=bytes([n]) * 16, name="a", size=1, media_type="x/y")
        )
    await transfers.handle(
        dave, FileOffer(file_id=b"\x09" * 16, name="a", size=1, media_type="x/y")
    )
    assert len(hooks.offers) == 4  # Carol's three do not count against Dave


async def test_ending_a_session_forgets_its_finished_transfers() -> None:
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x")
    transfers.decline(FID)
    await transfers.session_ended(session)
    assert transfers._finished == {}


async def test_failed_work_after_cancellation_is_not_released() -> None:
    gate = threading.Event()
    released: list[object] = []

    def fail_slowly() -> str:
        gate.wait(5)
        raise OSError(errno.EIO, "failed")

    waiter = asyncio.create_task(files_module._owned_in_thread(fail_slowly, released.append))
    await asyncio.sleep(0.01)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    gate.set()
    await asyncio.sleep(0.05)
    assert released == []


async def test_offer_contents(tmp_path: Path) -> None:
    transfers, stub, transfer, _ = await sender(tmp_path, 1234)
    (offer,) = stub.sent
    assert offer == FileOffer(
        file_id=transfer.file_id,
        name="source.bin",
        size=1234,
        media_type="application/octet-stream",
    )
    assert (transfer.direction, transfer.name, transfer.status) == (
        TransferDirection.OUT,
        "source.bin",
        FileStatus.OFFERED,
    )
    with pytest.raises(KeyError):  # our own offer is not ours to accept
        await transfers.accept(transfer.file_id, tmp_path)


async def test_repeated_progress_is_accepted(tmp_path: Path) -> None:
    transfers, stub, transfer, _ = await sender(tmp_path, 30_000)
    session = cast("Session", stub)
    await transfers.handle(session, FileAccept(file_id=transfer.file_id))
    await until(lambda: transfer.transferred == 30_000)
    for _ in range(2):
        await transfers.handle(session, FileProgress(file_id=transfer.file_id, received=16_000))
    assert transfer.acknowledged == 16_000


async def test_our_own_cancel_is_not_the_peers(tmp_path: Path) -> None:
    transfers, _, transfer, _ = await sender(tmp_path, 10)
    await transfers.cancel(transfer.file_id)
    assert transfer.status is FileStatus.CANCELLED
    assert transfer.reason is FileCancelReason.USER
    assert not transfer.by_peer


async def test_peer_cancel_keeps_the_peers_reason(tmp_path: Path) -> None:
    data = os.urandom(10_000)
    transfers, _, session = await accepted(tmp_path, data)
    transfer = transfers.get(FID)
    assert transfer is not None
    await transfers.handle(session, FileCancel(file_id=FID, reason=FileCancelReason.DISK_FULL))
    assert transfer.reason is FileCancelReason.DISK_FULL
    assert transfer.by_peer
    # A cancel for a transfer that is already over is ignored, not a protocol error.
    await transfers.handle(session, FileCancel(file_id=FID, reason=FileCancelReason.USER))


async def test_a_closed_session_does_not_break_answers(tmp_path: Path) -> None:
    transfers, _, stub, session = receiver()
    await offered(transfers, session, b"x")
    stub.is_open = False
    transfers.decline(FID)  # nothing can be sent; declining still works
    data = os.urandom(10_000)
    transfers, stub, session = await accepted(tmp_path, data)
    await feed(transfers, session, data)
    stub.is_open = False  # the session ends before our final acknowledgement
    await transfers.handle(session, FileDone(file_id=FID, sha256=hashlib.sha256(data).digest()))
    assert (tmp_path / "f.bin").read_bytes() == data
    (tmp_path / "s").mkdir()
    transfers2, stub2, transfer, _ = await sender(tmp_path / "s", 10)
    stub2.is_open = False
    await transfers2.cancel(transfer.file_id)
    assert transfer.status is FileStatus.CANCELLED


async def test_accept_after_the_session_closed_removes_the_part_file(tmp_path: Path) -> None:
    transfers, _, stub, session = receiver()
    await offered(transfers, session, b"x" * 10)
    stub.is_open = False
    with pytest.raises(SessionNotOpenError):
        await transfers.accept(FID, tmp_path)
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240


async def test_peer_cancel_while_creating_the_part_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transfers, _, _, session = receiver()
    await offered(transfers, session, b"x" * 10)
    gate = threading.Event()
    real = FileTransfers._create_part

    def slow_create(directory: Path, name: str) -> tuple[Path, Path, object]:
        gate.wait(5)
        return real(directory, name)

    monkeypatch.setattr(FileTransfers, "_create_part", staticmethod(slow_create))
    accepting = asyncio.create_task(transfers.accept(FID, tmp_path))
    await asyncio.sleep(0.01)
    await transfers.handle(session, FileCancel(file_id=FID, reason=FileCancelReason.USER))
    gate.set()
    with pytest.raises(KeyError):
        await accepting
    assert not any(tmp_path.iterdir())  # noqa: ASYNC240


async def test_closing_fails_every_transfer(tmp_path: Path) -> None:
    transfers, _, transfer, _ = await sender(tmp_path, 10)
    await transfers.close()
    assert transfer.status is FileStatus.FAILED
    assert transfers.active() == []


async def test_progress_reports_are_throttled(tmp_path: Path) -> None:
    hooks = Hooks()
    transfers = FileTransfers(hooks, max_size=2**30)
    stub = StubSession()
    source = tmp_path / "big.bin"
    source.write_bytes(os.urandom(3 * 2**20))
    transfer = transfers.offer(cast("Session", stub), source)
    await transfers.handle(cast("Session", stub), FileAccept(file_id=transfer.file_id))
    await until(lambda: any(isinstance(m, FileDone) for m in stub.sent))
    reports = [t for t in hooks.changes if t is transfer]
    assert 3 <= len(reports) <= 6  # about one per MiB, not one per chunk
    assert all(t is not None for t in hooks.changes)
    await transfers.cancel(transfer.file_id)
