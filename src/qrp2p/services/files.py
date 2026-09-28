"""File transfer (DESIGN §9): offers, streaming with flow control, verification, safe names.

```text
sender                                    receiver
file_offer {file_id, name, size, type} ─▶ sanitise name; limits; ask the user (or auto-accept)
                                     ◀─ file_accept (after a free-space check) | file_decline
file_chunk ...    (≤ 4 MiB unacknowledged) ─▶ append to <name>.part (worker thread)
                                     ◀─ file_progress {received} every 1 MiB
file_done {sha256}                     ─▶ check size and hash, rename .part → name
                                     ◀─ file_progress {received = size}: delivered
file_cancel {reason} at any time, from either side; the partial file is deleted
```

``file_done`` travels at file priority, behind the last chunk; offers, answers and cancels at
chat priority. Messages for a transfer that one side has just cancelled can still be in flight
and are ignored; messages for a transfer that never existed close the session
(``unexpected_message``).
"""

import asyncio
import contextlib
import ctypes
import ctypes.util
import errno
import hashlib
import hmac
import logging
import mimetypes
import os
import shutil
import sys
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Final, Protocol

from qrp2p.core.errors import CloseReason, FileCancelReason
from qrp2p.core.events import Priority
from qrp2p.core.wire import (
    MAX_CHUNK_BYTES,
    MAX_MEDIA_TYPE_BYTES,
    MAX_NAME_BYTES,
    FileAccept,
    FileCancel,
    FileChunk,
    FileDecline,
    FileDone,
    FileOffer,
    FileProgress,
)
from qrp2p.services.limits import MAX_PENDING_OFFERS
from qrp2p.services.models import ID_LEN, FileStatus
from qrp2p.services.session import Session, SessionNotOpenError
from qrp2p.services.text import is_unsafe_char

PROGRESS_EVERY: Final = 2**20
"""The receiver reports progress every 1 MiB."""
WINDOW: Final = 4 * 2**20
"""The sender keeps at most 4 MiB unacknowledged."""
READ_BLOCK: Final = 2**20
"""Disk reads and writes happen in 1 MiB blocks, in a worker thread."""
FREE_SPACE_MARGIN: Final = 16 * 2**20
"""Space left free on the target disk after a file is accepted."""
DEFAULT_MEDIA_TYPE: Final = "application/octet-stream"
PART_SUFFIX: Final = ".part"
NAME_BUDGET: Final = MAX_NAME_BYTES - len(PART_SUFFIX) - len(" (99999)")
"""Received names are cut to this many bytes, so ``.part`` and a clash suffix still fit."""

_WINDOWS_FORBIDDEN: Final = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED: Final = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{dev}{n}" for dev in ("COM", "LPT") for n in (*"123456789", "¹", "²", "³")}
)

type FileKey = tuple[int, bytes]
"""A transfer is identified by its session and its ``file_id``."""
type TransferMessage = (
    FileOffer | FileAccept | FileDecline | FileChunk | FileProgress | FileDone | FileCancel
)

_log = logging.getLogger(__name__)


# --- names and marks ------------------------------------------------------------------------------


def _truncate_utf8(text: str, limit: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", "ignore")


def split_extension(name: str) -> tuple[str, str]:
    """``("report", ".pdf")``; a leading dot is not an extension."""
    dot = name.rfind(".")
    if dot <= 0:
        return name, ""
    return name[:dot], name[dot:]


def sanitize_name(name: str) -> str:
    """Turn a peer-supplied file name into a safe base name (DESIGN §9).

    NFC; the last path component only; control, bidirectional-override and Windows-forbidden
    characters (including ``:`` and both separators) replaced by ``_``; no leading dot (no hidden
    files, no ``..``); no trailing dots or spaces; Windows reserved device names prefixed; at most
    :data:`NAME_BUDGET` bytes of UTF-8, keeping a short extension.
    """
    name = unicodedata.normalize("NFC", name)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join("_" if is_unsafe_char(c) or c in _WINDOWS_FORBIDDEN else c for c in name)
    name = name.strip(" ").rstrip(". ")
    if name.startswith("."):
        name = "_" + name[1:]
    if not name.strip("._ "):
        name = "file"
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if stem in _WINDOWS_RESERVED:
        name = "_" + name
    if len(name.encode("utf-8")) > NAME_BUDGET:
        base, ext = split_extension(name)
        if len(ext.encode("utf-8")) > 32:  # noqa: PLR2004  # keep only short extensions
            base, ext = name, ""
        name = _truncate_utf8(base, NAME_BUDGET - len(ext.encode("utf-8"))).rstrip(". ") + ext
    return name


def unique_path(directory: Path, name: str) -> Path:
    """A path in ``directory`` for ``name`` that clashes with nothing, case-insensitively.

    Clashes become ``name (2).ext``, ``name (3).ext``, …; the ``.part`` file must be free too.
    """
    taken = {entry.name.casefold() for entry in directory.iterdir()}
    base, ext = split_extension(name)
    candidate, n = name, 2
    while candidate.casefold() in taken or (candidate + PART_SUFFIX).casefold() in taken:
        candidate = f"{base} ({n}){ext}"
        n += 1
    return directory / candidate


def mark_downloaded(path: Path) -> bool:
    """Give ``path`` the OS "downloaded from elsewhere" mark; ``False`` if it could not be set.

    Windows: the ``Zone.Identifier`` stream (Mark of the Web, Internet zone). macOS: the
    ``com.apple.quarantine`` attribute. Linux has no such mark; nothing is done there.
    """
    try:
        if sys.platform == "win32":
            with Path(f"{path}:Zone.Identifier").open("w", encoding="ascii") as stream:
                stream.write("[ZoneTransfer]\r\nZoneId=3\r\n")
            return True
        if sys.platform == "darwin":
            return _set_quarantine(path)
    except OSError:
        _log.warning("could not mark a received file as downloaded")
        return False
    return False


def _set_quarantine(path: Path) -> bool:  # pragma: no cover  # macOS only
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        return False
    libc = ctypes.CDLL(libc_name, use_errno=True)
    value = f"0081;{int(time.time()):08x};QRP2P;".encode("ascii")
    result = libc.setxattr(os.fsencode(path), b"com.apple.quarantine", value, len(value), 0, 0)
    return result == 0


def rename_no_replace(source: Path, target: Path) -> None:
    """Rename ``source`` to ``target``; fail rather than overwrite an existing ``target``.

    Raises:
        FileExistsError: ``target`` exists.
    """
    if sys.platform == "win32":
        source.rename(target)  # Windows refuses to rename over an existing file
        return
    try:
        target.hardlink_to(source)  # atomic, and fails if target exists
    except FileExistsError:
        raise
    except OSError as error:  # a file system without hard links (FAT, some network mounts)
        if error.errno not in {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV}:
            raise
        if target.exists():
            raise FileExistsError(errno.EEXIST, "target exists") from None
        source.rename(target)
        return
    source.unlink()


def media_type_of(path: Path) -> str:
    """The media type guessed from the extension, else ``application/octet-stream``."""
    guessed, _ = mimetypes.guess_type(path.name, strict=False)
    if guessed is None or len(guessed.encode("utf-8")) > MAX_MEDIA_TYPE_BYTES:
        return DEFAULT_MEDIA_TYPE
    return guessed


# --- transfers --------------------------------------------------------------------------------------


class TransferDirection(StrEnum):
    """Which way the file goes."""

    OUT = "out"
    IN = "in"


class PeerMisbehavedError(Exception):
    """The peer broke the transfer protocol; the session closes with ``reason``."""

    def __init__(self, reason: CloseReason) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(slots=True)
class TransferIo:
    """A transfer's working state: files, hash, flow control."""

    task: asyncio.Task[None] | None = None
    window: asyncio.Event = field(default_factory=asyncio.Event)
    part: Path | None = None
    stream: BinaryIO | None = None
    hasher: hashlib._Hash = field(default_factory=hashlib.sha256)  # pyright: ignore[reportPrivateUsage]
    buffer: bytearray = field(default_factory=bytearray)
    reported: int = 0
    done_sent: bool = False
    final_ack: bool = False
    """Outgoing: the receiver reported ``received = size``, which it does only after verifying."""


@dataclass(eq=False, slots=True)
class Transfer:
    """One file transfer, either way. The node reads it; only :class:`FileTransfers` writes it."""

    file_id: bytes
    session: Session
    direction: TransferDirection
    name: str
    """Outgoing: the name offered. Incoming: the sanitised name."""
    size: int
    media_type: str
    status: FileStatus = FileStatus.OFFERED
    transferred: int = 0
    """Bytes sent (out) or received and written (in)."""
    acknowledged: int = 0
    """Outgoing: what the receiver reported."""
    sha256: bytes = b""
    path: Path | None = None
    """Outgoing: the source. Incoming: the final path, once accepted."""
    reason: FileCancelReason | None = None
    by_peer: bool = False
    entry_id: bytes = b""
    """The node's history entry for this transfer."""
    created: float = 0.0
    """Wall-clock time the node first recorded the transfer."""
    io: TransferIo = field(default_factory=TransferIo)
    """Working state of :class:`FileTransfers`; nothing else touches it."""

    @property
    def key(self) -> FileKey:
        """``(session id, file_id)``."""
        return (self.session.id, self.file_id)

    @property
    def finished(self) -> bool:
        """Complete, declined, cancelled or failed."""
        return self.status in _FINAL


_FINAL: Final = frozenset(
    {FileStatus.COMPLETE, FileStatus.DECLINED, FileStatus.CANCELLED, FileStatus.FAILED}
)


class TransferHooks(Protocol):
    """What file transfers report to the node."""

    def offered(self, transfer: Transfer, /) -> None:
        """An incoming offer passed the limits; accept, decline or leave it pending."""
        ...

    def changed(self, transfer: Transfer, /) -> None:
        """Status or progress changed (throttled to about once per MiB)."""
        ...


class FileTransfers:
    """Every file transfer of the node.

    Args:
        hooks: The node.
        random_bytes: Randomness for file IDs.
        max_size: The largest incoming file accepted (DESIGN §9, default 4 GiB).
    """

    def __init__(
        self,
        hooks: TransferHooks,
        *,
        random_bytes: Callable[[int], bytes] = os.urandom,
        max_size: int,
    ) -> None:
        self._hooks = hooks
        self._random = random_bytes
        self.max_size = max_size
        self._outgoing: dict[FileKey, Transfer] = {}
        self._incoming: dict[FileKey, Transfer] = {}
        self._finished: dict[FileKey, TransferDirection] = {}
        """Transfers that ended, so late messages for them are ignored rather than fatal."""

    # -- queries ------------------------------------------------------------------------------------

    def get(self, file_id: bytes) -> Transfer | None:
        """A live transfer by ``file_id`` (incoming first)."""
        for table in (self._incoming, self._outgoing):
            for (_, fid), transfer in table.items():
                if fid == file_id:
                    return transfer
        return None

    def active(self) -> list[Transfer]:
        """Every transfer that has not finished."""
        return [*self._incoming.values(), *self._outgoing.values()]

    def pending_offers(self, peer_id: bytes) -> int:
        """Incoming offers from ``peer_id`` that wait for a decision."""
        return sum(
            1
            for t in self._incoming.values()
            if t.status is FileStatus.OFFERED
            and t.session.peer is not None
            and t.session.peer.peer_id == peer_id
        )

    # -- sending ------------------------------------------------------------------------------------

    def offer(self, session: Session, path: Path, entry_id: bytes = b"") -> Transfer:
        """Offer ``path`` to the session's peer.

        Raises:
            OSError: The file cannot be read.
            SessionNotOpenError: The session is not open.
        """
        path = path.resolve()
        size = path.stat().st_size
        if not path.is_file():
            raise IsADirectoryError(errno.EISDIR, "not a regular file")
        name = _truncate_utf8(path.name, MAX_NAME_BYTES)
        transfer = Transfer(
            file_id=self._random(ID_LEN),
            session=session,
            direction=TransferDirection.OUT,
            name=name,
            size=size,
            media_type=media_type_of(path),
            path=path,
            entry_id=entry_id,
        )
        offer = FileOffer(
            file_id=transfer.file_id, name=name, size=size, media_type=transfer.media_type
        )
        session.send(offer, Priority.CHAT)
        self._outgoing[transfer.key] = transfer
        return transfer

    async def _send_file(self, transfer: Transfer) -> None:
        source = transfer.path
        assert source is not None  # noqa: S101  # outgoing transfers have a source
        session = transfer.session
        try:
            stream = await _owned_in_thread(lambda: source.open("rb"), _close_quietly)
        except OSError:
            self._cancel(transfer, FileCancelReason.USER, notify=True, status=FileStatus.FAILED)
            return
        try:
            while transfer.transferred < transfer.size:
                block = await asyncio.to_thread(
                    stream.read, min(READ_BLOCK, transfer.size - transfer.transferred)
                )
                if not block:
                    break  # the file shrank since the offer
                transfer.io.hasher.update(block)
                for start in range(0, len(block), MAX_CHUNK_BYTES):
                    data = block[start : start + MAX_CHUNK_BYTES]
                    while transfer.transferred - transfer.acknowledged >= WINDOW:
                        transfer.io.window.clear()
                        await transfer.io.window.wait()
                        if transfer.finished:
                            return
                    await session.send_bulk(FileChunk(file_id=transfer.file_id, data=data))
                    transfer.transferred += len(data)
                    self._progress(transfer)
            if transfer.transferred != transfer.size or await asyncio.to_thread(stream.read, 1):
                self._cancel(transfer, FileCancelReason.SIZE_MISMATCH, notify=True)
                return
            transfer.sha256 = transfer.io.hasher.digest()
            await session.send_bulk(FileDone(file_id=transfer.file_id, sha256=transfer.sha256))
            transfer.io.done_sent = True
            self._maybe_delivered(transfer)
        except SessionNotOpenError:
            self._fail(transfer)
        finally:
            stream.close()  # no await here: the task may be cancelled

    # -- receiving ----------------------------------------------------------------------------------

    async def accept(self, file_id: bytes, directory: Path) -> Transfer:
        """Accept an incoming offer into ``directory``.

        Checks free space first; too little cancels the transfer with ``disk_full``.

        Raises:
            KeyError: No pending offer with this ID.
            SessionNotOpenError: The session ended.
        """
        transfer = self._pending(file_id)

        def free_space() -> int:
            directory.mkdir(parents=True, exist_ok=True)
            return shutil.disk_usage(directory).free

        free = await asyncio.to_thread(free_space)
        if transfer.finished:  # the peer cancelled while we looked
            raise KeyError(file_id)
        if free < transfer.size + FREE_SPACE_MARGIN:
            self._cancel(transfer, FileCancelReason.DISK_FULL, notify=True)
            return transfer
        name = transfer.name
        part, final, stream = await _owned_in_thread(
            lambda: self._create_part(directory, name), _remove_part
        )
        if transfer.finished:  # the peer cancelled while we created the file
            await asyncio.to_thread(_remove_part, (part, final, stream))
            raise KeyError(file_id)
        transfer.io.part, transfer.path, transfer.io.stream = part, final, stream
        transfer.status = FileStatus.TRANSFERRING
        try:
            transfer.session.send(FileAccept(file_id=file_id), Priority.CHAT)
        except SessionNotOpenError:
            await self._discard(transfer)
            raise
        self._hooks.changed(transfer)
        return transfer

    @staticmethod
    def _create_part(directory: Path, name: str) -> tuple[Path, Path, BinaryIO]:
        """Create and open ``<final>.part`` with exclusive create, marked as downloaded."""
        directory.mkdir(parents=True, exist_ok=True)
        for _ in range(100):
            final = unique_path(directory, name)
            part = final.with_name(final.name + PART_SUFFIX)
            try:
                stream = part.open("xb")
            except FileExistsError:
                continue  # raced with another writer; pick the next name
            mark_downloaded(part)
            return part, final, stream
        raise FileExistsError(errno.EEXIST, "no free file name")

    def decline(self, file_id: bytes) -> Transfer:
        """Decline an incoming offer.

        Raises:
            KeyError: No pending offer with this ID.
        """
        transfer = self._pending(file_id)
        with contextlib.suppress(SessionNotOpenError):
            transfer.session.send(FileDecline(file_id=file_id), Priority.CHAT)
        self._finish(transfer, FileStatus.DECLINED)
        return transfer

    def _pending(self, file_id: bytes) -> Transfer:
        transfer = self.get(file_id)
        if (
            transfer is None
            or transfer.direction is not TransferDirection.IN
            or transfer.status is not FileStatus.OFFERED
        ):
            raise KeyError(file_id)
        return transfer

    async def cancel(self, file_id: bytes) -> Transfer:
        """Cancel a transfer by our user's choice (either direction).

        Raises:
            KeyError: No live transfer with this ID.
        """
        transfer = self.get(file_id)
        if transfer is None:
            raise KeyError(file_id)
        self._cancel(transfer, FileCancelReason.USER, notify=True)
        await self._discard(transfer)
        return transfer

    # -- messages from the peer ---------------------------------------------------------------------

    async def handle(self, session: Session, message: TransferMessage) -> None:
        """Act on a file-transfer message from ``session``'s peer.

        Raises:
            PeerMisbehavedError: The message is invalid in the transfer's state.
        """
        key = (session.id, message.file_id)
        match message:
            case FileOffer():
                self._on_offer(session, message)
            case FileAccept() | FileDecline() | FileProgress():
                transfer = self._live(self._outgoing, key, TransferDirection.OUT)
                if transfer is not None:
                    self._on_answer(transfer, message)
            case FileChunk():
                transfer = self._live(self._incoming, key, TransferDirection.IN)
                if transfer is not None:
                    await self._on_chunk(transfer, message.data)
            case FileDone():
                transfer = self._live(self._incoming, key, TransferDirection.IN)
                if transfer is not None:
                    await self._on_done(transfer, message.sha256)
            case FileCancel():
                transfer = self._incoming.get(key) or self._outgoing.get(key)
                if transfer is None:
                    self._require_finished(key)
                    return
                self._cancel(transfer, message.reason, notify=False, by_peer=True)
                await self._discard(transfer)

    def _live(
        self, table: dict[FileKey, Transfer], key: FileKey, direction: TransferDirection
    ) -> Transfer | None:
        transfer = table.get(key)
        if transfer is None:
            if self._finished.get(key) is not direction:
                raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)
            return None  # in flight when the transfer ended: ignore
        return transfer

    def _require_finished(self, key: FileKey) -> None:
        if key not in self._finished:
            raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)

    def _on_offer(self, session: Session, offer: FileOffer) -> None:
        key = (session.id, offer.file_id)
        if key in self._incoming or key in self._outgoing or key in self._finished:
            raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)
        transfer = Transfer(
            file_id=offer.file_id,
            session=session,
            direction=TransferDirection.IN,
            name=sanitize_name(offer.name),
            size=offer.size,
            media_type=offer.media_type,
        )
        self._incoming[key] = transfer
        peer = session.peer
        too_many = peer is not None and self.pending_offers(peer.peer_id) > MAX_PENDING_OFFERS
        if offer.size > self.max_size or too_many:
            self._cancel(transfer, FileCancelReason.LIMIT, notify=True)
            return
        self._hooks.offered(transfer)

    def _on_answer(
        self, transfer: Transfer, message: FileAccept | FileDecline | FileProgress
    ) -> None:
        match message:
            case FileAccept():
                if transfer.status is not FileStatus.OFFERED:
                    raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)
                transfer.status = FileStatus.TRANSFERRING
                self._hooks.changed(transfer)
                transfer.io.task = asyncio.create_task(
                    self._send_file(transfer), name=f"qrp2p-file-{transfer.file_id.hex()[:8]}"
                )
            case FileDecline():
                if transfer.status is not FileStatus.OFFERED:
                    raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)
                transfer.by_peer = True
                self._finish(transfer, FileStatus.DECLINED)
            case FileProgress():
                received = message.received
                if (
                    transfer.status is not FileStatus.TRANSFERRING
                    or received < transfer.acknowledged
                    or received > transfer.transferred
                ):
                    raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)
                transfer.acknowledged = received
                transfer.io.final_ack = received == transfer.size
                transfer.io.window.set()
                self._maybe_delivered(transfer)

    def _maybe_delivered(self, transfer: Transfer) -> None:
        if transfer.io.done_sent and transfer.io.final_ack:
            self._finish(transfer, FileStatus.COMPLETE)

    async def _on_chunk(self, transfer: Transfer, data: bytes) -> None:
        if transfer.status is not FileStatus.TRANSFERRING:
            raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)  # before our accept
        if transfer.transferred + len(transfer.io.buffer) + len(data) > transfer.size:
            self._cancel(transfer, FileCancelReason.SIZE_MISMATCH, notify=True)
            await self._discard(transfer)
            return
        transfer.io.buffer += data
        if len(transfer.io.buffer) >= READ_BLOCK:
            await self._flush(transfer)

    async def _flush(self, transfer: Transfer) -> None:
        buffer = bytes(transfer.io.buffer)
        transfer.io.buffer.clear()
        if not buffer:
            return
        stream = transfer.io.stream
        assert stream is not None  # noqa: S101  # open while transferring
        try:
            await asyncio.to_thread(stream.write, buffer)
        except ValueError:  # our user cancelled meanwhile, which closed the file
            if transfer.finished:
                return
            raise
        except OSError as error:
            disk_full = error.errno == errno.ENOSPC
            reason = FileCancelReason.DISK_FULL if disk_full else FileCancelReason.USER
            self._cancel(transfer, reason, notify=True, status=FileStatus.FAILED)
            await self._discard(transfer)
            return
        transfer.io.hasher.update(buffer)
        transfer.transferred += len(buffer)
        if transfer.transferred // PROGRESS_EVERY > transfer.io.reported // PROGRESS_EVERY and (
            transfer.transferred < transfer.size
        ):
            transfer.io.reported = transfer.transferred
            with contextlib.suppress(SessionNotOpenError):
                transfer.session.send(
                    FileProgress(file_id=transfer.file_id, received=transfer.transferred),
                    Priority.CONTROL,
                )
        self._hooks.changed(transfer)

    async def _on_done(self, transfer: Transfer, sha256: bytes) -> None:
        if transfer.status is not FileStatus.TRANSFERRING:
            raise PeerMisbehavedError(CloseReason.UNEXPECTED_MESSAGE)
        await self._flush(transfer)
        if transfer.finished:  # the final write failed
            return
        if transfer.transferred != transfer.size:
            self._cancel(transfer, FileCancelReason.SIZE_MISMATCH, notify=True)
            await self._discard(transfer)
            return
        digest = transfer.io.hasher.digest()
        if not hmac.compare_digest(digest, sha256):
            self._cancel(transfer, FileCancelReason.HASH_MISMATCH, notify=True)
            await self._discard(transfer)
            return
        transfer.sha256 = digest
        stream, part, final = transfer.io.stream, transfer.io.part, transfer.path
        assert stream is not None and part is not None and final is not None  # noqa: S101, PT018
        transfer.io.stream = None
        await asyncio.to_thread(_sync_and_close, stream)
        transfer.path = await asyncio.to_thread(_rename_final, part, final, transfer.name)
        transfer.io.part = None
        with contextlib.suppress(SessionNotOpenError):
            transfer.session.send(
                FileProgress(file_id=transfer.file_id, received=transfer.size), Priority.CONTROL
            )
        self._finish(transfer, FileStatus.COMPLETE)

    # -- ending ---------------------------------------------------------------------------------------

    def _cancel(
        self,
        transfer: Transfer,
        reason: FileCancelReason,
        *,
        notify: bool,
        by_peer: bool = False,
        status: FileStatus = FileStatus.CANCELLED,
    ) -> None:
        if transfer.finished:
            return
        if notify:
            with contextlib.suppress(SessionNotOpenError):
                transfer.session.send(
                    FileCancel(file_id=transfer.file_id, reason=reason), Priority.CHAT
                )
        transfer.reason = reason
        transfer.by_peer = by_peer
        self._finish(transfer, status)

    def _fail(self, transfer: Transfer) -> None:
        if not transfer.finished:
            self._finish(transfer, FileStatus.FAILED)

    def _finish(self, transfer: Transfer, status: FileStatus) -> None:
        transfer.status = status
        key = transfer.key
        table = self._incoming if transfer.direction is TransferDirection.IN else self._outgoing
        table.pop(key, None)
        self._finished[key] = transfer.direction
        transfer.io.window.set()  # wakes a sender waiting for acknowledgements
        task = transfer.io.task
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()
        if transfer.direction is TransferDirection.IN and status is not FileStatus.COMPLETE:
            self._schedule_discard(transfer)
        self._hooks.changed(transfer)

    def _schedule_discard(self, transfer: Transfer) -> None:
        if transfer.io.stream is None and transfer.io.part is None:
            return
        with contextlib.suppress(RuntimeError):  # no running loop: discard synchronously
            asyncio.get_running_loop().create_task(self._discard(transfer))
            return
        _discard_now(transfer)

    async def _discard(self, transfer: Transfer) -> None:
        """Close and delete an incoming transfer's partial file."""
        await asyncio.to_thread(_discard_now, transfer)

    async def session_ended(self, session: Session) -> None:
        """Fail every unfinished transfer of an ended session; delete partial files."""
        for transfer in [t for t in self.active() if t.session is session]:
            self._fail(transfer)
            if transfer.direction is TransferDirection.IN:
                await self._discard(transfer)
        self._finished = {k: v for k, v in self._finished.items() if k[0] != session.id}

    async def close(self) -> None:
        """Fail everything (on lock or exit)."""
        for session in {t.session for t in self.active()}:
            await self.session_ended(session)

    def _progress(self, transfer: Transfer) -> None:
        if transfer.transferred - transfer.io.reported >= PROGRESS_EVERY:
            transfer.io.reported = transfer.transferred
            self._hooks.changed(transfer)


async def _owned_in_thread[T](work: Callable[[], T], release: Callable[[T], None]) -> T:
    """Run ``work`` in a thread; if we are cancelled meanwhile, ``release`` what it returns.

    Without this, a file opened by the thread after our task was cancelled would never be
    closed (or a ``.part`` file never deleted).
    """
    future = asyncio.ensure_future(asyncio.to_thread(work))
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:

        def cleanup(done: asyncio.Future[T]) -> None:
            if not done.cancelled() and done.exception() is None:
                release(done.result())

        future.add_done_callback(cleanup)
        raise


def _close_quietly(stream: BinaryIO) -> None:
    with contextlib.suppress(OSError):
        stream.close()


def _remove_part(created: tuple[Path, Path, BinaryIO]) -> None:
    part, _, stream = created
    _close_quietly(stream)
    with contextlib.suppress(FileNotFoundError):
        part.unlink()


def _discard_now(transfer: Transfer) -> None:
    stream, part = transfer.io.stream, transfer.io.part
    transfer.io.stream = None
    transfer.io.part = None
    if stream is not None:
        with contextlib.suppress(OSError):
            stream.close()
    if part is not None:
        with contextlib.suppress(FileNotFoundError):
            part.unlink()


def _sync_and_close(stream: BinaryIO) -> None:
    try:
        stream.flush()
        os.fsync(stream.fileno())
    finally:
        stream.close()


def _rename_final(part: Path, final: Path, name: str) -> Path:
    """Move ``.part`` to the final name, choosing another if one appeared meanwhile."""
    for _ in range(100):
        try:
            rename_no_replace(part, final)
        except FileExistsError:
            final = unique_path(final.parent, name)
            continue
        return final
    raise FileExistsError(errno.EEXIST, "no free file name")
