"""Saved recordings: ``lab/*.qrlab`` in the data directory (DESIGN §10.1, §11.5).

Each recording is one file with a random name, so its title (inside the sealed body) never
shows on disk. Saving is always an explicit action. A glass-box session can be saved, a normal
one never: its provider had no values to give, and the Inspector's public trace is not a
recording. Opening reads at most :data:`~qrp2p.lab.recording.MAX_FILE` bytes and goes through
the strict decoder; a file that does not open is listed as unreadable rather than hidden.

These functions do blocking file and vault work: the node runs them on its vault thread.
"""

import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from qrp2p.core.crypto.secret import Secret
from qrp2p.lab import trace_schema
from qrp2p.lab.recording import (
    HEADER,
    MAX_FILE,
    SUFFIX,
    Event,
    GlassBoxRecording,
    LabRecording,
    Meta,
    Opened,
    Recording,
    RecordingError,
    Session,
    Traced,
    Value,
    decode,
    encode,
    pack,
    traced,
    unpack,
)
from qrp2p.services.exposure import RecordRevealed, ValueRevealed
from qrp2p.services.paths import ensure_private_dir, write_private_file
from qrp2p.services.trace_bus import BusEvent, SessionInfo, TraceBus, TraceRecord
from qrp2p.services.vault import Vault, VaultError

DIRECTORY: Final = "lab"
LIST_LIMIT: Final = 200
"""Recordings listed at most, newest first."""
_FILE_ID: Final = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True, slots=True)
class RecordingInfo:
    """A saved recording, as a list shows it."""

    file_id: str
    title: str
    kind: str
    """``lab``, ``glass_box`` or ``unreadable`` (another vault's, damaged, or another version)."""
    profile: str
    created: float
    size: int
    problem: str = ""
    """Why an unreadable recording does not open."""


class RecordingStore:
    """The recordings of one data directory.

    Args:
        directory: The ``lab`` folder.
        vault: The vault, which seals and opens recordings with ``k_lab``.
    """

    def __init__(self, directory: Path, vault: Vault) -> None:
        self._dir = directory
        self._vault = vault

    def save(self, recording: Recording) -> RecordingInfo:
        """Seal and write ``recording`` under a new random name.

        Raises:
            RecordingError: It exceeds a bound.
            VaultError: The vault is locked.
        """
        body = encode(recording)
        data = pack(self._vault.seal_lab(HEADER, body))
        file_id = secrets.token_hex(16)
        ensure_private_dir(self._dir)
        write_private_file(self._path(file_id), data)
        return _info(file_id, recording, len(data))

    def list(self) -> list[RecordingInfo]:
        """The saved recordings, newest first (at most :data:`LIST_LIMIT`)."""
        if not self._dir.is_dir():
            return []
        files = [p for p in self._dir.glob(f"*{SUFFIX}") if _FILE_ID.fullmatch(p.stem)]
        files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        found: list[RecordingInfo] = []
        for path in files[:LIST_LIMIT]:
            try:
                found.append(_info(path.stem, self._read(path), path.stat().st_size))
            except (RecordingError, VaultError, OSError) as error:
                found.append(
                    RecordingInfo(path.stem, "", "unreadable", "", 0.0, 0, problem=str(error))
                )
        return found

    def open(self, file_id: str) -> Recording:
        """A saved recording.

        Raises:
            RecordingError: No such recording, or it does not decode.
            VaultError: Locked, or it does not authenticate with this vault.
        """
        return self._read(self._path(file_id))

    def delete(self, file_id: str) -> None:
        """Delete a saved recording (the file only: nothing else refers to it).

        Raises:
            RecordingError: No such recording.
        """
        path = self._path(file_id)
        try:
            path.unlink()
        except FileNotFoundError:
            msg = "that recording no longer exists"
            raise RecordingError(msg) from None

    def _path(self, file_id: str) -> Path:
        if not _FILE_ID.fullmatch(file_id):
            msg = "no such recording"
            raise RecordingError(msg)
        return self._dir / f"{file_id}{SUFFIX}"

    def _read(self, path: Path) -> Recording:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            msg = "that recording no longer exists"
            raise RecordingError(msg) from None
        if size > MAX_FILE:
            msg = "the recording is larger than 256 MiB"
            raise RecordingError(msg)
        with path.open("rb") as file:
            data = file.read(MAX_FILE + 1)
        return decode(self._vault.open_lab(HEADER, unpack(data)))


def _info(file_id: str, recording: Recording, size: int) -> RecordingInfo:
    kind = "lab" if isinstance(recording, LabRecording) else "glass_box"
    meta = recording.meta
    return RecordingInfo(file_id, meta.title, kind, meta.profile, meta.created, size)


# -- a glass-box session's retained trace, as a recording ---------------------------------------


def session_recording(bus: TraceBus, session_id: int, title: str, now: float) -> GlassBoxRecording:
    """What this side retained of a glass-box session, with its revealed values.

    Raises:
        RecordingError: The session is not retained, or it is not a glass-box session.
    """
    info = bus.info(session_id)
    if info is None:
        msg = "that session is no longer retained"
        raise RecordingError(msg)
    if not info.glass_box:
        msg = "only a glass-box session can be saved: a normal session reveals nothing"
        raise RecordingError(msg)
    session = Session(
        initiator=info.initiator,
        started=info.started,
        profile=info.profile,
        peer_short_id=info.peer_short_id,
        established=info.established,
        ended=info.ended,
        end_reason=info.end_reason,
        admit_reason=info.admit_reason,
        by_peer=info.by_peer,
        pin_result=info.pin_result,
        contact_saved=info.contact_saved,
    )
    events = [_event(r) for r in bus.events(session_id)]
    meta = Meta(title=title, created=now, profile=info.profile)
    return GlassBoxRecording(meta=meta, exposed=True, session=session, events=events)


def _event(record: TraceRecord) -> Event:
    ordinal, time = record.ordinal, record.time
    match record.event:
        case ValueRevealed(secret=secret):
            return Value(ordinal, time, label=secret.label, value=secret.reveal())
        case RecordRevealed() as revealed:
            return Opened(
                ordinal,
                time,
                key=revealed.key,
                seq=revealed.seq,
                nonce=revealed.nonce.reveal(),
                plaintext=revealed.plaintext.reveal(),
                opened=revealed.opened,
            )
        case event:
            return traced(ordinal, time, event)


def restored(
    recording: GlassBoxRecording, session_id: int
) -> tuple[SessionInfo, list[TraceRecord]]:
    """A glass-box recording as a bus session to view: its descriptor and its events."""
    session = recording.session
    info = SessionInfo(
        session_id=session_id,
        initiator=session.initiator,
        address="recording",
        started=session.started,
        profile=session.profile,
        peer_short_id=session.peer_short_id,
        glass_box_requested=session.initiator,
        glass_box=True,
        established=session.established,
        ended=True,
        end_reason=session.end_reason,
        admit_reason=session.admit_reason,
        by_peer=session.by_peer,
        pin_result=session.pin_result,
        contact_saved=session.contact_saved,
    )
    return info, [
        TraceRecord(session_id, e.ordinal, e.time, _bus_event(e)) for e in recording.events
    ]


def _bus_event(event: Event) -> BusEvent:
    match event:
        case Value(label=label, value=value):
            return ValueRevealed(Secret(value, label))
        case Opened():
            return RecordRevealed(
                event.key,
                event.seq,
                Secret(event.nonce, f"{event.key}.nonce"),
                Secret(event.plaintext, "plaintext"),
                event.opened,
            )
        case Traced(event=public):
            return trace_schema.to_core(public)
