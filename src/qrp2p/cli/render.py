"""Text rendering for the CLI. Every peer-supplied string goes through ``display_text``."""

import time
from typing import Final

from qrp2p.services.discovery import NearbyPeer
from qrp2p.services.models import (
    Contact,
    Direction,
    FileStatus,
    HistoryEntry,
    MessageKind,
    MessageStatus,
    TrustState,
)
from qrp2p.services.text import display_text

NAME_LIMIT: Final = 40
_KIB: Final = 1024

_STATUS_MARK: Final = {
    MessageStatus.SENDING: "…",
    MessageStatus.SENT: "✓",
    MessageStatus.DELIVERED: "✓✓",
    MessageStatus.RECEIVED: "",
    MessageStatus.FAILED: "✗ not sent",
}
_TRUST: Final = {
    TrustState.PINNED: "pinned (not verified)",
    TrustState.VERIFIED: "VERIFIED",
    TrustState.BLOCKED: "blocked",
}


def name(text: str) -> str:
    """A peer-supplied or user-given name, safe for the terminal."""
    return display_text(text, limit=NAME_LIMIT)


def clock_time(timestamp: float) -> str:
    """``HH:MM`` in local time."""
    return time.strftime("%H:%M", time.localtime(timestamp))


def size(n: int) -> str:
    """``1.5 MiB``."""
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < _KIB or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= _KIB
    return f"{n} B"  # pragma: no cover  # unreachable


def parse_size(text: str) -> int:
    """``"10M"`` → 10 MiB; plain numbers are bytes.

    Raises:
        ValueError: Not a size.
    """
    text = text.strip().upper().removesuffix("B").removesuffix("I")
    factor = {"K": 2**10, "M": 2**20, "G": 2**30}.get(text[-1:], 1)
    number = text[:-1] if factor > 1 else text
    value = int(float(number) * factor)
    if value < 0:
        msg = "negative size"
        raise ValueError(msg)
    return value


def contact_line(index: int, contact: Contact, *, online: bool, detail: str = "") -> str:
    """One row of ``/contacts``."""
    dot = "●" if online else "○"
    trust = _TRUST[contact.trust]
    extra = f"  {detail}" if detail else ""
    return f"{index:>3}. {dot} {name(contact.name):<20} {contact.short_id}  {trust}{extra}"


def nearby_line(index: int, peer: NearbyPeer, contact: Contact | None) -> str:
    """One row of ``/nearby``."""
    known = f"  (contact {name(contact.name)})" if contact is not None else ""
    return f"{index:>3}. {name(peer.label)}  {peer.addresses[0]}:{peer.port}{known}"


def entry_line(contact: Contact, entry: HistoryEntry) -> str:
    """One history entry."""
    stamp = clock_time(entry.time)
    tag = " [GLASS-BOX]" if entry.glass_box else ""
    who = "you" if entry.direction is Direction.OUT else name(contact.name)
    match entry.kind:
        case MessageKind.CHAT:
            mark = _STATUS_MARK[entry.status] if entry.direction is Direction.OUT else ""
            text = display_text(entry.text, keep_newlines=True).replace("\n", "\n        ")
            return f"[{stamp}]{tag} {who}: {text}{'  ' + mark if mark else ''}"
        case MessageKind.FILE:
            return f"[{stamp}]{tag} {who}: {file_text(entry)}"
        case MessageKind.IDENTITY_CHANGED:
            return (
                f"[{stamp}] ** identity changed: {entry.text} (re-pinned; verify the safety number)"
            )


def file_text(entry: HistoryEntry) -> str:
    """A file entry's description."""
    info = entry.file
    if info is None:
        return "file"
    what = f"file {name(info.name)!r} ({size(info.size)})"
    match info.status:
        case FileStatus.OFFERED:
            return f"{what} offered"
        case FileStatus.COMPLETE if entry.direction is Direction.IN:
            return f"{what} saved to {display_text(info.path)}"
        case FileStatus.CANCELLED | FileStatus.FAILED if info.reason:
            return f"{what} {info.status.value} ({info.reason})"
        case _:
            return f"{what} {info.status.value}"


def safety_grid(groups: tuple[str, ...]) -> str:
    """The safety number as three rows of four groups."""
    rows = [" ".join(groups[i : i + 4]) for i in range(0, len(groups), 4)]
    return "\n".join(f"    {row}" for row in rows)
