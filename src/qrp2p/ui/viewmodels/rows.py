"""What each list row shows, computed from snapshots by pure functions (UI_DESIGN §6, §10).

View models call these and hand the result to :meth:`RowModel.sync`. Keeping the computation pure
keeps the user-facing wording and the grouping rules testable without a running UI, and makes
sure a row's look depends only on service facts, never on the order updates happened to arrive.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from qrp2p.ui.snapshots import ContactSnap, MessageSnap, NearbySnap
from qrp2p.ui.text import isolate

GROUP_GAP: Final = 180.0
"""Seconds within which messages of one sender form a group."""


@dataclass(frozen=True, slots=True)
class Formats:
    """Locale-dependent formatting, injected so the row functions stay pure."""

    time: Callable[[float], str]
    """Wall-clock seconds → a short local time."""
    day: Callable[[float], str]
    """Wall-clock seconds → ``Today``, ``Yesterday`` or a date; equal for equal days."""
    size: Callable[[int], str]
    """Bytes → a short human size."""


# -- contacts ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContactRow:
    """A contact in the strip or the chooser."""

    contact_id: str
    name: str
    initial: str
    short_id: str
    trust: str
    presence: str
    """``online``, ``connecting``, ``waiting``, ``nearby``, ``blocked`` or ``offline``."""
    presence_text: str
    unread: int
    glass_box: bool
    description: str
    """Everything above in one sentence, for screen readers and tooltips."""


TRUST_TEXT: Final = {"verified": "Verified", "pinned": "Not verified", "blocked": "Blocked"}


def initial(name: str) -> str:
    """The avatar letter: the name's first character, upper-cased."""
    stripped = name.strip()
    return stripped[:1].upper() if stripped else "?"


def presence(contact: ContactSnap, connecting: str, *, nearby: bool) -> tuple[str, str]:
    """A contact's availability and its label.

    ``connecting`` is ``""``, ``connecting`` or ``waiting``. Discovery presence is only a hint,
    never an open session (UI_DESIGN §3.1).
    """
    if contact.session is not None:
        return "online", "Online"
    if connecting == "waiting":
        return "waiting", "Waiting for them to accept"
    if connecting:
        return "connecting", "Connecting…"
    if contact.trust == "blocked":
        return "blocked", "Blocked"
    if nearby:
        return "nearby", "Nearby"
    return "offline", "Offline"


def contact_row(contact: ContactSnap, *, connecting: str, nearby: bool, unread: int) -> ContactRow:
    """One contact's row."""
    state, text = presence(contact, connecting, nearby=nearby)
    glass_box = contact.session is not None and contact.session.glass_box
    parts = [contact.name, TRUST_TEXT.get(contact.trust, contact.trust), text]
    if glass_box:
        parts.append("glass-box session")
    if unread:
        parts.append(f"{unread} unread")
    parts.append(f"ID {contact.short_id}")
    return ContactRow(
        contact_id=contact.contact_id,
        name=contact.name,
        initial=initial(contact.name),
        short_id=contact.short_id,
        trust=contact.trust,
        presence=state,
        presence_text=text,
        unread=unread,
        glass_box=glass_box,
        description=", ".join(parts),
    )


def strip_order(
    previous: Sequence[str], activity: Mapping[str, float], selected: str, limit: int
) -> list[str]:
    """The contacts the strip shows: the ``limit`` most recently active, always the selected one.

    Contacts already shown keep their places, and newcomers enter at the front: a message from a
    contact who is already visible never reshuffles the chips under the pointer.
    """
    ranked = sorted(activity, key=lambda c: (-activity[c], c))
    wanted = ranked[:limit]
    if selected and selected in activity and selected not in wanted:
        wanted = [*wanted[: max(limit - 1, 0)], selected]
    keep = [c for c in previous if c in wanted]
    new = [c for c in wanted if c not in keep]
    return new + keep


@dataclass(frozen=True, slots=True)
class NearbyRow:
    """A peer announced on the LAN that is not one of our contacts."""

    key: str
    label: str
    id_hint: str
    addresses: str
    profiles: str


def nearby_row(peer: NearbySnap) -> NearbyRow:
    """An announced peer; everything shown is an unauthenticated hint."""
    hint = peer.id_hint[:8]
    return NearbyRow(
        key=peer.key,
        label=peer.label,
        id_hint=f"{hint[:4]} {hint[4:]}".upper(),
        addresses=", ".join(peer.addresses),
        profiles=", ".join(peer.profiles),
    )


# -- messages ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MessageRow:
    """A message, file transfer or local note in a conversation."""

    entry_id: str
    kind: str
    """``chat``, ``file`` or ``identity_changed``."""
    direction: str
    text: str
    time_text: str
    status: str
    status_text: str
    glass_box: bool
    file_id: str
    file_name: str
    file_size_text: str
    file_status: str
    file_state_text: str
    file_progress: float
    """0..1 while transferring; -1 when no measured progress applies."""
    file_path: str
    file_busy: bool
    """An answer to this transfer is on its way: its actions are not offered again."""
    day_label: str
    """Set on the first message of a day."""
    group_start: bool
    group_end: bool
    show_meta: bool
    """Show the time and delivery state under this message."""


STATUS_TEXT: Final = {
    "sending": "Sending…",
    "sent": "Sent",
    "delivered": "Delivered",
    "failed": "Not sent",
    "received": "",
}

FILE_REASON_TEXT: Final = {
    "user": "",
    "size_mismatch": "the size did not match",
    "hash_mismatch": "the checksum did not match",
    "disk_full": "not enough disk space",
    "limit": "over the size limit",
}


def file_state(  # noqa: PLR0911  # one outcome per transfer state
    message: MessageSnap, progress: int | None, peer: str, formats: Formats
) -> tuple[str, float]:
    """A transfer's state in words, and its measured progress (-1 when none applies)."""
    file = message.file
    assert file is not None  # noqa: S101  # only called for file entries
    outgoing = message.direction == "out"
    reason = FILE_REASON_TEXT.get(file.reason, file.reason)
    match file.status:
        case "offered":
            text = (
                f"Waiting for {isolate(peer)} to accept"
                if outgoing
                else "Wants to send you this file"
            )
            return text, -1.0
        case "accepted":
            return "Starting…", -1.0
        case "transferring":
            done = progress or 0
            fraction = min(done / file.size, 1.0) if file.size else 1.0
            return f"{formats.size(done)} of {formats.size(file.size)}", fraction
        case "complete":
            return ("Delivered and verified" if outgoing else "Saved and verified"), -1.0
        case "declined":
            return "Declined", -1.0
        case "cancelled":
            return (f"Cancelled: {reason}" if reason else "Cancelled"), -1.0
        case _:
            return (f"Failed: {reason}" if reason else "Failed"), -1.0


def _groupable(a: MessageSnap, b: MessageSnap) -> bool:
    return (
        a.kind == b.kind == "chat"
        and a.direction == b.direction
        and 0 <= b.time - a.time < GROUP_GAP
    )


def _identity_text(message: MessageSnap) -> str:
    old, sep, new = message.text.partition(" -> ")
    if not sep:
        return message.text
    return f"Identity changed from {old} to {new}. Compare safety numbers to verify it."


def message_rows(
    messages: Sequence[MessageSnap],
    progress: Mapping[str, int],
    peer: str,
    formats: Formats,
    *,
    busy_files: frozenset[str] = frozenset(),
) -> list[MessageRow]:
    """A conversation's rows: day labels, sender groups and per-message state."""
    days = [formats.day(m.time) for m in messages]
    starts = [
        i == 0 or days[i] != days[i - 1] or not _groupable(messages[i - 1], m)
        for i, m in enumerate(messages)
    ]
    ends = [i + 1 == len(messages) or starts[i + 1] for i in range(len(messages))]
    rows: list[MessageRow] = []
    last_status = ""
    for i in reversed(range(len(messages))):  # backwards: each group's final status is known
        m = messages[i]
        if ends[i]:
            last_status = m.status
        show_meta = ends[i] or (m.direction == "out" and m.status != last_status)
        file_fields = ("", "", "", "", "", -1.0, "")
        if m.file is not None:
            state, fraction = file_state(m, progress.get(m.entry_id), peer, formats)
            path = m.file.path if m.direction == "in" and m.file.status == "complete" else ""
            file_fields = (
                m.file.file_id,
                m.file.name,
                formats.size(m.file.size),
                m.file.status,
                state,
                fraction,
                path,
            )
        text = _identity_text(m) if m.kind == "identity_changed" else m.text
        rows.append(
            MessageRow(
                entry_id=m.entry_id,
                kind=m.kind,
                direction=m.direction,
                text=text,
                time_text=formats.time(m.time),
                status=m.status,
                status_text=STATUS_TEXT.get(m.status, m.status) if m.direction == "out" else "",
                glass_box=m.glass_box,
                file_id=file_fields[0],
                file_name=file_fields[1],
                file_size_text=file_fields[2],
                file_status=file_fields[3],
                file_state_text=file_fields[4],
                file_progress=file_fields[5],
                file_path=file_fields[6],
                file_busy=bool(file_fields[0]) and file_fields[0] in busy_files,
                day_label=days[i] if i == 0 or days[i] != days[i - 1] else "",
                group_start=starts[i],
                group_end=ends[i],
                show_meta=show_meta,
            )
        )
    rows.reverse()
    return rows


# -- sessions ---------------------------------------------------------------------------------------

CLOSE_HEADLINE: Final = {
    "decrypt_failed": "Authentication failed",
    "signature_invalid": "Authentication failed",
    "finished_invalid": "Authentication failed",
    "unexpected_message": "Protocol error",
    "oversize": "Protocol error",
    "schema_error": "Protocol error",
    "pin_mismatch": "Identity mismatch",
    "policy": "Refused by policy",
    "timeout": "Connection timed out",
    "rate_limited": "Too many requests",
    "internal": "Internal error",
    "kem_failure": "Key exchange failed",
    "invalid_kem_key": "Key exchange failed",
    "reflection": "Refused a reflected handshake",
    "replaced": "Replaced by a newer session",
}


def ended_text(reason: str, *, by_peer: bool, peer: str) -> str:
    """Why a session ended, in words, with the exact reason nearby (UI_DESIGN §10)."""
    name = isolate(peer)
    if not reason:
        return "Connection lost: no reason was given"
    if reason == "normal":
        return f"{name} ended the session" if by_peer else "Disconnected"
    if reason == "locked":
        return f"{name} locked QRP2P" if by_peer else "Disconnected"
    headline = CLOSE_HEADLINE.get(reason, "Session closed")
    origin = f", reported by {name}" if by_peer else ""
    return f"{headline} ({reason}{origin})"
