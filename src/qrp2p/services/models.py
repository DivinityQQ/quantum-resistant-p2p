"""What the node keeps about contacts, settings and history (DESIGN §5.3, §10.3, §14.1).

These are plain values. The vault stores them encrypted (``qrp2p.services.vault``); the node hands
them to the front ends.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from qrp2p.core.crypto.identity import IdentityBundle
from qrp2p.core.crypto.profiles import DEFAULT_PORT, ProfileId

ID_LEN: Final = 16
"""Contact, conversation, message and file IDs: random 128-bit values."""
DEFAULT_MAX_FILE_SIZE: Final = 4 * 2**30
"""Largest file accepted by default (DESIGN §9)."""
DEFAULT_AUTO_LOCK_MINUTES: Final = 15


class TrustState(StrEnum):
    """A contact's trust state (DESIGN §5.3). *Unknown* is the absence of a contact."""

    PINNED = "pinned"
    VERIFIED = "verified"
    BLOCKED = "blocked"


class Retention(StrEnum):
    """How long a conversation's messages are kept (DESIGN §10.4)."""

    FOREVER = "forever"
    DAYS_30 = "30d"
    SESSION = "session"
    """Until the app locks or exits."""


RETENTION_SECONDS: Final = {Retention.DAYS_30: 30 * 86_400.0}


class Appearance(StrEnum):
    """The desktop app's colour scheme (UI_DESIGN §4.2)."""

    SYSTEM = "system"
    LIGHT = "light"
    DARK = "dark"


TEXT_SCALES: Final = (100, 115, 130, 150)
"""Text sizes the desktop app offers, in percent of the base size."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Contact:
    """A pinned, verified or blocked peer.

    ``contact_id`` is stable; the bundle (and so the peer ID) changes only by an explicit re-pin.
    """

    contact_id: bytes
    conv_id: bytes
    bundle: IdentityBundle
    name: str
    trust: TrustState = TrustState.PINNED
    profile_id: int = ProfileId.HYBRID_1
    retention: Retention = Retention.FOREVER
    auto_accept_files: bool = False
    auto_accept_limit: int = 0
    """Bytes; auto-accept applies only to verified contacts (DESIGN §9, §18)."""
    address: tuple[str, int] | None = None
    """Where we last reached the peer: a hint for reconnecting, never an identity."""
    created: float = 0.0

    @property
    def peer_id(self) -> bytes:
        """The pinned bundle's peer ID."""
        return self.bundle.peer_id

    @property
    def short_id(self) -> str:
        """``XXXX-XXXX``."""
        return self.bundle.short_id


@dataclass(frozen=True, slots=True, kw_only=True)
class Settings:
    """User settings (DESIGN §14.1)."""

    display_name: str = ""
    announce_name: bool = True
    """Show the display name in the mDNS instance name (DESIGN §6.1)."""
    default_profile: int = ProfileId.HYBRID_1
    default_retention: Retention = Retention.FOREVER
    auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES
    """0 disables auto-lock."""
    port: int = DEFAULT_PORT
    downloads_dir: str = ""
    """Empty: the OS downloads directory."""
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    appearance: Appearance = Appearance.SYSTEM
    """Desktop app only: applied after unlock; the unlock screen follows the system."""
    reduced_motion: bool = False
    """Desktop app only: immediate transitions instead of animations."""
    text_scale: int = 100
    """Desktop app only: one of :data:`TEXT_SCALES`."""


class MessageKind(StrEnum):
    """What a history entry records."""

    CHAT = "chat"
    FILE = "file"
    IDENTITY_CHANGED = "identity_changed"
    """The contact was re-pinned to a new bundle (DESIGN §5.3 rule 3)."""


class Direction(StrEnum):
    """Who sent it."""

    IN = "in"
    OUT = "out"
    LOCAL = "local"
    """A note by this app, such as the identity-changed marker."""


class MessageStatus(StrEnum):
    """Delivery state (DESIGN §8.5: *sent → delivered* truthfully)."""

    SENDING = "sending"
    """Queued for the writer."""
    SENT = "sent"
    """Handed to TCP."""
    DELIVERED = "delivered"
    """The peer's receipt arrived."""
    RECEIVED = "received"
    FAILED = "failed"
    """The session ended before the message was sent."""


class FileStatus(StrEnum):
    """A file transfer's state, as kept in history."""

    OFFERED = "offered"
    ACCEPTED = "accepted"
    TRANSFERRING = "transferring"
    COMPLETE = "complete"
    DECLINED = "declined"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(frozen=True, slots=True, kw_only=True)
class FileInfo:
    """A transfer's metadata. ``path`` is where a received file was saved."""

    file_id: bytes
    name: str
    size: int
    media_type: str
    status: FileStatus
    sha256: bytes = b""
    path: str = ""
    reason: str = ""
    """The cancel reason's label, when cancelled or failed."""


@dataclass(frozen=True, slots=True, kw_only=True)
class HistoryEntry:
    """One entry of a conversation.

    ``entry_id`` is the vault row; ``message_id`` the chat's wire ID (for receipts).
    """

    entry_id: bytes
    kind: MessageKind
    direction: Direction
    time: float
    message_id: bytes = b""
    status: MessageStatus = MessageStatus.RECEIVED
    text: str = ""
    file: FileInfo | None = None
    glass_box: bool = False
    """Sent or received in a glass-box session (DESIGN §11.3: tagged on every message)."""
