"""Events the node reports to its front ends (the CLI now, the desktop app's bridge in M3).

They are immutable values, delivered on the node's event loop to every subscriber. Peer-supplied
text inside them (names, chat) is raw: front ends render it as plain text only
(:func:`~qrp2p.services.text.display_text` on a terminal).
"""

from dataclasses import dataclass
from enum import StrEnum

from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.services.admission import PromptKind
from qrp2p.services.discovery import NearbyPeer
from qrp2p.services.models import HistoryEntry


class NodeState(StrEnum):
    """The node's life cycle."""

    NO_VAULT = "no_vault"
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class StateChanged:
    """The node was created, unlocked, locked or closed."""

    state: NodeState


@dataclass(frozen=True, slots=True)
class NearbyChanged:
    """The peers announced on the LAN changed."""

    peers: tuple[NearbyPeer, ...]


@dataclass(frozen=True, slots=True)
class ContactsChanged:
    """A contact was added, changed or removed."""

    contact_id: bytes


@dataclass(frozen=True, slots=True)
class SessionOpened:
    """A session with a contact opened."""

    contact_id: bytes
    profile: str
    glass_box: bool
    initiator: bool
    replaced: bool
    """It replaced an earlier session with the same contact."""


@dataclass(frozen=True, slots=True)
class SessionEnded:
    """An open session with a contact ended.

    ``reason`` is ``None`` when the connection dropped without a named reason.
    """

    contact_id: bytes
    reason: CloseReason | None
    by_peer: bool


@dataclass(frozen=True, slots=True)
class ConnectFailed:
    """An outgoing connection or handshake failed before a session opened."""

    target: str
    reason: CloseReason | None
    admit_reason: AdmitReason | None = None
    supported_profiles: int | None = None
    """The responder's unauthenticated ``ProfileUnsupported`` hint, if it sent one."""
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ProfileRefused:
    """We refused a contact's session with ``profile_policy`` (DESIGN §7.6).

    The contact authenticated, so ``offered`` is what it really asked for; our user may switch
    the contact to it. Nothing changes without that choice.
    """

    contact_id: bytes
    offered: str
    """The profile in the contact's Hello."""
    configured: str
    """The contact's profile here."""


@dataclass(frozen=True, slots=True)
class AdmissionPrompt:
    """An authenticated initiator waits for our user's decision (DESIGN §7.6).

    Answer with ``Node.answer_prompt`` before ``deadline`` (monotonic seconds).
    """

    prompt_id: int
    kind: PromptKind
    short_id: str
    contact_id: bytes | None
    """The contact, for a glass-box prompt; ``None`` for a contact request."""
    name_hint: str
    profile: str
    glass_box_refused: bool
    """An unknown peer asked for glass-box: the session will be a normal one."""
    deadline: float


class PromptOutcome(StrEnum):
    """How an admission prompt ended: what actually happened, not just what the user chose."""

    ACCEPTED = "accepted"
    """Contact request: the contact was pinned and the session admitted."""
    DECLINED = "declined"
    """Contact request: refused with ``declined``."""
    GLASS_BOX = "glass_box"
    """Glass-box request: admitted as a glass-box session."""
    NORMAL = "normal"
    """Glass-box request declined: admitted as a normal session."""
    BUSY = "busy"
    """Accepted, but the live-session cap was reached meanwhile: rejected with ``busy``."""
    GONE = "gone"
    """Contact request accepted, but the initiator left while the contact was saved; the
    contact stays pinned."""
    EXPIRED = "expired"
    """Not answered before the admission deadline."""
    WITHDRAWN = "withdrawn"
    """The initiator went away before an answer."""


@dataclass(frozen=True, slots=True)
class PromptClosed:
    """A prompt was answered, expired or became moot (the initiator went away)."""

    prompt_id: int
    outcome: PromptOutcome


@dataclass(frozen=True, slots=True)
class KeyMismatchDetected:
    """We connected to a contact and a different identity answered (DESIGN §5.3).

    The handshake stopped before we revealed ourselves. Resolve with ``Node.resolve_mismatch``:
    cancel, or re-pin to the new identity.
    """

    mismatch_id: int
    contact_id: bytes
    expected_short_id: str
    actual_short_id: str
    expected_peer_id: bytes
    """The pinned bundle's full peer ID (its fingerprint)."""
    actual_peer_id: bytes
    """The full peer ID of the identity that answered."""


@dataclass(frozen=True, slots=True)
class ConnectProgress:
    """An outgoing handshake reached a stage the user waits on.

    ``stage`` is ``"waiting_for_admission"``: the peer authenticated, we revealed ourselves
    (Confirm), and the responder's user decides now (up to the admission deadline, DESIGN §6.4).
    ``contact_id`` is ``None`` for a first contact.
    """

    target: str
    contact_id: bytes | None
    stage: str


@dataclass(frozen=True, slots=True)
class HistoryChanged:
    """A history entry was added (``added``) or changed (status, progress)."""

    contact_id: bytes
    entry: HistoryEntry
    added: bool
    progress: int | None = None
    """For a file transfer in progress: bytes so far."""


@dataclass(frozen=True, slots=True)
class Notice:
    """Something the user should know that is not tied to a request (e.g. mDNS failed)."""

    text: str


type NodeEvent = (
    StateChanged
    | NearbyChanged
    | ContactsChanged
    | SessionOpened
    | SessionEnded
    | ConnectFailed
    | ProfileRefused
    | ConnectProgress
    | AdmissionPrompt
    | PromptClosed
    | KeyMismatchDetected
    | HistoryChanged
    | Notice
)
