"""Immutable values that cross from the services thread to the Qt thread (UI_DESIGN §11.2).

The services thread builds every value here from the node's objects; the Qt thread only reads
them. They hold primitives (strings, numbers, booleans and tuples of these), never a ``Session``,
``Contact``, identity bundle or any other live object. IDs travel as lowercase hex.

Peer-supplied text (names, chat, file names, mDNS labels) is made safe for display here, once:
control characters and bidirectional overrides become U+FFFD (:mod:`qrp2p.ui.text`). QML still
renders every one of these strings as plain text.

Three kinds of delivery carry these values, each tagged with the lifecycle generation it belongs
to (see :mod:`qrp2p.ui.host`): :class:`Lifecycle`, :class:`Batch` and :class:`Reply`.
"""

from dataclasses import dataclass
from typing import Final

from qrp2p.services.discovery import NearbyPeer
from qrp2p.services.events import AdmissionPrompt, KeyMismatchDetected
from qrp2p.services.models import ID_LEN, Contact, HistoryEntry, Settings
from qrp2p.services.node import Node, NodeError, profile_by_id, profiles_in
from qrp2p.services.session import SessionRole
from qrp2p.ui.text import display_name, display_text, fingerprint

ID_HEX_LEN: Final = 2 * ID_LEN
"""Contact, conversation, entry and file IDs in hex."""

# -- values ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class IdentitySnap:
    """Our identity: what others see of us."""

    short_id: str
    fingerprint: str
    """The full peer ID, hex in groups of four."""
    bundle_bytes: int
    parts: tuple[tuple[str, int], ...]
    """The bundle's public keys with their measured sizes in bytes."""


@dataclass(frozen=True, slots=True, kw_only=True)
class NetworkSnap:
    """Where we listen."""

    port: int
    addresses: tuple[str, ...]
    """Local addresses others can dial (no loopback or link-local)."""
    discovery: bool
    """mDNS announcing and browsing works."""


@dataclass(frozen=True, slots=True, kw_only=True)
class SettingsSnap:
    """The user's settings, as the Settings screen shows them."""

    display_name: str
    announce_name: bool
    default_profile: str
    default_retention: str
    auto_lock_minutes: int
    port: int
    downloads_dir: str
    """The folder in use: the configured one, or the OS downloads folder."""
    downloads_custom: bool
    max_file_size: int
    appearance: str
    reduced_motion: bool
    text_scale: int


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionSnap:
    """The open session with a contact."""

    profile: str
    glass_box: bool
    initiator: bool
    """We opened it (only the initiator can start a rekey)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ContactSnap:
    """A contact and, if one is open, its session."""

    contact_id: str
    name: str
    short_id: str
    fingerprint: str
    trust: str
    profile: str
    retention: str
    auto_accept_files: bool
    auto_accept_limit: int
    address: str
    """Where we last reached them, ``host:port``; empty if never."""
    created: float
    session: SessionSnap | None


@dataclass(frozen=True, slots=True, kw_only=True)
class NearbySnap:
    """A peer announced on the LAN: every field is an unauthenticated hint."""

    key: str
    label: str
    id_hint: str
    profiles: tuple[str, ...]
    addresses: tuple[str, ...]
    port: int
    contact_id: str
    """The contact whose pin starts with ``id_hint``; empty if none (also only a hint)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class FileSnap:
    """A file transfer as history keeps it, plus live progress."""

    file_id: str
    name: str
    size: int
    status: str
    path: str
    """Where a received file was saved; empty otherwise."""
    reason: str
    transferred: int | None
    """Bytes so far while transferring; ``None`` when the event carried no progress."""


@dataclass(frozen=True, slots=True, kw_only=True)
class MessageSnap:
    """One history entry: a chat message, a file transfer or a local note."""

    entry_id: str
    kind: str
    direction: str
    time: float
    status: str
    text: str
    glass_box: bool
    file: FileSnap | None


@dataclass(frozen=True, slots=True, kw_only=True)
class PromptSnap:
    """An authenticated initiator waits for the user's decision (DESIGN §7.6)."""

    prompt_id: int
    kind: str
    short_id: str
    contact_id: str
    name: str
    profile: str
    glass_box_refused: bool
    expires_in: float
    """Seconds left when the snapshot was taken."""


@dataclass(frozen=True, slots=True, kw_only=True)
class MismatchSnap:
    """We connected to a contact and a different identity answered (DESIGN §5.3)."""

    mismatch_id: int
    contact_id: str
    name: str
    expected_short_id: str
    actual_short_id: str
    expected_fingerprint: str
    actual_fingerprint: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SafetySnap:
    """A safety number and the exact identity it was computed for (DESIGN §5.2)."""

    peer_id: str
    """The contact's pinned peer ID (hex) when the number was computed."""
    fingerprint: str
    short_id: str
    groups: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ActivitySnap:
    """When each conversation last had an entry (wall-clock seconds), by contact ID."""

    times: tuple[tuple[str, float], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class WorkspaceSnap:
    """Everything the unlocked app shows at once, taken atomically when the node unlocked."""

    identity: IdentitySnap
    network: NetworkSnap
    settings: SettingsSnap
    contacts: tuple[ContactSnap, ...]
    nearby: tuple[NearbySnap, ...]
    prompts: tuple[PromptSnap, ...]


# -- updates (inside a Batch) ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContactChanged:
    """A contact was added or changed, or its session opened or ended."""

    contact: ContactSnap


@dataclass(frozen=True, slots=True)
class ContactRemoved:
    """A contact was deleted."""

    contact_id: str


@dataclass(frozen=True, slots=True)
class NearbyChanged:
    """The peers announced on the LAN changed."""

    peers: tuple[NearbySnap, ...]


@dataclass(frozen=True, slots=True)
class MessageChanged:
    """A history entry was added or changed (status, file progress)."""

    contact_id: str
    message: MessageSnap
    added: bool


@dataclass(frozen=True, slots=True)
class PromptOpened:
    """A contact or glass-box request waits for an answer."""

    prompt: PromptSnap


@dataclass(frozen=True, slots=True)
class PromptClosed:
    """A request was answered, expired or withdrawn; ``outcome`` is what actually happened."""

    prompt_id: int
    outcome: str


@dataclass(frozen=True, slots=True)
class MismatchOpened:
    """A key mismatch waits for Cancel or Re-pin."""

    mismatch: MismatchSnap


@dataclass(frozen=True, slots=True)
class ConnectStage:
    """An outgoing handshake reached ``stage`` (``waiting_for_admission``)."""

    contact_id: str
    """Empty for a first contact."""
    target: str
    stage: str


@dataclass(frozen=True, slots=True)
class SessionEnded:
    """An open session ended; ``reason`` is empty when the connection was lost unnamed."""

    contact_id: str
    reason: str
    by_peer: bool


@dataclass(frozen=True, slots=True)
class NoticePosted:
    """Something the user should know that belongs to no request."""

    text: str


type Update = (
    ContactChanged
    | ContactRemoved
    | NearbyChanged
    | MessageChanged
    | PromptOpened
    | PromptClosed
    | MismatchOpened
    | ConnectStage
    | SessionEnded
    | NoticePosted
)


# -- deliveries -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Lifecycle:
    """The node's life cycle moved; a new generation starts.

    ``state`` is a :class:`~qrp2p.services.events.NodeState` value, or ``in_use`` (another
    process has the data directory) or ``failed`` (the node could not start; ``error`` says why).
    ``workspace`` is set exactly when ``state`` is ``unlocked``.
    """

    gen: int
    state: str
    workspace: WorkspaceSnap | None = None
    error: str = ""


@dataclass(frozen=True, slots=True)
class Batch:
    """Updates of one generation, in the order the node reported them."""

    gen: int
    updates: tuple[Update, ...]


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    """Why a request failed: a kind for the code, a message for the user."""

    kind: str
    message: str


@dataclass(frozen=True, slots=True)
class Reply:
    """The outcome of one request: ``value`` on success, else ``error``."""

    gen: int
    request_id: int
    value: object = None
    error: ErrorInfo | None = None


type Delivery = Lifecycle | Batch | Reply


# -- building snapshots (services thread) ----------------------------------------------------------


def identity_snap(node: Node) -> IdentitySnap:
    """Our identity, with the sizes measured from the actual bundle."""
    bundle = node.identity
    parts = (
        ("Ed25519 public key", len(bundle.ed25519)),
        ("ML-DSA-65 public key", len(bundle.mldsa65)),
        ("ML-DSA-87 public key", len(bundle.mldsa87)),
    )
    return IdentitySnap(
        short_id=bundle.short_id,
        fingerprint=fingerprint(bundle.peer_id),
        bundle_bytes=len(bundle.encode()),
        parts=parts,
    )


def settings_snap(node: Node, settings: Settings | None = None) -> SettingsSnap:
    """The settings in use (``settings`` if given, else the node's)."""
    s = settings or node.settings
    return SettingsSnap(
        display_name=display_name(s.display_name),
        announce_name=s.announce_name,
        default_profile=profile_by_id(s.default_profile).name,
        default_retention=s.default_retention.value,
        auto_lock_minutes=s.auto_lock_minutes,
        port=s.port,
        downloads_dir=str(node.downloads_dir()),
        downloads_custom=bool(s.downloads_dir),
        max_file_size=s.max_file_size,
        appearance=s.appearance.value,
        reduced_motion=s.reduced_motion,
        text_scale=s.text_scale,
    )


def contact_snap(node: Node, contact: Contact) -> ContactSnap:
    """A contact with its open session, if any."""
    session = node.session_info(contact.contact_id)
    session_snap = None
    if session is not None:
        profile = session.profile
        session_snap = SessionSnap(
            profile=profile.name if profile is not None else "",
            glass_box=session.glass_box,
            initiator=session.role is SessionRole.INITIATOR,
        )
    address = ""
    if contact.address is not None:
        host, port = contact.address
        address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return ContactSnap(
        contact_id=contact.contact_id.hex(),
        name=display_name(contact.name),
        short_id=contact.short_id,
        fingerprint=fingerprint(contact.peer_id),
        trust=contact.trust.value,
        profile=profile_by_id(contact.profile_id).name,
        retention=contact.retention.value,
        auto_accept_files=contact.auto_accept_files,
        auto_accept_limit=contact.auto_accept_limit,
        address=display_text(address),
        created=contact.created,
        session=session_snap,
    )


def nearby_snap(node: Node, peer: NearbyPeer) -> NearbySnap:
    """An announced peer, matched to a contact by its ID hint."""
    contact = node.contact_for_nearby(peer)
    profiles = tuple(p.name for p in profiles_in(peer.profiles))
    return NearbySnap(
        key=display_text(peer.instance),
        label=display_name(peer.label),
        id_hint=peer.id_hint.hex(),
        profiles=profiles,
        addresses=tuple(display_text(a) for a in peer.addresses),
        port=peer.port,
        contact_id=contact.contact_id.hex() if contact is not None else "",
    )


def message_snap(entry: HistoryEntry, progress: int | None = None) -> MessageSnap:
    """A history entry; ``progress`` is a transfer's live byte count."""
    info = entry.file
    file = None
    if info is not None:
        file = FileSnap(
            file_id=info.file_id.hex(),
            name=display_name(info.name, limit=None),
            size=info.size,
            status=info.status.value,
            path=info.path,
            reason=info.reason,
            transferred=progress,
        )
    return MessageSnap(
        entry_id=entry.entry_id.hex(),
        kind=entry.kind.value,
        direction=entry.direction.value,
        time=entry.time,
        status=entry.status.value,
        text=display_text(entry.text, keep_newlines=True),
        glass_box=entry.glass_box,
        file=file,
    )


def prompt_snap(prompt: AdmissionPrompt, now: float) -> PromptSnap:
    """An admission prompt; ``now`` is the node's monotonic clock."""
    return PromptSnap(
        prompt_id=prompt.prompt_id,
        kind=prompt.kind.value,
        short_id=prompt.short_id,
        contact_id=prompt.contact_id.hex() if prompt.contact_id is not None else "",
        name=display_name(prompt.name_hint),
        profile=prompt.profile,
        glass_box_refused=prompt.glass_box_refused,
        expires_in=max(prompt.deadline - now, 0.0),
    )


def mismatch_snap(node: Node, event: KeyMismatchDetected) -> MismatchSnap:
    """A key mismatch, named after the contact it concerns."""
    try:
        name = display_name(node.contact(event.contact_id).name)
    except NodeError:  # deleted meanwhile
        name = event.expected_short_id
    return MismatchSnap(
        mismatch_id=event.mismatch_id,
        contact_id=event.contact_id.hex(),
        name=name,
        expected_short_id=event.expected_short_id,
        actual_short_id=event.actual_short_id,
        expected_fingerprint=fingerprint(event.expected_peer_id),
        actual_fingerprint=fingerprint(event.actual_peer_id),
    )
