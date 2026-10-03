"""What the Inspector receives about a session: its descriptor, profile and trace items.

These values cross from the services thread (or the lab controller) to the Qt thread, so they
are immutable and hold primitives: core trace events (frozen dataclasses of public values),
and, for exposed sessions only, revealed values as bytes.
"""

from dataclasses import dataclass

from qrp2p.core.trace import TraceEvent


@dataclass(frozen=True, slots=True)
class Revealed:
    """A secret of an exposed session (glass-box or lab), under its schedule name."""

    label: str
    value: bytes


@dataclass(frozen=True, slots=True)
class RecordOpened:
    """An exposed session's record: the nonce and plaintext of one AEAD operation.

    ``key`` names the key (``hs_R.key``, ``ap_I[0]+1.key``…) and with ``seq`` the record.
    """

    key: str
    seq: int
    nonce: bytes
    plaintext: bytes
    opened: bool
    """``True`` for a record received, ``False`` for one sent."""


type Item = TraceEvent | Revealed | RecordOpened


@dataclass(frozen=True, slots=True)
class TraceItem:
    """One trace event with its session-scoped ordinal and local monotonic time."""

    ordinal: int
    time: float
    event: Item


@dataclass(frozen=True, slots=True)
class ProfileFacts:
    """A profile's algorithms and sizes, as the specification defines them (DESIGN §4, App. A)."""

    name: str
    kem: str
    signature: str
    aead: str
    hash: str
    hash_len: int
    sig_len: int
    ek_len: int
    ct_len: int
    ek_parts: tuple[tuple[str, int], ...]
    ct_parts: tuple[tuple[str, int], ...]
    lab_only: bool


@dataclass(frozen=True, slots=True)
class SessionFacts:
    """What is known about an inspected session besides its trace."""

    session_id: int
    initiator: bool
    """We opened the connection."""
    address: str
    profile: ProfileFacts | None
    local_name: str
    """How the local side is named: "You", or the lab node's name."""
    peer_name: str
    """The authenticated peer's contact name, or its short ID, or empty before authentication."""
    peer_short_id: str
    contact_id: str
    trust: str
    """The contact's trust state now (``pinned``, ``verified``…); empty if not a contact."""
    pinned_before: bool
    """We initiated to a pinned contact (its identity was checked before we revealed ours)."""
    glass_box_requested: bool
    glass_box: bool
    exposed: bool
    """Values are revealed: a glass-box session or the solo lab."""
    lab: bool
    established: bool
    ended: bool
    end_reason: str
    admit_reason: str
    by_peer: bool
