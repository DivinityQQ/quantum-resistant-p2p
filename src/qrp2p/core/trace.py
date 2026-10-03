"""Typed trace events: what the Inspector may show about a session (DESIGN §11.1, §11.2, §12).

Every field here is public: frame bytes as they cross the wire, sizes, counters, labels, public
keys, transcript hashes and close reasons. Secret values have no field to go in; a derived secret
appears only as its label and size (``SecretDerived``). Values of secrets reach the trace bus only
through ``RevealingProvider`` in glass-box and lab sessions (DESIGN §11.3).

The core emits these events; the services add the session ID and a timestamp and keep them in the
per-session ring buffer.
"""

from dataclasses import dataclass
from enum import StrEnum

from qrp2p.core.crypto.aead import TAG_LEN
from qrp2p.core.crypto.profiles import NONCE_LEN, Profile
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.wire import Frame, FrameType


class Direction(StrEnum):
    """Which way a frame or key goes, from this node's point of view."""

    OUT = "out"
    IN = "in"


@dataclass(frozen=True, slots=True)
class Field:
    """A named byte range of a frame body, for the message dissector.

    ``offset`` is relative to the body (the 5-byte frame header precedes it). A field with a
    ``parent`` lies within the parent field's range: an AEAD part's ciphertext and tag, or a
    hybrid KEM value's components.
    """

    name: str
    offset: int
    length: int
    parent: str = ""


@dataclass(frozen=True, slots=True)
class FrameTraced:
    """A frame sent or received, with its fields."""

    direction: Direction
    frame: Frame
    fields: tuple[Field, ...]


@dataclass(frozen=True, slots=True)
class StateChanged:
    """A state machine moved to ``state``."""

    machine: str
    state: str


@dataclass(frozen=True, slots=True)
class SecretDerived:
    """A secret was derived. Only its public label and size, never its value."""

    label: str
    length: int


class ReleaseCause(StrEnum):
    """Why the engine dropped its references to secrets (:class:`SecretsReleased`)."""

    USED = "used"
    """Its only job is done: a decapsulation key after decapsulating, a shared secret or a
    chaining secret once everything was derived from it."""
    REPLACED = "replaced"
    """A direction switched to newer keys (KeyUpdate or PQ rekey)."""
    HANDSHAKE_DONE = "handshake_done"
    """The handshake ended: its secrets are erased (DESIGN §7.4)."""
    EPOCH_DONE = "epoch_done"
    """A PQ rekey completed: the previous epoch's rekey salt and exporter are erased."""
    CLOSED = "closed"
    """The handshake or a pending rekey ended without finishing."""


@dataclass(frozen=True, slots=True)
class SecretsReleased:
    """The engine dropped every reference it held to these secrets.

    Python cannot wipe memory (DESIGN §3.5), so this says no more than that: the engine can no
    longer use the values, and they are freed when nothing else refers to them. Values a
    glass-box or lab session revealed keep existing in what revealed them.
    """

    labels: tuple[str, ...]
    cause: ReleaseCause


@dataclass(frozen=True, slots=True)
class TranscriptHashed:
    """A named transcript hash, e.g. ``th_hello`` or ``th_final``. Public."""

    name: str
    digest: bytes


@dataclass(frozen=True, slots=True)
class RecordTraced:
    """A record sealed (``OUT``) or opened (``IN``): counters, size and kind, never plaintext."""

    direction: Direction
    epoch: int
    generation: int
    seq: int
    length: int
    kind: str


@dataclass(frozen=True, slots=True)
class KeysSwitched:
    """A traffic key changed: after a KeyUpdate or at the end of a PQ rekey."""

    direction: Direction
    epoch: int
    generation: int
    cause: str


@dataclass(frozen=True, slots=True)
class RekeyStep:
    """A step of the PQ rekey (DESIGN §8.4)."""

    step: str
    epoch: int


@dataclass(frozen=True, slots=True)
class SessionClosed:
    """The handshake or session ended."""

    reason: CloseReason
    admit_reason: AdmitReason | None
    by_peer: bool


type TraceEvent = (
    FrameTraced
    | StateChanged
    | SecretDerived
    | SecretsReleased
    | TranscriptHashed
    | RecordTraced
    | KeysSwitched
    | RekeyStep
    | SessionClosed
)


_SEALED: dict[FrameType, str] = {
    FrameType.CONFIRM: "ConfirmInner (sealed)",
    FrameType.ADMIT: "AdmitInner (sealed)",
    FrameType.RECORD: "record (sealed)",
}
_HELLO_FIXED = 3 + NONCE_LEN
"""``version ‖ profile ‖ flags ‖ nonce_I``."""


def _parts(name: str, offset: int, parts: tuple[tuple[str, int], ...]) -> list[Field]:
    """A field and, after it, its components (a hybrid KEM's ``ek`` or ``ct``)."""
    fields = [Field(name, offset, sum(size for _, size in parts))]
    for part, size in parts:
        fields.append(Field(part, offset, size, parent=name))
        offset += size
    return fields


def _sealed(name: str, offset: int, length: int) -> list[Field]:
    """An AEAD output and, after it, its ciphertext and 16-byte tag."""
    whole = Field(name, offset, length)
    if length < TAG_LEN:
        return [whole]
    return [
        whole,
        Field("ciphertext", offset, length - TAG_LEN, parent=name),
        Field("tag", offset + length - TAG_LEN, TAG_LEN, parent=name),
    ]


def dissect(frame: Frame, profile: Profile | None) -> tuple[Field, ...]:
    """Split a frame body into named fields, parents before their components.

    ``profile`` is needed to split a Reply and a hybrid KEM's values. A frame that does not have
    the expected size is not split: its body stays one field, never prettified into validity.
    """
    body = len(frame.body)
    kem = profile.kem if profile is not None else None
    match frame.type:
        case FrameType.HELLO if body >= _HELLO_FIXED:
            ek_len = body - _HELLO_FIXED
            parts = kem.ek_parts if kem is not None and kem.ek_len == ek_len else ()
            ek = (
                _parts("ek_I", _HELLO_FIXED, parts)
                if parts
                else [Field("ek_I", _HELLO_FIXED, ek_len)]
            )
            return (
                Field("version", 0, 1),
                Field("profile", 1, 1),
                Field("flags", 2, 1),
                Field("nonce_I", 3, NONCE_LEN),
                *ek,
            )
        case FrameType.REPLY if profile is not None and body == profile.reply_body_len:
            ct_end = NONCE_LEN + profile.ct_len
            parts = profile.kem.ct_parts
            ct = (
                _parts("ct", NONCE_LEN, parts)
                if parts
                else [Field("ct", NONCE_LEN, profile.ct_len)]
            )
            return (
                Field("nonce_R", 0, NONCE_LEN),
                *ct,
                *_sealed("ReplyInner (sealed)", ct_end, body - ct_end),
            )
        case FrameType.CONFIRM | FrameType.ADMIT | FrameType.RECORD:
            return tuple(_sealed(_SEALED[frame.type], 0, body))
        case FrameType.PROFILE_UNSUPPORTED:
            return (Field("supported", 0, body),)
        case _:
            return (Field("body", 0, body),)
