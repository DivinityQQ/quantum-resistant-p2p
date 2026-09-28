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

from qrp2p.core.crypto.profiles import NONCE_LEN, Profile
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.wire import Frame, FrameType


class Direction(StrEnum):
    """Which way a frame or key goes, from this node's point of view."""

    OUT = "out"
    IN = "in"


@dataclass(frozen=True, slots=True)
class Field:
    """A named byte range of a frame body, for the message dissector."""

    name: str
    offset: int
    length: int


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
    | TranscriptHashed
    | RecordTraced
    | KeysSwitched
    | RekeyStep
    | SessionClosed
)


_WHOLE_BODY: dict[FrameType, str] = {
    FrameType.CONFIRM: "ConfirmInner (sealed)",
    FrameType.ADMIT: "AdmitInner (sealed)",
    FrameType.PROFILE_UNSUPPORTED: "supported",
    FrameType.RECORD: "record (sealed)",
}


def dissect(frame: Frame, profile: Profile | None) -> tuple[Field, ...]:
    """Split a frame body into named fields. ``profile`` is needed to split a Reply."""
    body = len(frame.body)
    if frame.type is FrameType.HELLO and body >= 3 + NONCE_LEN:
        return (
            Field("version", 0, 1),
            Field("profile", 1, 1),
            Field("flags", 2, 1),
            Field("nonce_I", 3, NONCE_LEN),
            Field("ek_I", 3 + NONCE_LEN, body - 3 - NONCE_LEN),
        )
    if frame.type is FrameType.REPLY and profile is not None and body == profile.reply_body_len:
        ct_end = NONCE_LEN + profile.ct_len
        return (
            Field("nonce_R", 0, NONCE_LEN),
            Field("ct", NONCE_LEN, profile.ct_len),
            Field("ReplyInner (sealed)", ct_end, body - ct_end),
        )
    return (Field(_WHOLE_BODY.get(frame.type, "body"), 0, body),)
