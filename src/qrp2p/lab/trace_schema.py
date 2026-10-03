"""The file schema of trace events in a recording (DESIGN §11.5).

The core's trace events are plain dataclasses, which msgspec decodes leniently (unknown fields
are ignored and values are unbounded). A recording is read through these strict, bounded
mirrors instead, and converted to the core's events only after it decoded; the protocol engine
does not change to accommodate untrusted files. A mirror that drifts from its core event fails
the round-trip tests.
"""

from typing import Annotated, Final

import msgspec
from msgspec import Meta, Struct

from qrp2p.core import trace
from qrp2p.core.crypto.profiles import MAX_FRAME_BODY
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.trace import Direction, ReleaseCause, TraceEvent
from qrp2p.core.wire import FrameType

MAX_NAME: Final = 160
"""Characters in a schedule name, a state or a reason."""

type Name = Annotated[str, Meta(min_length=1, max_length=MAX_NAME)]
type Counter = Annotated[int, Meta(ge=0)]
"""A sequence number or epoch: MessagePack itself bounds it to 64 bits."""
type Size = Annotated[int, Meta(ge=0, le=MAX_FRAME_BODY)]
type Payload = Annotated[bytes, Meta(max_length=MAX_FRAME_BODY)]


class _Strict(Struct, frozen=True, forbid_unknown_fields=True):
    pass


class Field(_Strict, frozen=True):
    """A named byte range of a frame body (its bounds are checked against the body later)."""

    name: Name
    offset: Size
    length: Size
    parent: Annotated[str, Meta(max_length=MAX_NAME)] = ""


class Frame(_Strict, frozen=True):
    """Captured wire bytes: possibly a malformed message, which is evidence too."""

    type: FrameType
    body: Payload


class FrameTraced(_Strict, frozen=True, tag="frame"):
    """A frame as it was sent or received, and its fields."""

    direction: Direction
    frame: Frame
    fields: Annotated[tuple[Field, ...], Meta(max_length=64)]


class StateChanged(_Strict, frozen=True, tag="state"):
    """A state machine transition."""

    machine: Name
    state: Name


class SecretDerived(_Strict, frozen=True, tag="derived"):
    """A derivation the engine reported: its name and size."""

    label: Name
    length: Size


class SecretsReleased(_Strict, frozen=True, tag="released"):
    """References the engine dropped, and why."""

    labels: Annotated[tuple[Name, ...], Meta(max_length=64)]
    cause: ReleaseCause


class TranscriptHashed(_Strict, frozen=True, tag="hashed"):
    """A transcript hash and its public digest."""

    name: Name
    digest: Annotated[bytes, Meta(min_length=32, max_length=64)]


class RecordTraced(_Strict, frozen=True, tag="record"):
    """A record's public counters."""

    direction: Direction
    epoch: Counter
    generation: Counter
    seq: Counter
    length: Size
    kind: Name


class KeysSwitched(_Strict, frozen=True, tag="switched"):
    """A key switch's public counters."""

    direction: Direction
    epoch: Counter
    generation: Counter
    cause: Name


class RekeyStep(_Strict, frozen=True, tag="rekey"):
    """A PQ rekey step."""

    step: Name
    epoch: Counter


class SessionClosed(_Strict, frozen=True, tag="closed"):
    """The session's end and its named reason."""

    reason: CloseReason
    admit_reason: AdmitReason | None
    by_peer: bool


type Traced = (
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

_CORE: Final[dict[type[Traced], type[TraceEvent]]] = {
    FrameTraced: trace.FrameTraced,
    StateChanged: trace.StateChanged,
    SecretDerived: trace.SecretDerived,
    SecretsReleased: trace.SecretsReleased,
    TranscriptHashed: trace.TranscriptHashed,
    RecordTraced: trace.RecordTraced,
    KeysSwitched: trace.KeysSwitched,
    RekeyStep: trace.RekeyStep,
    SessionClosed: trace.SessionClosed,
}
_FILE: Final[dict[type[TraceEvent], type[Traced]]] = {v: k for k, v in _CORE.items()}


def to_file(event: TraceEvent) -> Traced:
    """A core trace event as its file form.

    Raises:
        msgspec.ValidationError: It is beyond a bound of the file schema.
    """
    return msgspec.convert(event, type=_FILE[type(event)], from_attributes=True)


def to_core(event: Traced) -> TraceEvent:
    """A decoded file event as the core's own event."""
    return msgspec.convert(event, type=_CORE[type(event)], from_attributes=True)
