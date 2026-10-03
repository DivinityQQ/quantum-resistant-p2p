"""Strict, bounded serialized trace payloads; core dataclasses are runtime events.

Keeping the file schema here avoids changing the protocol engine to accommodate untrusted
recordings. Unknown fields are rejected at every nested level before runtime reconstruction.
"""

from typing import Annotated

from msgspec import Meta, Struct

from qrp2p.core.crypto.profiles import MAX_FRAME_BODY
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.trace import Direction, ReleaseCause
from qrp2p.core.wire import FrameType

type Label = Annotated[str, Meta(min_length=1, max_length=160)]
type Counter = Annotated[int, Meta(ge=0)]
type Size = Annotated[int, Meta(ge=0, le=MAX_FRAME_BODY)]
type Payload = Annotated[bytes, Meta(max_length=MAX_FRAME_BODY)]


class Field(Struct, frozen=True, forbid_unknown_fields=True):
    """One bounded byte range; semantic parent checks follow decoding."""

    name: Label
    offset: Size
    length: Size
    parent: Annotated[str, Meta(max_length=160)] = ""


class Frame(Struct, frozen=True, forbid_unknown_fields=True):
    """Captured wire bytes, including malformed messages."""

    type: FrameType
    body: Payload


class FrameTraced(Struct, frozen=True, forbid_unknown_fields=True):
    """A captured frame and at most 64 ranges."""

    direction: Direction
    frame: Frame
    fields: Annotated[tuple[Field, ...], Meta(max_length=64)]


class StateChanged(Struct, frozen=True, forbid_unknown_fields=True):
    """A public transition."""

    machine: Label
    state: Label


class SecretDerived(Struct, frozen=True, forbid_unknown_fields=True):
    """A named derivation, without its value."""

    label: Label
    length: Size


class SecretsReleased(Struct, frozen=True, forbid_unknown_fields=True):
    """References dropped by the engine."""

    labels: Annotated[tuple[Label, ...], Meta(max_length=64)]
    cause: ReleaseCause


class TranscriptHashed(Struct, frozen=True, forbid_unknown_fields=True):
    """A public digest."""

    name: Label
    digest: Annotated[bytes, Meta(min_length=32, max_length=48)]


class RecordTraced(Struct, frozen=True, forbid_unknown_fields=True):
    """A record's public counters."""

    direction: Direction
    epoch: Counter
    generation: Counter
    seq: Counter
    length: Size
    kind: Label


class KeysSwitched(Struct, frozen=True, forbid_unknown_fields=True):
    """A key change's public counters."""

    direction: Direction
    epoch: Counter
    generation: Counter
    cause: Label


class RekeyStep(Struct, frozen=True, forbid_unknown_fields=True):
    """A public rekey step."""

    step: Label
    epoch: Counter


class SessionClosed(Struct, frozen=True, forbid_unknown_fields=True):
    """A named close reason."""

    reason: CloseReason
    admit_reason: AdmitReason | None
    by_peer: bool
