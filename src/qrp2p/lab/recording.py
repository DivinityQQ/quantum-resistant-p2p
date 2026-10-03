"""Recordings: the ``.qrlab`` format (DESIGN §11.5).

```text
file   = header ‖ nonce[12] ‖ ChaCha20-Poly1305(k_lab, nonce, body, aad = header)
header = "QRLAB" ‖ 0x00 ‖ version:u8
body   = MessagePack, one of:
         lab        { meta, run }                    a solo-lab run: it replays and forks
         glass_box  { meta, exposed, session, events }  our side of a glass-box session: view only
```

``k_lab`` never leaves the vault: the vault seals and opens the body (``seal_lab``/``open_lab``);
this module only builds and checks the bytes around it. A lab recording holds everything needed
to replay the run (identities, steps, both provider logs, see :class:`~qrp2p.lab.solo.LabRun`).
A glass-box recording holds the trace this side retained, revealed values included, and an
EXPOSED stamp; it cannot be replayed, because the peer's randomness and keys were never ours.

A recording is untrusted input when it is opened (it may have been copied in from elsewhere):
the file is capped before it is read, the schema is strict at every level (unknown fields and
wrong types are refused; trace events are read through :mod:`qrp2p.lab.trace_schema`), every
list and value has a bound, what the views rely on is checked (finite times, known profiles,
field ranges inside their frames, provider-log marks), and a failure is a
:class:`RecordingError` with a named reason that never contains recorded bytes. What a replay
is fed is checked again where it is used, by the replaying provider (DESIGN §11.6).
"""

from itertools import pairwise
from math import isfinite
from typing import Annotated, Final

import msgspec
from msgspec import Struct

from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.trace import TraceEvent
from qrp2p.lab import trace_schema
from qrp2p.lab.classical import lab_profile_named
from qrp2p.lab.solo import RUN_FORMAT, LabError, LabRun, validate_marks
from qrp2p.lab.trace_schema import Counter, Name, Payload
from qrp2p.services.trace_bus import PinResult

MAGIC: Final = b"QRLAB\0"
VERSION: Final = 1
HEADER: Final = MAGIC + bytes([VERSION])
NONCE_LEN: Final = 12
TAG_LEN: Final = 16
MAX_FILE: Final = 256 * 1024 * 1024
"""Bytes a recording may have; a larger file is refused before it is read."""
MAX_TITLE: Final = 200
MAX_EVENTS: Final = 20_000
"""Events a glass-box recording may hold (a retained trace keeps at most about 12,000)."""
MAX_CREATED: Final = 253_402_214_400.0
"""The start of the year 10000: a creation time beyond it cannot be shown as a date."""
SUFFIX: Final = ".qrlab"


class RecordingError(Exception):
    """A recording that cannot be opened or saved; the message says why, never what it holds."""


class Meta(Struct, frozen=True, forbid_unknown_fields=True):
    """What a recording is, shown before it is opened."""

    title: Annotated[str, msgspec.Meta(min_length=1, max_length=MAX_TITLE)]
    created: float
    """Wall-clock seconds since the epoch."""
    profile: Name


class LabRecording(Struct, frozen=True, tag="lab", forbid_unknown_fields=True):
    """A solo-lab run."""

    meta: Meta
    run: LabRun


# -- a glass-box session's retained trace ------------------------------------------------------


class _Event(Struct, frozen=True, forbid_unknown_fields=True):
    ordinal: Counter
    time: float


class Traced(_Event, frozen=True, tag="trace"):
    """A public trace event, in its file form (:func:`traced` makes one)."""

    event: trace_schema.Traced


class Value(_Event, frozen=True, tag="value"):
    """A revealed secret, under its schedule name."""

    label: Name
    value: Payload


class Opened(_Event, frozen=True, tag="opened"):
    """A record's revealed nonce and plaintext."""

    key: Name
    seq: Counter
    nonce: Annotated[bytes, msgspec.Meta(min_length=12, max_length=12)]
    plaintext: Payload
    opened: bool


type Event = Traced | Value | Opened


class Session(Struct, frozen=True, forbid_unknown_fields=True):
    """The recorded session's descriptor, as it stood when it was saved."""

    initiator: bool
    started: float
    profile: Name
    peer_short_id: Annotated[str, msgspec.Meta(max_length=trace_schema.MAX_NAME)]
    established: bool
    ended: bool
    end_reason: Annotated[str, msgspec.Meta(max_length=trace_schema.MAX_NAME)]
    admit_reason: Annotated[str, msgspec.Meta(max_length=trace_schema.MAX_NAME)]
    by_peer: bool
    pin_result: PinResult
    contact_saved: bool


class GlassBoxRecording(Struct, frozen=True, tag="glass_box", forbid_unknown_fields=True):
    """Our side of a glass-box session: its retained trace, revealed values included."""

    meta: Meta
    exposed: bool
    """The EXPOSED stamp: every value of this session can be read from it (always true)."""
    session: Session
    events: Annotated[list[Event], msgspec.Meta(max_length=MAX_EVENTS)]


type Recording = LabRecording | GlassBoxRecording

_ENCODER: Final = msgspec.msgpack.Encoder()
_DECODER: Final = msgspec.msgpack.Decoder(Recording)


def traced(ordinal: int, time: float, event: TraceEvent) -> Traced:
    """A core trace event as a recording's event.

    Raises:
        RecordingError: It is beyond a bound of the file schema.
    """
    try:
        return Traced(ordinal, time, trace_schema.to_file(event))
    except msgspec.ValidationError as error:
        msg = f"a trace event does not fit the recording schema ({_where(error)})"
        raise RecordingError(msg) from None


def encode(recording: Recording) -> bytes:
    """A recording's body: checked by decoding it, so that what is saved will open again.

    Raises:
        RecordingError: It breaks the schema or a bound.
    """
    body = _ENCODER.encode(recording)
    decode(body)
    return body


def decode(body: bytes) -> Recording:
    """A recording from its body.

    Raises:
        RecordingError: Not a recording of this version, or beyond a bound.
    """
    if len(body) > MAX_FILE - len(HEADER) - NONCE_LEN - TAG_LEN:
        msg = "the recording is larger than 256 MiB"
        raise RecordingError(msg)
    try:
        recording = _DECODER.decode(body)
    except msgspec.ValidationError as error:
        msg = f"the recording does not match its schema ({_where(error)})"
        raise RecordingError(msg) from None
    except msgspec.DecodeError, UnicodeDecodeError:  # a string that is not UTF-8 included
        msg = "the recording is not valid MessagePack"
        raise RecordingError(msg) from None
    _check(recording)
    return recording


def pack(sealed: bytes) -> bytes:
    """The file: the header, then the sealed body (``nonce ‖ ciphertext``)."""
    return HEADER + sealed


def unpack(data: bytes) -> bytes:
    """The sealed body of a file, after checking its header and size.

    Raises:
        RecordingError: Not a recording, another version, or too short or long.
    """
    if len(data) > MAX_FILE:
        msg = "the recording is larger than 256 MiB"
        raise RecordingError(msg)
    if not data.startswith(MAGIC):
        msg = "not a QRP2P recording"
        raise RecordingError(msg)
    if len(data) < len(HEADER) or data[len(MAGIC)] != VERSION:
        msg = "a recording of another version"
        raise RecordingError(msg)
    if len(data) < len(HEADER) + NONCE_LEN + TAG_LEN:
        msg = "the recording is truncated"
        raise RecordingError(msg)
    return data[len(HEADER) :]


def _where(error: msgspec.ValidationError) -> str:
    """The schema path of a validation error (``$.run.steps[3]``), never the offending value."""
    text = str(error)
    at = text.rfind(" - at `")
    return text[at + len(" - at `") : -1] if at >= 0 else "unexpected structure"


def _require(condition: bool, reason: str) -> None:  # noqa: FBT001  # a check and its reason
    if not condition:
        raise RecordingError(reason)


def _check(recording: Recording) -> None:
    meta = recording.meta
    _require(
        isfinite(meta.created) and 0 <= meta.created < MAX_CREATED,
        "the recording's creation time is not a date",
    )
    profile = lab_profile_named(meta.profile)
    if profile is None:
        msg = "the recording names an unknown profile"
        raise RecordingError(msg)
    match recording:
        case LabRecording(run=run):
            _check_run(run, profile)
        case GlassBoxRecording():
            _check_glass_box(recording, profile)


def _check_run(run: LabRun, profile: Profile) -> None:
    _require(
        run.format == RUN_FORMAT and run.profile == profile.id,
        "the lab run's format or profile does not match the recording",
    )
    try:
        validate_marks(run)
    except LabError as error:
        raise RecordingError(str(error)) from None


def _check_glass_box(recording: GlassBoxRecording, profile: Profile) -> None:
    _require(recording.exposed, "a glass-box recording without its EXPOSED stamp")
    session = recording.session
    _require(
        session.profile == recording.meta.profile and not profile.lab_only,
        "the session's profile does not match the recording",
    )
    _require(isfinite(session.started), "the session's start time is not a number")
    ordinals = [e.ordinal for e in recording.events]
    _require(all(a < b for a, b in pairwise(ordinals)), "the recording's events are out of order")
    for event in recording.events:
        _require(isfinite(event.time), "a trace event's time is not a number")
        match event:
            case Traced(event=trace_schema.FrameTraced() as frame):
                _check_fields(frame)
            case Traced(event=trace_schema.TranscriptHashed(digest=digest)):
                _require(len(digest) == profile.hash_len, "a transcript hash has the wrong size")
            case _:
                pass


def _check_fields(traced: trace_schema.FrameTraced) -> None:
    """Each field lies inside the body and inside its parent, which comes before it."""
    seen: dict[str, trace_schema.Field] = {}
    for field in traced.fields:
        _require(field.name not in seen, "a frame's field names are duplicated")
        _require(
            field.offset + field.length <= len(traced.frame.body),
            "a frame's field lies outside its body",
        )
        parent = seen.get(field.parent) if field.parent else field
        _require(
            parent is not None
            and parent.offset <= field.offset
            and field.offset + field.length <= parent.offset + parent.length,
            "a frame's field lies outside its parent",
        )
        seen[field.name] = field
