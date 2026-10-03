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
the file is capped before it is read, the schema is strict (unknown fields and wrong types are
refused), every list has a bound, and a failure is a :class:`RecordingError` with a named reason
that never contains recorded bytes.
"""

from itertools import pairwise
from typing import Final

import msgspec
from msgspec import Struct

from qrp2p.core.trace import (
    FrameTraced,
    KeysSwitched,
    RecordTraced,
    RekeyStep,
    SecretDerived,
    SecretsReleased,
    SessionClosed,
    StateChanged,
    TranscriptHashed,
)
from qrp2p.lab.solo import LabRun

MAGIC: Final = b"QRLAB\0"
VERSION: Final = 1
HEADER: Final = MAGIC + bytes([VERSION])
NONCE_LEN: Final = 12
TAG_LEN: Final = 16
MAX_FILE: Final = 256 * 1024 * 1024
"""Bytes a recording may have; a larger file is refused before it is read."""
MAX_TITLE: Final = 200
MAX_STEPS: Final = 10_000
MAX_LOG: Final = 100_000
MAX_EVENTS: Final = 20_000
"""Events a glass-box recording may hold (a retained trace keeps at most about 12,000)."""
SUFFIX: Final = ".qrlab"


class RecordingError(Exception):
    """A recording that cannot be opened or saved; the message says why, never what it holds."""


class Meta(Struct, frozen=True, forbid_unknown_fields=True):
    """What a recording is, shown before it is opened."""

    title: str
    created: float
    """Wall-clock seconds since the epoch."""
    profile: str


class LabRecording(Struct, frozen=True, tag="lab", forbid_unknown_fields=True):
    """A solo-lab run."""

    meta: Meta
    run: LabRun


# -- a glass-box session's retained trace ------------------------------------------------------


class _Event(Struct, frozen=True, forbid_unknown_fields=True):
    ordinal: int
    time: float


class Frame(_Event, frozen=True, tag="frame"):
    """A captured frame."""

    event: FrameTraced


class State(_Event, frozen=True, tag="state"):
    """A state machine transition."""

    event: StateChanged


class Derived(_Event, frozen=True, tag="derived"):
    """A derivation the engine reported (name and size)."""

    event: SecretDerived


class Released(_Event, frozen=True, tag="released"):
    """References the engine dropped."""

    event: SecretsReleased


class Hashed(_Event, frozen=True, tag="hashed"):
    """A transcript hash."""

    event: TranscriptHashed


class Record(_Event, frozen=True, tag="record"):
    """A record's counters."""

    event: RecordTraced


class Switched(_Event, frozen=True, tag="switched"):
    """A key switch."""

    event: KeysSwitched


class Rekey(_Event, frozen=True, tag="rekey"):
    """A PQ rekey step."""

    event: RekeyStep


class Closed(_Event, frozen=True, tag="closed"):
    """The session's end."""

    event: SessionClosed


class Value(_Event, frozen=True, tag="value"):
    """A revealed secret, under its schedule name."""

    label: str
    value: bytes


class Opened(_Event, frozen=True, tag="opened"):
    """A record's revealed nonce and plaintext."""

    key: str
    seq: int
    nonce: bytes
    plaintext: bytes
    opened: bool


type Event = (
    Frame
    | State
    | Derived
    | Released
    | Hashed
    | Record
    | Switched
    | Rekey
    | Closed
    | Value
    | Opened
)


class Session(Struct, frozen=True, forbid_unknown_fields=True):
    """The recorded session's descriptor, as it stood when it was saved."""

    initiator: bool
    started: float
    profile: str
    peer_short_id: str
    established: bool
    ended: bool
    end_reason: str
    admit_reason: str
    by_peer: bool


class GlassBoxRecording(Struct, frozen=True, tag="glass_box", forbid_unknown_fields=True):
    """Our side of a glass-box session: its retained trace, revealed values included."""

    meta: Meta
    exposed: bool
    """The EXPOSED stamp: every value of this session can be read from it (always true)."""
    session: Session
    events: list[Event]


type Recording = LabRecording | GlassBoxRecording

_ENCODER: Final = msgspec.msgpack.Encoder()
_DECODER: Final = msgspec.msgpack.Decoder(Recording)


def encode(recording: Recording) -> bytes:
    """The recording's body, to be sealed.

    Raises:
        RecordingError: It exceeds a bound (it could not be opened again).
    """
    _check(recording)
    return _ENCODER.encode(recording)


def decode(body: bytes) -> Recording:
    """A recording from its opened body.

    Raises:
        RecordingError: Not a recording of this version, or beyond a bound.
    """
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


def _check(recording: Recording) -> None:
    if not 0 < len(recording.meta.title) <= MAX_TITLE:
        msg = f"a recording's title has 1 to {MAX_TITLE} characters"
        raise RecordingError(msg)
    match recording:
        case LabRecording(run=run):
            logs = len(run.alice_log) + len(run.bob_log)
            if len(run.steps) > MAX_STEPS or len(run.marks) > MAX_STEPS or logs > MAX_LOG:
                msg = "the lab run is longer than a recording may be"
                raise RecordingError(msg)
        case GlassBoxRecording(events=events, exposed=exposed):
            if not exposed:
                msg = "a glass-box recording without its EXPOSED stamp"
                raise RecordingError(msg)
            if len(events) > MAX_EVENTS:
                msg = "the recording holds more events than a session retains"
                raise RecordingError(msg)
            ordinals = [e.ordinal for e in events]
            if any(b <= a for a, b in pairwise(ordinals)) or (ordinals and ordinals[0] < 0):
                msg = "the recording's events are out of order"
                raise RecordingError(msg)
