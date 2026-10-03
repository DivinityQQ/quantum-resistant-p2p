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

import re
from itertools import chain, pairwise
from math import isfinite
from typing import Annotated, Final

import msgspec
from msgspec import Struct

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.crypto.provider import epoch_name
from qrp2p.core.trace import (
    Field,
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
from qrp2p.lab import trace_schema
from qrp2p.lab.classical import lab_profile_named
from qrp2p.lab.replay import Draw, Encapsulation, Entry, Signature
from qrp2p.lab.solo import CHAT_LIMIT, RUN_FORMAT, SEED_LEN, Kind, LabError, LabRun, validate_marks

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
MAX_CREATED: Final = 253_402_214_400
MAX_COUNTER: Final = 2**64 - 1
MAX_LABEL: Final = 160
_LABEL: Final = re.compile(r"[A-Za-z][A-Za-z_0-9]*(?:\[[0-9]+\])?(?:\+[0-9]+)?(?:\.(?:key|iv))?")


class RecordingError(Exception):
    """A recording that cannot be opened or saved; the message says why, never what it holds."""


class Meta(Struct, frozen=True, forbid_unknown_fields=True):
    """What a recording is, shown before it is opened."""

    title: Annotated[str, msgspec.Meta(min_length=1, max_length=MAX_TITLE)]
    created: float
    """Wall-clock seconds since the epoch."""
    profile: trace_schema.Label


class LabRecording(Struct, frozen=True, tag="lab", forbid_unknown_fields=True):
    """A solo-lab run."""

    meta: Meta
    run: LabRun


# -- a glass-box session's retained trace ------------------------------------------------------


class _Event(Struct, frozen=True, forbid_unknown_fields=True):
    ordinal: trace_schema.Counter
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

    label: trace_schema.Label
    value: trace_schema.Payload


class Opened(_Event, frozen=True, tag="opened"):
    """A record's revealed nonce and plaintext."""

    key: trace_schema.Label
    seq: trace_schema.Counter
    nonce: Annotated[bytes, msgspec.Meta(min_length=12, max_length=12)]
    plaintext: trace_schema.Payload
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
    profile: trace_schema.Label
    peer_short_id: Annotated[str, msgspec.Meta(max_length=MAX_LABEL)]
    established: bool
    ended: bool
    end_reason: Annotated[str, msgspec.Meta(max_length=MAX_LABEL)]
    admit_reason: Annotated[str, msgspec.Meta(max_length=MAX_LABEL)]
    by_peer: bool
    pinned_before: bool = False
    pin_result: str = "unavailable"
    contact_saved: bool = False


class GlassBoxRecording(Struct, frozen=True, tag="glass_box", forbid_unknown_fields=True):
    """Our side of a glass-box session: its retained trace, revealed values included."""

    meta: Meta
    exposed: bool
    """The EXPOSED stamp: every value of this session can be read from it (always true)."""
    session: Session
    events: Annotated[list[Event], msgspec.Meta(max_length=MAX_EVENTS)]


type Recording = LabRecording | GlassBoxRecording


class _WireFrame(_Event, frozen=True, tag="frame"):
    event: trace_schema.FrameTraced


class _WireState(_Event, frozen=True, tag="state"):
    event: trace_schema.StateChanged


class _WireDerived(_Event, frozen=True, tag="derived"):
    event: trace_schema.SecretDerived


class _WireReleased(_Event, frozen=True, tag="released"):
    event: trace_schema.SecretsReleased


class _WireHashed(_Event, frozen=True, tag="hashed"):
    event: trace_schema.TranscriptHashed


class _WireRecord(_Event, frozen=True, tag="record"):
    event: trace_schema.RecordTraced


class _WireSwitched(_Event, frozen=True, tag="switched"):
    event: trace_schema.KeysSwitched


class _WireRekey(_Event, frozen=True, tag="rekey"):
    event: trace_schema.RekeyStep


class _WireClosed(_Event, frozen=True, tag="closed"):
    event: trace_schema.SessionClosed


type _WireEvent = (
    _WireFrame
    | _WireState
    | _WireDerived
    | _WireReleased
    | _WireHashed
    | _WireRecord
    | _WireSwitched
    | _WireRekey
    | _WireClosed
    | Value
    | Opened
)


class _WireGlassBox(Struct, frozen=True, tag="glass_box", forbid_unknown_fields=True):
    meta: Meta
    exposed: bool
    session: Session
    events: Annotated[list[_WireEvent], msgspec.Meta(max_length=MAX_EVENTS)]


_ENCODER: Final = msgspec.msgpack.Encoder()
_DECODER: Final = msgspec.msgpack.Decoder(LabRecording | _WireGlassBox)


def encode(recording: Recording) -> bytes:
    """The recording's body, to be sealed.

    Raises:
        RecordingError: It exceeds a bound (it could not be opened again).
    """
    _check(recording)
    body = _ENCODER.encode(recording)
    _body_size(body)
    decode(body)  # enforce the same nested schema on writes as on reads
    return body


def decode(body: bytes) -> Recording:
    """A recording from its opened body.

    Raises:
        RecordingError: Not a recording of this version, or beyond a bound.
    """
    _body_size(body)
    try:
        wire = _DECODER.decode(body)
    except msgspec.ValidationError as error:
        msg = f"the recording does not match its schema ({_where(error)})"
        raise RecordingError(msg) from None
    except msgspec.DecodeError, UnicodeDecodeError:  # a string that is not UTF-8 included
        msg = "the recording is not valid MessagePack"
        raise RecordingError(msg) from None
    recording: Recording = (
        wire
        if isinstance(wire, LabRecording)
        else GlassBoxRecording(
            wire.meta, wire.exposed, wire.session, [_runtime(e) for e in wire.events]
        )
    )
    _check(recording)
    return recording


def _body_size(body: bytes) -> None:
    if len(body) > MAX_FILE - len(HEADER) - NONCE_LEN - TAG_LEN:
        msg = "the recording is larger than 256 MiB"
        raise RecordingError(msg)


def _runtime(event: _WireEvent) -> Event:  # noqa: PLR0911  # typed schema variants
    """Construct core events only after the strict nested file schema passed."""
    ordinal, time = event.ordinal, event.time
    match event:
        case _WireFrame():
            return Frame(
                ordinal, time, msgspec.convert(event.event, type=FrameTraced, from_attributes=True)
            )
        case _WireState():
            return State(
                ordinal, time, msgspec.convert(event.event, type=StateChanged, from_attributes=True)
            )
        case _WireDerived():
            return Derived(
                ordinal,
                time,
                msgspec.convert(event.event, type=SecretDerived, from_attributes=True),
            )
        case _WireReleased():
            return Released(
                ordinal,
                time,
                msgspec.convert(event.event, type=SecretsReleased, from_attributes=True),
            )
        case _WireHashed():
            return Hashed(
                ordinal,
                time,
                msgspec.convert(event.event, type=TranscriptHashed, from_attributes=True),
            )
        case _WireRecord():
            return Record(
                ordinal, time, msgspec.convert(event.event, type=RecordTraced, from_attributes=True)
            )
        case _WireSwitched():
            return Switched(
                ordinal, time, msgspec.convert(event.event, type=KeysSwitched, from_attributes=True)
            )
        case _WireRekey():
            return Rekey(
                ordinal, time, msgspec.convert(event.event, type=RekeyStep, from_attributes=True)
            )
        case _WireClosed():
            return Closed(
                ordinal,
                time,
                msgspec.convert(event.event, type=SessionClosed, from_attributes=True),
            )
        case _:
            return event


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


def _require(condition: bool, reason: str) -> None:  # noqa: FBT001  # validation predicate
    if not condition:
        raise RecordingError(reason)


def _check(recording: Recording) -> None:
    meta = recording.meta
    _require(
        0 < len(meta.title) <= MAX_TITLE, f"a recording's title has 1 to {MAX_TITLE} characters"
    )
    _require(
        isfinite(meta.created) and 0 <= meta.created <= MAX_CREATED,
        "the recording's creation time is outside the displayable range",
    )
    profile = lab_profile_named(meta.profile)
    if profile is None:
        msg = "the recording names an unknown profile"
        raise RecordingError(msg)
    match recording:
        case LabRecording(run=run):
            logs = len(run.alice_log) + len(run.bob_log)
            _require(
                len(run.steps) <= MAX_STEPS and len(run.marks) <= MAX_STEPS and logs <= MAX_LOG,
                "the lab run is longer than a recording may be",
            )
            _check_run(run, profile)
        case GlassBoxRecording():
            _check_glass(recording, profile)


def _check_glass(recording: GlassBoxRecording, profile: Profile) -> None:
    _require(recording.exposed, "a glass-box recording without its EXPOSED stamp")
    _require(
        len(recording.events) <= MAX_EVENTS,
        "the recording holds more events than a session retains",
    )
    session = recording.session
    _require(
        session.profile == recording.meta.profile and not profile.lab_only,
        "the session's profile does not match the recording",
    )
    _require(
        isfinite(session.started) and session.started >= 0, "the session's start time is invalid"
    )
    _require(
        session.pin_result in {"", "matched", "mismatched", "unavailable"},
        "the session's pin comparison result is invalid",
    )
    _require(
        session.pin_result in {"", "unavailable"} or (session.initiator and session.pinned_before),
        "the session's pin comparison has no earlier pin",
    )
    ordinals = [e.ordinal for e in recording.events]
    _require(
        not any(b <= a for a, b in pairwise(ordinals)) and (not ordinals or ordinals[0] >= 0),
        "the recording's events are out of order",
    )
    for event in recording.events:
        _require(isfinite(event.time) and event.time >= 0, "a trace event's time is invalid")
        _check_event(event, profile.hash_len)


def _check_run(run: LabRun, profile: Profile) -> None:
    _require(
        run.format == RUN_FORMAT and run.profile == profile.id,
        "the lab run's format or profile does not match the recording",
    )
    _require(
        all(len(seed) == SEED_LEN for seed in (*run.alice, *run.bob)),
        "the lab run's identity seeds have the wrong size",
    )
    try:
        validate_marks(run)
    except LabError as error:
        raise RecordingError(str(error)) from None
    for step in run.steps:
        valid = 0 < len(step.text) <= CHAT_LIMIT if step.kind is Kind.CHAT else not step.text
        _require(valid, "the lab run's step text is invalid")
    for entry in chain(run.alice_log, run.bob_log):
        _check_entry(entry, profile)


def _check_entry(entry: Entry, profile: Profile) -> None:
    match entry:
        case Draw(data=data):
            _require(
                len(data) in {SEED_LEN, profile.kem.seed_len}, "a provider draw has the wrong size"
            )
        case Signature():
            _require(
                entry.profile == profile.id
                and entry.role in {r.value for r in Role}
                and len(entry.th) == profile.hash_len
                and len(entry.sig) == profile.sig_len,
                "a provider signature has an invalid profile, role or size",
            )
        case Encapsulation():
            _require(
                entry.profile == profile.id
                and 0 <= entry.epoch <= MAX_COUNTER
                and len(entry.ek) == profile.ek_len
                and len(entry.ct) == profile.ct_len,
                "a provider encapsulation has an invalid profile, epoch or size",
            )
            bases = (
                ("ssM", "ssX", "ss")
                if profile.kem.ct_parts
                else (("ssX", "ss") if profile.lab_only else ("ss",))
            )
            names = [epoch_name(n, entry.epoch) for n in bases]
            _require(
                [n for n, _ in entry.secrets] == names
                and all(len(v) == profile.kem.ss_len for _, v in entry.secrets),
                "a provider encapsulation's named secrets are invalid",
            )


def _check_label(label: str) -> None:
    _require(
        len(label) <= MAX_LABEL
        and bool(_LABEL.fullmatch(label))
        and all(int(n) <= MAX_COUNTER for n in re.findall(r"\d+", label)),
        "a schedule label is invalid or outside the counter range",
    )


def _check_event(event: Event, hash_len: int) -> None:  # noqa: C901  # typed event variants
    _require(0 <= event.ordinal <= MAX_COUNTER, "a trace ordinal is outside the counter range")
    match event:
        case Frame(event=traced):
            _check_fields(traced)
        case Hashed(event=hashed):
            _check_label(hashed.name)
            _require(
                len(hashed.digest) == hash_len, "a transcript digest has the wrong profile size"
            )
        case Derived(event=derived):
            _check_label(derived.label)
        case Released(event=released):
            for label in released.labels:
                _check_label(label)
        case Value(label=label):
            _check_label(label)  # excludes identity seeds, which exist only in LabRun
        case Opened(key=key):
            _check_label(key)
            _require(
                0 <= event.seq <= MAX_COUNTER, "a record sequence is outside the counter range"
            )
        case Record(event=record):
            _require(
                all(0 <= n <= MAX_COUNTER for n in (record.epoch, record.generation, record.seq)),
                "a record counter is outside its range",
            )
        case Switched(event=switched):
            _require(
                all(0 <= n <= MAX_COUNTER for n in (switched.epoch, switched.generation)),
                "a key-switch counter is outside its range",
            )
        case Rekey(event=rekey):
            _require(0 <= rekey.epoch <= MAX_COUNTER, "a rekey counter is outside its range")
        case _:
            pass


def _check_fields(traced: FrameTraced) -> None:
    parents: dict[str, Field] = {}
    for field in traced.fields:
        _require(field.name not in parents, "a frame's field names are duplicated")
        _require(
            field.offset >= 0
            and field.length >= 0
            and field.offset + field.length <= len(traced.frame.body),
            "a frame's field lies outside its captured body",
        )
        if field.parent:
            parent = parents.get(field.parent)
            _require(
                parent is not None
                and parent.offset <= field.offset
                and field.offset + field.length <= parent.offset + parent.length,
                "a frame's field has an invalid parent range or order",
            )
        parents[field.name] = field
