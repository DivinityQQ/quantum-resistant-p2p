"""The ``.qrlab`` body and file framing (DESIGN §11.5): strict, bounded, and fuzzed.

A recording decodes to exactly what was encoded; anything else (another version, a truncated
file, a wrong type, an unknown field, a missing EXPOSED stamp, events out of order, a list
beyond its bound) is a RecordingError whose message names the problem and never holds a
recorded value; arbitrary bytes never raise anything else.
"""

import contextlib

import msgspec
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qrp2p.core.crypto.profiles import HYBRID_1
from qrp2p.core.trace import Direction, Field, FrameTraced, SecretDerived
from qrp2p.core.wire import Frame as WireFrame
from qrp2p.core.wire import FrameType
from qrp2p.lab import recording
from qrp2p.lab.recording import (
    HEADER,
    Derived,
    Frame,
    GlassBoxRecording,
    LabRecording,
    Meta,
    RecordingError,
    Session,
    Value,
    decode,
    encode,
    pack,
    unpack,
)
from qrp2p.lab.solo import SoloLab
from qrp2p.services.trace_bus import TraceBus
from tests.support import DeterministicRandom

META = Meta(title="first handshake", created=1_800_000_000.0, profile="HYBRID-1")
SESSION = Session(
    initiator=True,
    started=10.0,
    profile="HYBRID-1",
    peer_short_id="BOBB-BOBB",
    established=True,
    ended=False,
    end_reason="",
    admit_reason="",
    by_peer=False,
)
SECRET = b"\x5a" * 32


def lab_recording() -> LabRecording:
    lab = SoloLab.fresh(HYBRID_1, TraceBus(), (1, 2), DeterministicRandom("recording"))
    lab.run()
    return LabRecording(meta=META, run=lab.run_record())


def glass_box(**changes: object) -> GlassBoxRecording:
    frame = WireFrame(FrameType.HELLO, b"\1" * 40)
    events = [
        Frame(0, 1.0, event=FrameTraced(Direction.OUT, frame, (Field("nonce_I", 0, 32),))),
        Derived(1, 1.5, event=SecretDerived("hs", 32)),
        Value(2, 1.5, label="hs", value=SECRET),
    ]
    values: dict[str, object] = {
        "meta": META,
        "exposed": True,
        "session": SESSION,
        "events": events,
    }
    values.update(changes)
    return GlassBoxRecording(**values)  # type: ignore[arg-type]


def test_both_kinds_round_trip_exactly() -> None:
    for original in (lab_recording(), glass_box()):
        assert decode(encode(original)) == original


def test_a_file_is_its_header_then_the_sealed_body() -> None:
    sealed = b"\0" * 12 + b"ciphertext and tag"
    data = pack(sealed)
    assert data.startswith(b"QRLAB\0\x01")
    assert unpack(data) == sealed
    with pytest.raises(RecordingError, match="not a QRP2P recording"):
        unpack(b"PNG\r\n" + sealed)
    with pytest.raises(RecordingError, match="another version"):
        unpack(b"QRLAB\0\x02" + sealed)
    with pytest.raises(RecordingError, match="truncated"):
        unpack(HEADER + b"\0" * 20)


def test_an_oversized_file_is_refused_before_anything_else(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(recording, "MAX_FILE", 64)
    with pytest.raises(RecordingError, match="larger than 256 MiB"):
        unpack(HEADER + b"\0" * 64)


def test_the_schema_is_strict_and_its_errors_hold_no_values() -> None:
    body = msgspec.msgpack.decode(encode(glass_box()))
    body["session"]["surprise"] = 1
    with pytest.raises(RecordingError, match="does not match its schema"):
        decode(msgspec.msgpack.encode(body))
    body = msgspec.msgpack.decode(encode(glass_box()))
    body["events"][2]["value"] = "a value that is not bytes"
    with pytest.raises(RecordingError) as raised:
        decode(msgspec.msgpack.encode(body))
    assert "not bytes" not in str(raised.value)
    assert "$.events[2].value" in str(raised.value)
    body = msgspec.msgpack.decode(encode(lab_recording()))
    body["run"]["steps"][0]["kind"] = "SECRET-LOOKING-VALUE"
    with pytest.raises(RecordingError) as raised:
        decode(msgspec.msgpack.encode(body))
    assert "SECRET" not in str(raised.value)
    with pytest.raises(RecordingError, match="not valid MessagePack"):
        decode(b"\xc1")


def test_semantic_rules_are_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(RecordingError, match="EXPOSED stamp"):
        decode(msgspec.msgpack.encode(glass_box(exposed=False)))
    events = glass_box().events
    with pytest.raises(RecordingError, match="out of order"):
        encode(glass_box(events=[events[1], events[0]]))
    with pytest.raises(RecordingError, match="title"):
        encode(glass_box(meta=msgspec.structs.replace(META, title="")))
    with pytest.raises(RecordingError, match="title"):
        encode(glass_box(meta=msgspec.structs.replace(META, title="x" * 201)))
    monkeypatch.setattr(recording, "MAX_EVENTS", 2)
    with pytest.raises(RecordingError, match="more events"):
        decode(msgspec.msgpack.encode(glass_box()))
    monkeypatch.setattr(recording, "MAX_STEPS", 2)
    with pytest.raises(RecordingError, match="longer than a recording"):
        decode(msgspec.msgpack.encode(lab_recording()))


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(st.binary(max_size=4096))
def test_arbitrary_bytes_never_raise_anything_but_a_recording_error(data: bytes) -> None:
    for parse in (decode, unpack):
        with contextlib.suppress(RecordingError):
            parse(data)


@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(st.data())
def test_a_damaged_body_decodes_or_is_refused_by_name(data: st.DataObject) -> None:
    body = bytearray(encode(glass_box()))
    for _ in range(data.draw(st.integers(1, 8))):
        at = data.draw(st.integers(0, len(body) - 1))
        body[at] = data.draw(st.integers(0, 255))
    cut = data.draw(st.integers(0, len(body)))
    try:
        decoded = decode(bytes(body[:cut]))
    except RecordingError:
        return
    assert isinstance(decoded, GlassBoxRecording | LabRecording)
