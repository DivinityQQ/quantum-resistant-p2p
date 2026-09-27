"""Trace events carry the right public facts (DESIGN §11.2): what the Inspector will show."""

from collections.abc import Iterable

from qrp2p.core.crypto.profiles import HYBRID_1, NONCE_LEN
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.trace import (
    Direction,
    Field,
    FrameTraced,
    KeysSwitched,
    RecordTraced,
    RekeyStep,
    SecretDerived,
    SessionClosed,
    StateChanged,
    TranscriptHashed,
    dissect,
)
from qrp2p.core.wire import Chat, Frame, FrameType, KeyUpdate
from tests.core.harness import Link, handshake, session, traces

HANDSHAKE_HASHES = [
    "th_hello",
    "th_sig_R",
    "th_fin_R",
    "th_sig_I",
    "th_fin_I",
    "th_fin_A",
    "th_final",
]


def of[T](events: Iterable[object], kind: type[T]) -> list[T]:
    return [t for t in traces(events) if isinstance(t, kind)]


def test_dissect_hello_and_reply_fields() -> None:
    run = handshake()
    hello = dissect(run.hello, None)
    assert hello == (
        Field("version", 0, 1),
        Field("profile", 1, 1),
        Field("flags", 2, 1),
        Field("nonce_I", 3, NONCE_LEN),
        Field("ek_I", 35, HYBRID_1.ek_len),
    )
    reply = dissect(run.reply, HYBRID_1)
    assert reply == (
        Field("nonce_R", 0, NONCE_LEN),
        Field("ct", NONCE_LEN, HYBRID_1.ct_len),
        Field("ReplyInner (sealed)", NONCE_LEN + HYBRID_1.ct_len, HYBRID_1.signed_inner_len + 16),
    )
    assert sum(f.length for f in reply) == len(run.reply.body)


def test_dissect_sealed_and_odd_frames() -> None:
    run = handshake()
    assert dissect(run.confirm, HYBRID_1) == (
        Field("ConfirmInner (sealed)", 0, len(run.confirm.body)),
    )
    assert dissect(run.admit, HYBRID_1) == (Field("AdmitInner (sealed)", 0, len(run.admit.body)),)
    assert dissect(Frame(FrameType.PROFILE_UNSUPPORTED, b"\x03"), None) == (
        Field("supported", 0, 1),
    )
    assert dissect(Frame(FrameType.RECORD, b"x" * 20), HYBRID_1) == (
        Field("record (sealed)", 0, 20),
    )
    # A Reply without a known profile, or of the wrong size, and a truncated Hello: one field.
    assert dissect(run.reply, None) == (Field("body", 0, len(run.reply.body)),)
    assert dissect(Frame(FrameType.REPLY, b"xx"), HYBRID_1) == (Field("body", 0, 2),)
    assert dissect(Frame(FrameType.HELLO, b"\x02\x01"), None) == (Field("body", 0, 2),)
    shortest = dissect(Frame(FrameType.HELLO, bytes(3 + NONCE_LEN)), None)
    assert shortest[-1] == Field("ek_I", 3 + NONCE_LEN, 0)
    assert dissect(Frame(FrameType.HELLO, bytes(2 + NONCE_LEN)), None) == (
        Field("body", 0, 2 + NONCE_LEN),
    )


def test_handshake_trace_names_every_transcript_hash_in_order() -> None:
    run = handshake()
    i_events = [*run.start, *run.on_reply, *run.on_admit]
    r_events = [*run.on_hello, *run.on_confirm, *run.on_decision]
    assert [t.name for t in of(i_events, TranscriptHashed)] == HANDSHAKE_HASHES
    assert [t.name for t in of(r_events, TranscriptHashed)] == HANDSHAKE_HASHES
    assert [t.digest for t in of(i_events, TranscriptHashed)] == [
        t.digest for t in of(r_events, TranscriptHashed)
    ]
    assert all(len(t.digest) == 32 for t in of(i_events, TranscriptHashed))


def test_each_side_traces_the_kem_components_and_secrets() -> None:
    run = handshake()
    for events in ([*run.on_reply], [*run.on_hello]):
        labels = [t.label for t in of(events, SecretDerived)]
        assert labels[:3] == ["ssM", "ssX", "ss"]
        assert {"hs", "hs_R", "hs_I", "fk_R", "fk_I", "hs_R.key", "hs_I.iv"} <= set(labels)
        assert all(t.length in {12, 32} for t in of(events, SecretDerived))


def test_frames_and_states_are_traced_with_direction() -> None:
    run = handshake()
    out = of(run.start, FrameTraced)
    assert [(t.direction, t.frame) for t in out] == [(Direction.OUT, run.hello)]
    assert out[0].fields == dissect(run.hello, HYBRID_1)
    incoming = of(run.on_hello, FrameTraced)
    assert [(t.direction, t.frame.type) for t in incoming] == [
        (Direction.IN, FrameType.HELLO),
        (Direction.OUT, FrameType.REPLY),
    ]
    assert incoming[0].fields == dissect(run.hello, None)
    assert incoming[1].fields == dissect(run.reply, HYBRID_1)
    reply_in = of(run.on_reply, FrameTraced)[0]
    assert (reply_in.direction, reply_in.fields) == (Direction.IN, dissect(run.reply, HYBRID_1))
    assert [t.state for t in of([*run.start, *run.on_reply, *run.on_admit], StateChanged)] == [
        "wait_reply",
        "wait_admit",
        "established",
    ]
    assert {t.machine for t in of(run.on_hello, StateChanged)} == {"responder"}


def test_handshake_close_is_traced() -> None:
    run = handshake(until="confirm")
    events = run.r.reject(AdmitReason.BUSY, 4.0)
    assert of(events, SessionClosed) == [
        SessionClosed(CloseReason.POLICY, AdmitReason.BUSY, by_peer=False)
    ]


def test_records_are_traced_with_counters_and_kind() -> None:
    net = Link(*session())
    net.push("i", Chat(id=bytes(16), text="a"))
    net.push("i", Chat(id=bytes(16), text="b"))
    net.run()
    out = of(net["i"].events, RecordTraced)
    assert [(t.direction, t.epoch, t.generation, t.seq, t.kind) for t in out] == [
        (Direction.OUT, 0, 0, 0, "chat"),
        (Direction.OUT, 0, 0, 1, "chat"),
    ]
    assert [t.length for t in out] == [len(f.body) for f in net["i"].wire]
    incoming = of(net["r"].events, RecordTraced)
    assert [(t.direction, t.epoch, t.generation, t.seq, t.kind) for t in incoming] == [
        (Direction.IN, 0, 0, 0, "chat"),
        (Direction.IN, 0, 0, 1, "chat"),
    ]
    frames = of(net["i"].events, FrameTraced)
    assert [(t.direction, t.frame) for t in frames] == [(Direction.OUT, f) for f in net["i"].wire]
    assert frames[0].fields == (Field("record (sealed)", 0, len(net["i"].wire[0].body)),)
    assert [(t.direction, t.frame, t.fields) for t in of(net["r"].events, FrameTraced)] == [
        (Direction.IN, f, (Field("record (sealed)", 0, len(f.body)),)) for f in net["i"].wire
    ]
    assert [t.length for t in incoming] == [len(f.body) for f in net["i"].wire]


def test_key_update_and_rekey_are_traced() -> None:
    net = Link(*session())
    net.push("i", KeyUpdate())
    net.run()
    assert of(net["i"].events, KeysSwitched) == [KeysSwitched(Direction.OUT, 0, 1, "key_update")]
    assert of(net["r"].events, KeysSwitched) == [KeysSwitched(Direction.IN, 0, 1, "key_update")]
    assert of(net["r"].events, SecretDerived)[-1].label == "ap_I[0]+1"
    net.push("i", Chat(id=bytes(16), text="after update"))
    net.run()
    assert of(net["r"].events, RecordTraced)[-1].generation == 1

    net.absorb("i", net["i"].channel.start_rekey(20.0))
    net.run()
    i_switched = of(net["i"].events, KeysSwitched)[1:]
    r_switched = of(net["r"].events, KeysSwitched)[1:]
    assert sorted(i_switched, key=str) == sorted(
        [KeysSwitched(Direction.OUT, 1, 0, "rekey"), KeysSwitched(Direction.IN, 1, 0, "rekey")],
        key=str,
    )
    assert sorted(r_switched, key=str) == sorted(i_switched, key=str)
    assert of(net["i"].events, RekeyStep) == [
        RekeyStep("offer", 0),
        RekeyStep("finish", 0),
        RekeyStep("done", 1),
    ]
    assert of(net["r"].events, RekeyStep) == [RekeyStep("answer", 0), RekeyStep("done", 1)]
    net.push("r", Chat(id=bytes(16), text="epoch 1"))
    net.run()
    last_in = of(net["i"].events, RecordTraced)[-1]
    assert (last_in.epoch, last_in.generation, last_in.seq) == (1, 0, 0)
    last_out = of(net["r"].events, RecordTraced)[-1]
    assert (last_out.direction, last_out.epoch, last_out.seq) == (Direction.OUT, 1, 0)
    assert all(isinstance(t.length, int) for t in of(net["i"].events, SecretDerived))


def test_session_close_is_traced_on_both_sides() -> None:
    net = Link(*session())
    net.absorb("i", net["i"].channel.close(CloseReason.LOCKED))
    net.run()
    assert of(net["i"].events, SessionClosed) == [
        SessionClosed(CloseReason.LOCKED, None, by_peer=False)
    ]
    assert of(net["r"].events, SessionClosed) == [
        SessionClosed(CloseReason.LOCKED, None, by_peer=True)
    ]
