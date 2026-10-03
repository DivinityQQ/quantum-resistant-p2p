"""Trace events carry the right public facts (DESIGN §11.2): what the Inspector will show."""

from collections.abc import Iterable

from qrp2p.core.crypto.aead import TAG_LEN
from qrp2p.core.crypto.profiles import HYBRID_1, NONCE_LEN, PQ_CNSA_1
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.trace import (
    Direction,
    Field,
    FrameTraced,
    KeysSwitched,
    RecordTraced,
    RekeyStep,
    ReleaseCause,
    SecretDerived,
    SecretsReleased,
    SessionClosed,
    StateChanged,
    TranscriptHashed,
    dissect,
)
from qrp2p.core.wire import Chat, Frame, FrameType, KeyUpdate
from tests.core.harness import Link, handshake, initiator, responder, session, traces

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


def sealed(name: str, offset: int, length: int) -> tuple[Field, ...]:
    return (
        Field(name, offset, length),
        Field("ciphertext", offset, length - TAG_LEN, parent=name),
        Field("tag", offset + length - TAG_LEN, TAG_LEN, parent=name),
    )


def test_dissect_hello_and_reply_fields() -> None:
    run = handshake()
    prefix = (
        Field("version", 0, 1),
        Field("profile", 1, 1),
        Field("flags", 2, 1),
        Field("nonce_I", 3, NONCE_LEN),
    )
    assert dissect(run.hello, None) == (*prefix, Field("ek_I", 35, HYBRID_1.ek_len))
    # X-Wing's ek is ML-KEM-768's key followed by X25519's (DESIGN §4.2), sizes from the KEM.
    assert dissect(run.hello, HYBRID_1) == (
        *prefix,
        Field("ek_I", 35, 1216),
        Field("pkM", 35, 1184, parent="ek_I"),
        Field("pkX", 35 + 1184, 32, parent="ek_I"),
    )
    # A profile whose KEM does not match the key's size does not split it.
    assert dissect(run.hello, PQ_CNSA_1)[-1] == Field("ek_I", 35, HYBRID_1.ek_len)
    reply = dissect(run.reply, HYBRID_1)
    ct_end = NONCE_LEN + HYBRID_1.ct_len
    assert reply == (
        Field("nonce_R", 0, NONCE_LEN),
        Field("ct", NONCE_LEN, 1120),
        Field("ctM", NONCE_LEN, 1088, parent="ct"),
        Field("ctX", NONCE_LEN + 1088, 32, parent="ct"),
        *sealed("ReplyInner (sealed)", ct_end, HYBRID_1.signed_inner_len + TAG_LEN),
    )
    assert sum(f.length for f in reply if not f.parent) == len(run.reply.body)


def test_dissect_a_kem_without_components() -> None:
    run = handshake(initiator(profile=PQ_CNSA_1), responder())
    assert dissect(run.reply, PQ_CNSA_1)[:2] == (
        Field("nonce_R", 0, NONCE_LEN),
        Field("ct", NONCE_LEN, PQ_CNSA_1.ct_len),
    )
    assert dissect(run.hello, PQ_CNSA_1)[-1] == Field("ek_I", 35, PQ_CNSA_1.ek_len)


def test_dissect_sealed_and_odd_frames() -> None:
    run = handshake()
    assert dissect(run.confirm, HYBRID_1) == sealed(
        "ConfirmInner (sealed)", 0, len(run.confirm.body)
    )
    assert dissect(run.admit, HYBRID_1) == sealed("AdmitInner (sealed)", 0, len(run.admit.body))
    assert dissect(Frame(FrameType.PROFILE_UNSUPPORTED, b"\x03"), None) == (
        Field("supported", 0, 1),
    )
    assert dissect(Frame(FrameType.RECORD, b"x" * 20), HYBRID_1) == sealed("record (sealed)", 0, 20)
    # Too short to hold a tag: one field, not a pretend split.
    assert dissect(Frame(FrameType.RECORD, b"x" * 15), HYBRID_1) == (
        Field("record (sealed)", 0, 15),
    )
    assert dissect(Frame(FrameType.RECORD, b"x" * 16), None)[-1] == Field(
        "tag", 0, 16, parent="record (sealed)"
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
    assert incoming[0].fields == dissect(run.hello, HYBRID_1)  # split with the offered profile
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
    assert frames[0].fields == sealed("record (sealed)", 0, len(net["i"].wire[0].body))
    assert [(t.direction, t.frame, t.fields) for t in of(net["r"].events, FrameTraced)] == [
        (Direction.IN, f, sealed("record (sealed)", 0, len(f.body))) for f in net["i"].wire
    ]
    assert [t.length for t in incoming] == [len(f.body) for f in net["i"].wire]


def test_key_update_and_rekey_are_traced() -> None:
    net = Link(*session())
    net.push("i", KeyUpdate())
    net.run()
    assert of(net["i"].events, KeysSwitched) == [KeysSwitched(Direction.OUT, 0, 1, "key_update")]
    assert of(net["r"].events, KeysSwitched) == [KeysSwitched(Direction.IN, 0, 1, "key_update")]
    assert [t.label for t in of(net["r"].events, SecretDerived)][-3:] == [
        "ap_I[0]+1",
        "ap_I[0]+1.key",
        "ap_I[0]+1.iv",
    ]
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


def released(events: Iterable[object]) -> list[tuple[tuple[str, ...], ReleaseCause]]:
    return [(t.labels, t.cause) for t in of(events, SecretsReleased)]


def test_the_handshake_reports_what_it_releases() -> None:
    run = handshake()
    on_reply = released(run.on_reply)
    assert on_reply == [
        (("dk",), ReleaseCause.USED),
        (("ssM", "ssX", "ss"), ReleaseCause.USED),
    ]
    hs = ("hs", "hs_R", "hs_I", "fk_R", "fk_I", "hs_R.key", "hs_R.iv", "hs_I.key", "hs_I.iv")
    for events in (run.on_admit, run.on_decision):
        assert released(events) == [
            (("derived[0]", "cs_0"), ReleaseCause.USED),
            (hs, ReleaseCause.HANDSHAKE_DONE),
        ]
    assert released(run.on_hello) == [(("ssM", "ssX", "ss"), ReleaseCause.USED)]


def test_a_failed_handshake_releases_what_it_held() -> None:
    run = handshake(until="confirm")
    events = run.r.reject(AdmitReason.BUSY, 4.0)
    assert released(events) == [
        (
            ("hs", "hs_R", "hs_I", "fk_R", "fk_I", "hs_R.key", "hs_R.iv", "hs_I.key", "hs_I.iv"),
            ReleaseCause.CLOSED,
        )
    ]
    # An initiator that never got a Reply still holds its ephemeral key.
    run = handshake(until="hello")
    assert released(run.i.tick(100.0)) == [(("dk",), ReleaseCause.CLOSED)]


def test_key_update_releases_the_old_generation() -> None:
    net = Link(*session())
    net.push("i", KeyUpdate())
    net.run()
    for side in ("i", "r"):
        assert released(net[side].events)[-1] == (
            ("ap_I[0]", "ap_I[0].key", "ap_I[0].iv"),
            ReleaseCause.REPLACED,
        )


def test_rekey_reports_every_release_in_order() -> None:
    net = Link(*session())
    net.absorb("i", net["i"].channel.start_rekey(20.0))
    net.run()
    switched = {
        ("ap_I[0]", "ap_I[0].key", "ap_I[0].iv"),
        ("ap_R[0]", "ap_R[0].key", "ap_R[0].iv"),
    }
    epoch_0 = (("derived[1]", "exporter_0"), ReleaseCause.EPOCH_DONE)
    initiator_side = released(net["i"].events)
    assert initiator_side[:3] == [
        (("dk[1]",), ReleaseCause.USED),
        (("ssM[1]", "ssX[1]"), ReleaseCause.USED),
        (("ss[1]", "cs_1"), ReleaseCause.USED),
    ]
    responder_side = released(net["r"].events)
    assert responder_side[:2] == [
        (("ssM[1]", "ssX[1]"), ReleaseCause.USED),
        (("ss[1]", "cs_1"), ReleaseCause.USED),
    ]
    for side in (initiator_side, responder_side):
        # Each direction is released as it switches, in whichever order the link delivers.
        assert {labels for labels, _ in side[-3:-1]} == switched
        assert {cause for _, cause in side[-3:-1]} == {ReleaseCause.REPLACED}
        assert side[-1] == epoch_0
    assert (len(initiator_side), len(responder_side)) == (6, 5)


def test_closing_during_a_rekey_releases_what_the_rekey_held() -> None:
    net = Link(*session())
    net.absorb("i", net["i"].channel.start_rekey(20.0))
    assert released(net["i"].channel.close()) == [(("dk[1]",), ReleaseCause.CLOSED)]


def test_secret_labels_are_unique_and_released_ones_were_derived() -> None:
    """The Inspector joins key-graph nodes, trace events and glass-box values by label."""
    run = handshake()
    net = Link(*run.channels())
    for start in (20.0, 200.0):
        net.advance(start)
        net.absorb("i", net["i"].channel.start_rekey(start))
        net.run()
        net.push("i", KeyUpdate())
        net.push("r", KeyUpdate())
        net.run()
    before = {
        "i": [*run.start, *run.on_reply, *run.on_admit],
        "r": [*run.on_hello, *run.on_confirm, *run.on_decision],
    }
    for side in ("i", "r"):
        events = [*before[side], *net[side].events]
        derived = [t.label for t in of(events, SecretDerived)]
        assert len(derived) == len(set(derived)), side
        assert {"dk[2]" if side == "i" else "ss[2]", "cs_2", "ap_R[2]+1.iv"} <= set(derived)
        for labels, _ in released(events):
            assert set(labels) <= set(derived), labels


def test_the_responder_traces_every_hello_it_receives() -> None:
    hello = handshake(until="start").hello
    for body in (b"", b"\x02", hello.body[:2], b"\x07" + hello.body[1:]):  # malformed: closed
        events = responder().receive(Frame(FrameType.HELLO, body), 1.0)
        (traced,) = [t for t in of(events, FrameTraced) if t.direction is Direction.IN]
        assert traced.frame.body == body
        assert traced.fields == dissect(traced.frame, None)
    # A Hello for a profile the responder does not serve is traced, then refused.
    events = responder(profiles=[PQ_CNSA_1]).receive(hello, 1.0)
    assert of(events, FrameTraced)[0].fields == dissect(hello, None)
    assert of(events, FrameTraced)[1].frame.type is FrameType.PROFILE_UNSUPPORTED


def test_a_rekey_traces_its_transcript_hash_on_both_sides() -> None:
    net = Link(*session())
    net.absorb("i", net["i"].channel.start_rekey(20.0))
    net.run()
    hashes = [of(net[side].events, TranscriptHashed) for side in ("i", "r")]
    assert [[h.name for h in side] for side in hashes] == [["th_rekey[1]"], ["th_rekey[1]"]]
    assert hashes[0][0].digest == hashes[1][0].digest
    assert len(hashes[0][0].digest) == HYBRID_1.hash_len
