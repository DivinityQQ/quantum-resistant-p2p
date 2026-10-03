"""The record layer: records, KeyUpdate, the signed PQ rekey, liveness and close (DESIGN §8)."""

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qrp2p.core.crypto import aead
from qrp2p.core.crypto.kdf import TrafficKeys
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, REAL_PROFILES, Profile
from qrp2p.core.errors import CloseReason, ProtocolError
from qrp2p.core.events import Closed, Deliver, Priority, Queue, Send
from qrp2p.core.record import (
    IDLE_TIMEOUT,
    KEY_UPDATE_RECORDS,
    KEY_UPDATE_SECONDS,
    PING_AFTER,
    REKEY_MIN_INTERVAL,
    REKEY_SECONDS,
    ChannelState,
    is_control,
)
from qrp2p.core.trace import KeysSwitched, RekeyStep
from qrp2p.core.wire import (
    MAX_RECORD_BODY,
    Chat,
    Close,
    FileChunk,
    Frame,
    FrameReader,
    FrameType,
    Inner,
    KeyUpdate,
    Ping,
    Pong,
    Receipt,
    RekeyAnswer,
    RekeyFinish,
    RekeyOffer,
    RekeySwitch,
    decode_inner,
    encode_inner,
)
from tests.core.harness import ESTABLISHED_AT as T0
from tests.core.harness import Link, initiator, none_of, one, sent, session, traces

ID = b"\x01" * 16


def chat(text: str, n: int = 1) -> Chat:
    return Chat(id=n.to_bytes(16, "big"), text=text)


def link(profile: Profile = HYBRID_1, **kwargs: object) -> Link:
    i, r = session(i=initiator(profile=profile))
    return Link(i, r, **kwargs)  # type: ignore[arg-type]


def open_with(keys: TrafficKeys, seq: int, frame: Frame, profile: Profile = HYBRID_1) -> bytes:
    return aead.unseal(profile.aead, keys, seq, frame.header, frame.body)


# --- records -----------------------------------------------------------------------------------


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_messages_flow_both_ways_in_order(profile: Profile) -> None:
    net = link(profile)
    for n in range(5):
        net.push("i", chat(f"hi {n}", n))
        net.push("r", chat(f"yo {n}", n))
    net.run()
    assert net["r"].delivered == [chat(f"hi {n}", n) for n in range(5)]
    assert net["i"].delivered == [chat(f"yo {n}", n) for n in range(5)]


def test_sequence_numbers_are_implicit_and_start_at_zero() -> None:
    net = link()
    net.push("i", chat("a"))
    net.push("i", chat("b"))
    net.run()
    i = net["i"].channel
    first, second = net["i"].wire
    keys = i._send.keys
    assert decode_inner(open_with(keys, 0, first)) == chat("a")
    assert decode_inner(open_with(keys, 1, second)) == chat("b")
    assert len(first.body) == len(b"") + len(first.body)  # nothing but ciphertext and tag
    with pytest.raises(ProtocolError):
        open_with(keys, 1, first)


def test_writer_priority_puts_control_first() -> None:
    assert is_control(Ping())
    assert is_control(RekeySwitch())
    assert not is_control(chat("x"))
    net = link()
    net.push("i", FileChunk(file_id=ID, data=b"x"), Priority.FILE)
    net.push("i", chat("c"))
    net.push("i", Ping(), Priority.CONTROL)
    net.run()
    kinds = [type(m).__name__ for m in net["r"].delivered]
    assert kinds == ["Chat", "FileChunk"]  # the ping was answered, not delivered
    assert net["i"].channel._recv.seq == 1  # the pong came back


def test_frames_never_interleave_and_split_cleanly() -> None:
    """v1 regression 3: interleaved chunked frames lost both messages."""
    net = link()
    for n in range(3):
        net.push("i", FileChunk(file_id=ID, data=bytes([n]) * 16_000), Priority.FILE)
        net.push("i", chat(f"m{n}", n))
    stream = b""
    r = net["r"].channel
    net.tamper = None
    for _ in range(6):
        net.step("i")
    stream = b"".join(f.encode() for f in net["i"].wire)
    frames = FrameReader().feed(stream)
    assert frames == net["i"].wire
    assert len(net["r"].delivered) == 6
    assert r.state is ChannelState.OPEN


# --- attacks on records (Attack Lab 4, 5; v1 regression 2) ---------------------------------------


def expect_decrypt_failed(net: Link, side: str = "r") -> None:
    closed = one(net[side].closed, Closed)
    assert closed.reason is CloseReason.DECRYPT_FAILED
    assert net[side].channel.state is not ChannelState.OPEN


def test_flipped_bit_is_decrypt_failed_and_announced() -> None:
    """Attack Lab scenario 4."""

    def flip(name: str, frame: Frame) -> Frame:
        if name != "i":
            return frame
        return Frame(frame.type, bytes([frame.body[0] ^ 1]) + frame.body[1:])

    net = link(tamper=flip)
    net.push("i", chat("hello"))
    net.run()
    expect_decrypt_failed(net)
    assert net["r"].delivered == []
    # The responder still sent close { decrypt_failed } over its working direction.
    assert len(net["r"].wire) == 1
    assert one(net["i"].closed, Closed) == Closed(CloseReason.DECRYPT_FAILED, by_peer=True)


def test_replay_and_reorder_are_decrypt_failed() -> None:
    """Attack Lab scenario 5, and v1 regression 2 (a replay accepted after dedup eviction)."""
    net = link()
    for n in range(300):  # far past v1's 100-entry dedup set
        net.push("i", chat(str(n), n))
    net.run()
    old = net["i"].wire[0]
    events = net["r"].channel.receive(old, 20.0)
    assert one(events, Closed).reason is CloseReason.DECRYPT_FAILED
    assert none_of(events, Deliver)

    net = link()
    net.push("i", chat("a"))
    net.push("i", chat("b"))
    first_events = net["i"].channel.seal_next(chat("a"), 11.0)
    second_events = net["i"].channel.seal_next(chat("b"), 11.0)
    r = net["r"].channel
    events = r.receive(sent(second_events)[0], 12.0)  # reordered
    assert one(events, Closed).reason is CloseReason.DECRYPT_FAILED
    assert r.receive(sent(first_events)[0], 12.0) == []  # closing channels ignore input


def test_dropped_record_breaks_the_next_one() -> None:
    net = link()
    i, r = net["i"].channel, net["r"].channel
    i.seal_next(chat("lost"), 11.0)
    events = r.receive(sent(i.seal_next(chat("next"), 11.0))[0], 12.0)
    assert one(events, Closed).reason is CloseReason.DECRYPT_FAILED


def test_oversize_and_non_record_frames() -> None:
    _, r = session()
    too_big = Frame(FrameType.RECORD, b"\x00" * (MAX_RECORD_BODY + 1))
    assert one(r.receive(too_big, 11.0), Closed).reason is CloseReason.OVERSIZE
    _, r = session()
    events = r.receive(Frame(FrameType.HELLO, b"\x02\x01\x00"), 11.0)
    assert one(events, Closed).reason is CloseReason.UNEXPECTED_MESSAGE
    _, r = session()
    assert one(r.receive(Frame(FrameType.RECORD, b"short"), 11.0), Closed).reason is (
        CloseReason.DECRYPT_FAILED
    )


def test_valid_record_with_bad_schema_is_schema_error() -> None:
    i, r = session()
    keys, profile = i._send.keys, i.profile
    plaintext = b"\x81\xa4kind\xa4nope"
    header = Frame(FrameType.RECORD, b"\x00" * (len(plaintext) + 16)).header
    body = aead.seal(profile.aead, keys, 0, header, plaintext)
    assert one(r.receive(Frame(FrameType.RECORD, body), 11.0), Closed).reason is (
        CloseReason.SCHEMA_ERROR
    )


def test_a_record_whose_text_is_not_utf8_is_a_schema_error() -> None:
    """Authentic, well-formed MessagePack, but a string that is not UTF-8: a named close."""
    i, r = session()
    keys, profile = i._send.keys, i.profile
    plaintext = bytearray(encode_inner(Chat(id=bytes(16), text="hello")))
    plaintext[plaintext.index(b"hello")] = 0x80
    header = Frame(FrameType.RECORD, b"\x00" * (len(plaintext) + 16)).header
    body = aead.seal(profile.aead, keys, 0, header, bytes(plaintext))
    assert one(r.receive(Frame(FrameType.RECORD, body), 11.0), Closed).reason is (
        CloseReason.SCHEMA_ERROR
    )


# --- close -------------------------------------------------------------------------------------


def test_close_normal_is_sent_and_received() -> None:
    net = link()
    net.absorb("i", net["i"].channel.close())
    assert one(net["i"].closed, Closed) == Closed(CloseReason.NORMAL)
    assert net["i"].channel.state is ChannelState.CLOSING
    net.run()
    assert net["i"].channel.state is ChannelState.CLOSED
    assert one(net["r"].closed, Closed) == Closed(CloseReason.NORMAL, by_peer=True)
    assert net["r"].channel.state is ChannelState.CLOSED
    with pytest.raises(RuntimeError):
        net["i"].channel.seal_next(chat("late"), 12.0)
    assert net["i"].channel.close() == []


def test_closing_channel_seals_only_the_close() -> None:
    i, _ = session()
    i.close(CloseReason.LOCKED)
    with pytest.raises(RuntimeError):
        i.seal_next(chat("no"), 11.0)
    assert sent(i.seal_next(Close(reason=CloseReason.LOCKED), 11.0))
    assert i.state is ChannelState.CLOSED


def test_sender_is_the_session_not_a_field() -> None:
    """v1 regression 1: a peer set sender_id / is_system inside a message."""
    i, r = session()
    assert "sender" not in Chat.__struct_fields__
    assert "is_system" not in Chat.__struct_fields__
    delivered = one(r.receive(sent(i.seal_next(chat("x"), 11.0))[0], 11.0), Deliver)
    assert delivered.message == chat("x")
    assert r.peer == i._identity.bundle


# --- liveness ----------------------------------------------------------------------------------


def test_ping_after_quiet_period_and_pong() -> None:
    net = link()
    net.tick(T0 + PING_AFTER - 0.1)
    assert net["i"].queue == []
    net.tick(T0 + PING_AFTER)
    assert [m for _, _, m in net["i"].queue] == [Ping()]
    net.tick(T0 + PING_AFTER + 1)
    assert [m for _, _, m in net["i"].queue] == [Ping()]  # queued once
    net.run()
    # Both sides were quiet, so both pinged; each received the other's ping and a pong.
    assert net["i"].channel._recv.seq == net["r"].channel._recv.seq == 2
    assert Pong in [
        type(m)
        for m in (
            decode_inner(open_with(net["r"].channel._send.keys, s, f))
            for s, f in enumerate(net["r"].wire)
        )
    ]
    assert net["r"].delivered == net["i"].delivered == []


def test_idle_timeout_closes_with_timeout() -> None:
    net = link()
    net.tick(T0 + IDLE_TIMEOUT)
    for side in ("i", "r"):
        assert one(net[side].closed, Closed).reason is CloseReason.TIMEOUT
        assert Close(reason=CloseReason.TIMEOUT) in [m for _, _, m in net[side].queue]


# --- KeyUpdate ---------------------------------------------------------------------------------


def test_key_update_after_ten_minutes() -> None:
    net = link()
    old = net["i"].channel._send.keys
    net.push("i", chat("before"))
    net.run()
    net.advance(T0 + KEY_UPDATE_SECONDS)
    net.push("i", chat("after", 2))
    net.run()
    i, r = net["i"].channel, net["r"].channel
    assert net["r"].delivered[-1] == chat("after", 2)
    assert i._send.generation == r._recv.generation == 1
    assert i._send.keys.key != old.key
    last = net["i"].wire[-1]
    with pytest.raises(ProtocolError):  # the old key cannot open records under the new one
        open_with(old, 0, last)
    switched = [t for t in traces(net["i"].events) if isinstance(t, KeysSwitched)]
    assert switched[0].cause == "key_update"


def test_key_update_after_2_16_records() -> None:
    net = link()
    net["i"].channel._send.records = KEY_UPDATE_RECORDS
    net.tick(11.0)
    assert KeyUpdate() in [m for _, _, m in net["i"].queue]
    net.run()
    assert net["r"].channel._recv.generation == 1
    assert net["i"].channel._send.records == 0


def test_key_update_is_forward_secure_within_the_epoch() -> None:
    i, _ = session()
    before = i._send.secret
    i.seal_next(KeyUpdate(), 11.0)
    after = i._send.secret
    assert after != before
    assert after.label == f"{before.label}+1"


# --- the signed PQ rekey -------------------------------------------------------------------------


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_rekey_moves_both_sides_to_a_new_epoch(profile: Profile) -> None:
    net = link(profile)
    i, r = net["i"].channel, net["r"].channel
    old_exporter = i._epoch.exporter
    net.absorb("i", i.start_rekey(20.0))
    # Chat keeps flowing while the rekey runs.
    for n in range(3):
        net.push("i", chat(f"i{n}", n))
        net.push("r", chat(f"r{n}", n))
    net.run()
    assert i.epoch == r.epoch == 1
    assert not i.rekey_in_progress
    assert not r.rekey_in_progress
    assert i._epoch.exporter == r._epoch.exporter != old_exporter
    assert i._send.secret == r._recv.secret
    assert i._recv.secret == r._send.secret
    assert len(net["r"].delivered) == len(net["i"].delivered) == 3
    steps = [t.step for t in traces(net["i"].events) if isinstance(t, RekeyStep)]
    assert steps == ["offer", "finish", "done"]
    net.push("r", chat("new epoch"))
    net.run()
    assert net["i"].delivered[-1] == chat("new epoch")


def test_rekey_starts_on_the_hour_and_at_most_once_a_minute() -> None:
    net = link()
    i = net["i"].channel
    net.advance(T0 + REKEY_SECONDS - 1)
    assert i.epoch == 0
    net.advance(T0 + REKEY_SECONDS)
    assert i.epoch == 1
    assert i.start_rekey(net.now + REKEY_MIN_INTERVAL - 1) == []
    assert one(i.start_rekey(net.now + REKEY_MIN_INTERVAL), Queue).message.__class__ is RekeyOffer
    with pytest.raises(RuntimeError):
        net["r"].channel.start_rekey(net.now)


def rekey_messages(profile: Profile = HYBRID_1) -> tuple[Link, RekeyOffer]:
    net = link(profile)
    offer = one(net["i"].channel.start_rekey(20.0), Queue).message
    assert isinstance(offer, RekeyOffer)
    return net, offer


def deliver(net: Link, side: str, message: Inner, now: float = 20.0) -> list[object]:
    """Send ``message`` to ``side`` as the other side's peer would, state machine bypassed."""
    return list(net[side].channel.receive(net.raw(net.other(side), message), now))


@pytest.mark.parametrize(
    ("side", "message", "reason"),
    [
        ("i", RekeyOffer(ek=b"\x00" * 1216), CloseReason.UNEXPECTED_MESSAGE),  # R cannot offer
        ("r", RekeyAnswer(ct=b"", sig=b""), CloseReason.UNEXPECTED_MESSAGE),
        ("i", RekeyAnswer(ct=b"", sig=b""), CloseReason.UNEXPECTED_MESSAGE),  # nothing offered
        ("r", RekeyFinish(sig=b""), CloseReason.UNEXPECTED_MESSAGE),
        ("r", RekeySwitch(), CloseReason.UNEXPECTED_MESSAGE),
        ("i", RekeySwitch(), CloseReason.UNEXPECTED_MESSAGE),
        ("r", RekeyOffer(ek=b"\x00" * 10), CloseReason.SCHEMA_ERROR),
        ("r", RekeyOffer(ek=b"\xff" * 1216), CloseReason.INVALID_KEM_KEY),
    ],
)
def test_rekey_messages_out_of_place(side: str, message: Inner, reason: CloseReason) -> None:
    net = link()
    assert one(deliver(net, side, message), Closed).reason is reason


def test_second_offer_during_a_rekey_is_unexpected() -> None:
    net, offer = rekey_messages()
    deliver(net, "r", offer)
    assert one(deliver(net, "r", offer, 21.0), Closed).reason is CloseReason.UNEXPECTED_MESSAGE


def test_offers_too_close_together_are_unexpected() -> None:
    net = link()
    i = net["i"].channel
    net.absorb("i", i.start_rekey(20.0))
    net.run()
    i._last_rekey_start = float("-inf")  # an initiator that ignores its own rate limit
    net.absorb("i", i.start_rekey(25.0))
    net.run()
    assert one(net["r"].closed, Closed).reason is CloseReason.UNEXPECTED_MESSAGE


def answer_for(net: Link, offer: RekeyOffer) -> RekeyAnswer:
    events = deliver(net, "r", offer)
    message = one(events, Queue).message
    assert isinstance(message, RekeyAnswer)
    return message


def flip0(data: bytes) -> bytes:
    return bytes([data[0] ^ 1]) + data[1:]


def test_rekey_answer_with_bad_signature_closes() -> None:
    net, offer = rekey_messages()
    answer = answer_for(net, offer)
    bad = RekeyAnswer(ct=answer.ct, sig=flip0(answer.sig))
    assert one(deliver(net, "i", bad), Closed).reason is CloseReason.SIGNATURE_INVALID


def test_rekey_answer_with_substituted_ciphertext_closes() -> None:
    """An active attacker with the session keys (A5) swaps in its own encapsulation (8b)."""
    net, offer = rekey_messages()
    answer = answer_for(net, offer)
    _, mallory_ct = HYBRID_1.kem.encapsulate(offer.ek)
    bad = RekeyAnswer(ct=mallory_ct, sig=answer.sig)
    assert one(deliver(net, "i", bad), Closed).reason is CloseReason.SIGNATURE_INVALID


def test_rekey_answer_wrong_sizes() -> None:
    net, offer = rekey_messages()
    answer = answer_for(net, offer)
    for bad in (
        RekeyAnswer(ct=answer.ct[:-1], sig=answer.sig),
        RekeyAnswer(ct=answer.ct, sig=answer.sig + b"\x00"),
    ):
        n2, o2 = rekey_messages()
        answer_for(n2, o2)
        assert one(deliver(n2, "i", bad), Closed).reason is CloseReason.SCHEMA_ERROR
    del net


def test_rekey_finish_with_bad_signature_closes() -> None:
    net, offer = rekey_messages()
    answer = answer_for(net, offer)
    finish = next(e.message for e in deliver(net, "i", answer) if isinstance(e, Queue))
    assert isinstance(finish, RekeyFinish)
    bad = RekeyFinish(sig=flip0(finish.sig))
    assert one(deliver(net, "r", bad), Closed).reason is CloseReason.SIGNATURE_INVALID
    net2, offer2 = rekey_messages()
    answer_for(net2, offer2)
    short = RekeyFinish(sig=finish.sig[:-1])
    assert one(deliver(net2, "r", short), Closed).reason is CloseReason.SCHEMA_ERROR


def test_rekey_signatures_are_bound_to_the_session() -> None:
    """A rekey answer from one session does not verify in another (the exporter differs)."""
    net_a, offer_a = rekey_messages()
    net_b, _ = rekey_messages()
    answer_a = answer_for(net_a, offer_a)
    # Session B's initiator gets session A's answer; B's own offer is outstanding.
    assert one(deliver(net_b, "i", answer_a), Closed).reason in {
        CloseReason.SIGNATURE_INVALID,
        CloseReason.KEM_FAILURE,
    }


def test_leaked_traffic_keys_stop_working_after_a_rekey() -> None:
    """Attack Lab scenario 8a: a passive attacker holding the current receive keys."""
    net = link()
    leaked = net["r"].channel._recv.keys
    net.push("i", chat("secret 1"))
    net.run()
    assert decode_inner(open_with(leaked, 0, net["i"].wire[0])) == chat("secret 1")
    net.absorb("i", net["i"].channel.start_rekey(20.0))
    net.run()
    net.push("i", chat("secret 2", 2))
    net.run()
    last = net["i"].wire[-1]
    for seq in range(10):
        with pytest.raises(ProtocolError):
            open_with(leaked, seq, last)
    assert net["r"].delivered[-1] == chat("secret 2", 2)


# --- fuzz ----------------------------------------------------------------------------------------


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(list(FrameType)), st.binary(max_size=MAX_RECORD_BODY + 64))
def test_garbage_frames_close_with_a_named_reason(frame_type: FrameType, body: bytes) -> None:
    _, r = session()
    events = r.receive(Frame(frame_type, body), 11.0)
    assert one(events, Closed).reason in {
        CloseReason.DECRYPT_FAILED,
        CloseReason.OVERSIZE,
        CloseReason.UNEXPECTED_MESSAGE,
    }


def test_other_profile_sessions_are_independent() -> None:
    a = link(PQ_CNSA_1)
    b = link(HYBRID_1)
    a.push("i", chat("x"))
    a.run()
    frame = a["i"].wire[0]
    assert one(b["r"].channel.receive(frame, 11.0), Closed).reason is CloseReason.DECRYPT_FAILED
    assert none_of([], Send)
    assert Receipt(id=ID) != chat("x")


# --- boundaries and erasure (mutation testing found these gaps) ----------------------------------


def test_largest_record_round_trips() -> None:
    from qrp2p.core.wire import MAX_RECORD_PLAINTEXT, encode_inner  # noqa: PLC0415

    # Fill a record to exactly the plaintext limit with a rekey blob (no per-field cap).
    pad = MAX_RECORD_PLAINTEXT - len(encode_inner(RekeyOffer(ek=b"\x00" * 300)))
    biggest = RekeyOffer(ek=b"\x00" * (300 + pad))
    assert len(encode_inner(biggest)) == MAX_RECORD_PLAINTEXT
    i, r = session()
    frame = sent(i.seal_next(biggest, 11.0))[0]
    assert len(frame.body) == MAX_RECORD_BODY
    # The record layer accepts the size; the rekey layer then refuses the wrong-size key.
    assert one(r.receive(frame, 11.0), Closed).reason is CloseReason.SCHEMA_ERROR


def test_key_update_by_count_triggers_exactly_at_the_threshold() -> None:
    net = link()
    i = net["i"].channel
    for n in range(3):
        net.push("i", chat("x", n))
    net.run()
    assert i._send.records == 3
    i._send.records = KEY_UPDATE_RECORDS - 1
    net.tick(11.0)
    assert KeyUpdate() not in [m for _, _, m in net["i"].queue]
    net.push("i", chat("one more"))
    net.run()
    net.tick(12.0)
    net.tick(13.0)
    assert [m for _, _, m in net["i"].queue].count(KeyUpdate()) == 1  # queued once


def test_rekey_offer_exactly_at_the_minimum_gap_is_accepted() -> None:
    net = link()
    i, r = net["i"].channel, net["r"].channel
    net.now = 20.0
    net.absorb("i", i.start_rekey(net.now))
    net.run()
    i._last_rekey_start = float("-inf")
    net.now = 20.0 + 30.0
    net.absorb("i", i.start_rekey(net.now))
    net.run()
    assert r.state is ChannelState.OPEN
    assert i.epoch == r.epoch == 2


def test_duplicate_rekey_switch_is_unexpected() -> None:
    net, offer = rekey_messages()
    answer = answer_for(net, offer)
    finish_events = deliver(net, "i", answer)
    finish = [e.message for e in finish_events if isinstance(e, Queue)]
    assert [type(m) for m in finish] == [RekeyFinish, RekeySwitch]
    r = net["r"].channel
    # The initiator seals finish and switch for real, so its send key moves to the new epoch.
    for message in finish:
        net.absorb("r", r.receive(sent(net["i"].channel.seal_next(message, 20.0))[0], 20.0))
    assert r._rekey is not None
    assert r._rekey.recv_switched
    assert not r._rekey.send_switched  # the responder's own switch is still queued
    events = r.receive(net.raw("i", RekeySwitch()), 20.0)
    assert one(events, Closed).reason is CloseReason.UNEXPECTED_MESSAGE


def test_rekey_switch_cannot_be_sealed_before_new_keys() -> None:
    i, _ = session()
    with pytest.raises(RuntimeError, match="before the new keys"):
        i.seal_next(RekeySwitch(), 11.0)


def test_rekey_erases_what_it_no_longer_needs() -> None:
    net, offer = rekey_messages()
    i = net["i"].channel
    assert i._rekey is not None
    assert i._rekey.dk is not None
    answer = answer_for(net, offer)
    deliver(net, "i", answer)
    assert i._rekey is not None
    assert i._rekey.dk is None  # the ephemeral key did its only job
    assert i._rekey.ss is None
    r = net["r"].channel
    assert r._rekey is not None
    assert r._rekey.ss is not None  # kept until the finish arrives


def test_glass_box_flag_reaches_the_channel() -> None:
    i, r = session(i=initiator(gb=True), glass_box=True)
    assert i.glass_box
    assert r.glass_box
    i, r = session()
    assert not i.glass_box
    assert not r.glass_box


def test_rekey_state_is_dropped_on_close() -> None:
    net, _ = rekey_messages()
    i = net["i"].channel
    assert i._rekey is not None
    events = i.receive(net.raw("r", Close(reason=CloseReason.NORMAL)), 20.0)
    assert one(events, Closed).by_peer
    assert i._rekey is None
    net, _ = rekey_messages()
    net["i"].channel.close()
    assert net["i"].channel._rekey is None


def test_key_updates_repeat_every_ten_minutes() -> None:
    net = link()
    net.advance(T0 + KEY_UPDATE_SECONDS)
    net.advance(T0 + 2 * KEY_UPDATE_SECONDS)
    assert net["i"].channel._send.generation == 2
    assert net["r"].channel._recv.generation == 2


def test_timers_keep_running_after_a_rekey() -> None:
    net = link()
    i = net["i"].channel
    net.now = 100.0
    net.absorb("i", i.start_rekey(net.now))
    net.run()
    assert i.epoch == 1
    net.advance(100.0 + REKEY_SECONDS - 1)
    assert i.epoch == 1
    net.advance(100.0 + REKEY_SECONDS)
    assert i.epoch == 2


def test_initiator_can_finish_a_rekey_on_the_receive_side() -> None:
    """The writer may seal our rekey_switch before the peer's arrives; timers must still work."""
    net, offer = rekey_messages()
    i, r = net["i"].channel, net["r"].channel
    answer = answer_for(net, offer)
    queued = [e.message for e in i.receive(net.raw("r", answer), 20.0) if isinstance(e, Queue)]
    r_queue: list[Inner] = []
    for message in queued:  # finish and switch, both sealed before anything comes back
        events = r.receive(sent(i.seal_next(message, 20.0))[0], 20.0)
        r_queue += [e.message for e in events if isinstance(e, Queue)]
    assert i.rekey_in_progress  # our send side has switched, the receive side has not
    assert r_queue == [RekeySwitch()]
    i.receive(sent(r.seal_next(RekeySwitch(), 21.0))[0], 21.0)
    assert not i.rekey_in_progress
    assert i.epoch == 1
    later = 21.0 + REKEY_SECONDS
    i._last_received = i._last_sent = later - 1  # a live session (pings not modelled here)
    events = i.tick(later)
    assert RekeyOffer in [type(e.message) for e in events if isinstance(e, Queue)]
