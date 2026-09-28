"""Wire formats (DESIGN §6.3, §7.2, §7.3, §8.2)."""

import msgspec
import pytest
from hypothesis import given
from hypothesis import strategies as st

from qrp2p.core.crypto.identity import BUNDLE_LEN
from qrp2p.core.crypto.kdf import SHA256
from qrp2p.core.crypto.profiles import HYBRID_1, MAX_FRAME_BODY, PQ_CNSA_1, REAL_PROFILES
from qrp2p.core.errors import AdmitReason, CloseReason, FileCancelReason, ProtocolError
from qrp2p.core.wire import (
    AdmitBody,
    Chat,
    Close,
    Decision,
    FileCancel,
    FileChunk,
    FileDone,
    FileOffer,
    FileProgress,
    Frame,
    FrameReader,
    FrameType,
    Hello,
    Inner,
    KeyUpdate,
    Ping,
    Receipt,
    RekeyAnswer,
    RekeyOffer,
    Reply,
    SignedInner,
    Tag,
    Transcript,
    decode_inner,
    decode_profile_unsupported,
    encode_inner,
    frame_header,
    hello_prefix,
    inner_kind,
    parse_header,
    profile_bitmask,
    transcript_entry,
)
from qrp2p.lab.classical import LAB_CLASSICAL


def reason(excinfo: pytest.ExceptionInfo[ProtocolError]) -> CloseReason:
    return excinfo.value.reason


# --- Frames ------------------------------------------------------------------------------------


def test_frame_header_layout() -> None:
    assert frame_header(FrameType.RECORD, 0x0102) == b"\x00\x00\x01\x02\x20"
    assert Frame(FrameType.HELLO, b"ab").encode() == b"\x00\x00\x00\x02\x10ab"


def test_oversize_frame_rejected_before_allocation() -> None:
    reader = FrameReader()
    with pytest.raises(ProtocolError) as excinfo:
        reader.feed((MAX_FRAME_BODY + 1).to_bytes(4, "big") + bytes([FrameType.RECORD]))
    assert reason(excinfo) is CloseReason.OVERSIZE
    # v1 regression: a 25-byte message claiming a 4 GiB body must not make us wait for or
    # allocate that body.
    with pytest.raises(ProtocolError) as excinfo:
        FrameReader().feed(b"\xff\xff\xff\xff\x10" + b"\x00" * 20)
    assert reason(excinfo) is CloseReason.OVERSIZE


def test_maximum_frame_is_accepted() -> None:
    body = b"\x00" * MAX_FRAME_BODY
    assert FrameReader().feed(Frame(FrameType.RECORD, body).encode()) == [
        Frame(FrameType.RECORD, body)
    ]


def test_unknown_frame_type_is_schema_error() -> None:
    with pytest.raises(ProtocolError) as excinfo:
        parse_header(b"\x00\x00\x00\x00\x99")
    assert reason(excinfo) is CloseReason.SCHEMA_ERROR
    with pytest.raises(ProtocolError):
        parse_header(b"\x00\x00\x00")


def test_reader_needed_bounds_each_read() -> None:
    reader = FrameReader()
    assert reader.needed == 5
    reader.feed(b"\x00\x00\x00\x03")
    assert reader.needed == 1
    reader.feed(b"\x20")
    assert reader.needed == 3
    assert reader.feed(b"abc") == [Frame(FrameType.RECORD, b"abc")]
    assert reader.needed == 5


def test_empty_body_frame() -> None:
    assert FrameReader().feed(b"\x00\x00\x00\x00\x20") == [Frame(FrameType.RECORD, b"")]


frames = st.lists(
    st.builds(Frame, st.sampled_from(list(FrameType)), st.binary(max_size=64)), max_size=6
)


@given(frames, st.lists(st.integers(1, 40), min_size=1, max_size=20))
def test_reader_reassembles_any_split(items: list[Frame], cuts: list[int]) -> None:
    stream = b"".join(f.encode() for f in items)
    reader = FrameReader()
    out: list[Frame] = []
    pos = 0
    for cut in cuts * (len(stream) // max(sum(cuts), 1) + 1):
        out += reader.feed(stream[pos : pos + cut])
        pos += cut
        if pos >= len(stream):
            break
    out += reader.feed(stream[pos:])
    assert out == items


@given(st.binary(max_size=200))
def test_reader_on_garbage_yields_frames_or_named_error(data: bytes) -> None:
    try:
        FrameReader().feed(data)
    except ProtocolError as e:
        assert e.reason in {CloseReason.OVERSIZE, CloseReason.SCHEMA_ERROR}


# --- Handshake messages ------------------------------------------------------------------------


def hello(profile=HYBRID_1, gb: bool = False) -> Hello:  # noqa: ANN001
    return Hello(profile.id, gb, b"\x01" * 32, b"\x02" * profile.ek_len)


@pytest.mark.parametrize("profile", [*REAL_PROFILES, LAB_CLASSICAL])
def test_hello_round_trip_and_size(profile) -> None:  # noqa: ANN001
    for gb in (False, True):
        body = hello(profile, gb).encode()
        assert len(body) == profile.hello_body_len
        assert hello_prefix(body) == (profile.id, gb)
        assert Hello.decode(body, profile) == hello(profile, gb)


@pytest.mark.parametrize(
    ("mutate", "detail"),
    [
        (lambda b: b[:2], "truncated"),
        (lambda b: b"\x01" + b[1:], "version"),
        (lambda b: b[:2] + b"\x02" + b[3:], "reserved"),
        (lambda b: b[:2] + b"\x81" + b[3:], "reserved"),
    ],
)
def test_hello_prefix_rejections(mutate, detail: str) -> None:  # noqa: ANN001
    with pytest.raises(ProtocolError) as excinfo:
        hello_prefix(mutate(hello().encode()))
    assert reason(excinfo) is CloseReason.SCHEMA_ERROR
    assert detail in excinfo.value.detail


def test_hello_size_and_profile_must_match() -> None:
    body = hello().encode()
    for bad in (body + b"\x00", body[:-1]):
        with pytest.raises(ProtocolError) as excinfo:
            Hello.decode(bad, HYBRID_1)
        assert reason(excinfo) is CloseReason.SCHEMA_ERROR
    with pytest.raises(ProtocolError):
        Hello.decode(body, PQ_CNSA_1)


@pytest.mark.parametrize("profile", REAL_PROFILES)
def test_reply_and_signed_inner_split_exactly(profile) -> None:  # noqa: ANN001
    inner = SignedInner(b"i" * BUNDLE_LEN, b"s" * profile.sig_len, b"f" * profile.hash_len)
    assert SignedInner.decode(inner.encode(), profile) == inner
    sealed = b"x" * (profile.signed_inner_len + 16)
    reply = Reply(b"n" * 32, b"c" * profile.ct_len, sealed)
    body = reply.encode()
    assert len(body) == profile.reply_body_len
    assert Reply.decode(body, profile) == reply
    assert reply.transcript_value == b"n" * 32 + b"c" * profile.ct_len
    with pytest.raises(ProtocolError):
        Reply.decode(body[:-1], profile)
    with pytest.raises(ProtocolError):
        SignedInner.decode(inner.encode() + b"\x00", profile)


def test_admit_body_rules() -> None:
    ok = AdmitBody(Decision.ACCEPT, glass_box=True, reason=AdmitReason.NONE)
    assert ok.encode() == b"\x00\x01\x00"
    assert AdmitBody.decode(b"\x00\x01\x00") == ok
    assert AdmitBody.decode(b"\x01\x00\x02") == AdmitBody(
        Decision.REJECT, glass_box=False, reason=AdmitReason.PROFILE_POLICY
    )
    for bad in (
        b"\x00\x00\x01",  # accept with a reason
        b"\x01\x00\x00",  # reject without a reason
        b"\x01\x01\x01",  # glass-box reject
        b"\x02\x00\x00",  # unknown decision
        b"\x01\x00\x09",  # unknown reason
        b"\x00\x02\x00",  # reserved flag
        b"\x00\x00",
    ):
        with pytest.raises(ProtocolError) as excinfo:
            AdmitBody.decode(bad)
        assert reason(excinfo) is CloseReason.SCHEMA_ERROR


def test_profile_unsupported_bitmask() -> None:
    assert profile_bitmask(REAL_PROFILES) == 0b11
    assert profile_bitmask([HYBRID_1, LAB_CLASSICAL]) == 0b01
    assert decode_profile_unsupported(b"\x03") == 3
    with pytest.raises(ProtocolError):
        decode_profile_unsupported(b"")


# --- Transcript --------------------------------------------------------------------------------


def test_transcript_entries_are_tagged_and_length_prefixed() -> None:
    assert transcript_entry(Tag.ID_R, b"abc") == b"\x21\x00\x00\x00\x03abc"
    tr = Transcript(SHA256)
    tr.add(Tag.HELLO, b"h")
    tr.add(Tag.REPLY, b"")
    assert bytes(tr) == b"\x10\x00\x00\x00\x01h\x11\x00\x00\x00\x00"
    assert tr.digest() == SHA256.digest(bytes(tr))


def test_transcript_entries_cannot_be_shifted() -> None:
    # Moving a byte from one value to the next changes the encoding (unambiguous framing).
    a, b = Transcript(SHA256), Transcript(SHA256)
    a.add(Tag.ID_R, b"ab")
    a.add(Tag.SIG_R, b"c")
    b.add(Tag.ID_R, b"a")
    b.add(Tag.SIG_R, b"bc")
    assert a.digest() != b.digest()


# --- Inner messages ----------------------------------------------------------------------------

ID = b"\x07" * 16

inners = st.one_of(
    st.builds(Chat, id=st.just(ID), text=st.text(max_size=200)),
    st.builds(Receipt, id=st.just(ID)),
    st.builds(
        FileOffer,
        file_id=st.just(ID),
        name=st.text(max_size=60),
        size=st.integers(0, 2**64 - 1),
        media_type=st.text(max_size=30),
    ),
    st.builds(FileChunk, file_id=st.just(ID), data=st.binary(max_size=300)),
    st.builds(FileProgress, file_id=st.just(ID), received=st.integers(0, 2**64 - 1)),
    st.builds(FileDone, file_id=st.just(ID), sha256=st.just(b"\x00" * 32)),
    st.builds(FileCancel, file_id=st.just(ID), reason=st.sampled_from(list(FileCancelReason))),
    st.builds(RekeyOffer, ek=st.binary(max_size=64)),
    st.builds(RekeyAnswer, ct=st.binary(max_size=64), sig=st.binary(max_size=64)),
    st.just(KeyUpdate()),
    st.just(Ping()),
    st.builds(Close, reason=st.sampled_from(list(CloseReason))),
)


@given(inners)
def test_inner_round_trip(message: Inner) -> None:
    assert decode_inner(encode_inner(message)) == message


def test_inner_kind_names_match_the_spec() -> None:
    assert inner_kind(Chat(id=ID, text="")) == "chat"
    assert inner_kind(KeyUpdate()) == "key_update"
    assert msgspec.msgpack.decode(encode_inner(Ping())) == {"kind": "ping"}


def schema_error(obj: object) -> None:
    with pytest.raises(ProtocolError) as excinfo:
        decode_inner(msgspec.msgpack.encode(obj))
    assert reason(excinfo) is CloseReason.SCHEMA_ERROR


@pytest.mark.parametrize(
    "obj",
    [
        {"kind": "nope"},
        {"kind": "chat", "id": ID, "text": "x", "sender": "alice"},  # v1 regression: no sender
        {"kind": "chat", "id": ID},
        {"kind": "chat", "id": ID[:15], "text": "x"},
        {"kind": "chat", "id": ID, "text": "é" * 8001},  # 16,002 bytes
        {"kind": "chat", "id": "x" * 16, "text": "x"},
        {"kind": "file_offer", "file_id": ID, "name": "n" * 256, "size": 1, "media_type": ""},
        {"kind": "file_offer", "file_id": ID, "name": "n", "size": -1, "media_type": ""},
        {"kind": "file_offer", "file_id": ID, "name": "n", "size": 1, "media_type": "m" * 128},
        {"kind": "file_chunk", "file_id": ID, "data": b"\x00" * 16_001},
        {"kind": "close", "reason": 99},
        {"kind": "close", "reason": True},
        {"kind": "file_cancel", "file_id": ID, "reason": 5},
        {"kind": "ping", "extra": 1},
        [1, 2, 3],
        "chat",
    ],
)
def test_inner_schema_violations(obj: object) -> None:
    schema_error(obj)


def test_inner_malformed_and_oversize() -> None:
    for data in (b"", b"\xc1", encode_inner(Ping()) + b"\x00", b"\x00" * 16_385):
        with pytest.raises(ProtocolError) as excinfo:
            decode_inner(data)
        assert reason(excinfo) is CloseReason.SCHEMA_ERROR


def test_text_limit_counts_bytes_not_characters() -> None:
    assert decode_inner(encode_inner(Chat(id=ID, text="é" * 8000))) == Chat(id=ID, text="é" * 8000)
    with pytest.raises(ValueError, match="16000 bytes"):
        Chat(id=ID, text="é" * 8001)


def test_encode_refuses_oversize_plaintext() -> None:
    with pytest.raises(ValueError, match="plaintext limit"):
        encode_inner(RekeyOffer(ek=b"\x00" * 16_384))


@given(st.binary(max_size=300))
def test_inner_garbage_gives_only_schema_error(data: bytes) -> None:
    try:
        decode_inner(data)
    except ProtocolError as e:
        assert e.reason is CloseReason.SCHEMA_ERROR


# --- boundaries (mutation testing found these gaps) ----------------------------------------------


def test_exact_limits_are_accepted() -> None:
    assert hello_prefix(b"\x02\x01\x01") == (1, True)
    top = FileProgress(file_id=ID, received=2**64 - 1)
    assert decode_inner(encode_inner(top)) == top
    with pytest.raises(ValueError, match="u64"):
        FileProgress(file_id=ID, received=2**64)
    offer = FileOffer(file_id=ID, name="n" * 255, size=2**64 - 1, media_type="m" * 127)
    assert decode_inner(encode_inner(offer)) == offer
    assert profile_bitmask([]) == 0
    assert profile_bitmask([LAB_CLASSICAL]) == 0


@pytest.mark.parametrize(
    "call",
    [
        lambda: parse_header(b"\x00\x00\x00"),
        lambda: Hello.decode(hello().encode(), PQ_CNSA_1),
        lambda: SignedInner.decode(b"", HYBRID_1),
        lambda: decode_profile_unsupported(b"\x01\x02"),
        lambda: Reply.decode(b"", HYBRID_1),
    ],
)
def test_malformed_handshake_parts_are_schema_errors(call) -> None:  # noqa: ANN001
    with pytest.raises(ProtocolError) as excinfo:
        call()
    assert reason(excinfo) is CloseReason.SCHEMA_ERROR


def test_inner_of_exactly_the_plaintext_limit_decodes() -> None:
    pad = 16_384 - len(encode_inner(RekeyOffer(ek=b"\x00" * 300)))
    biggest = RekeyOffer(ek=b"\x00" * (300 + pad))
    data = encode_inner(biggest)
    assert len(data) == 16_384
    assert decode_inner(data) == biggest
