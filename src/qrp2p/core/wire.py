"""Wire formats: frames, handshake messages, transcript entries and Inner messages.

```text
frame     = length:u32 ‖ type:u8 ‖ body[length]                                   (DESIGN §6.3)
Hello     = version:u8 (=0x02) ‖ profile:u8 ‖ flags:u8 ‖ nonce_I[32] ‖ ek_I          (DESIGN §7.2)
Reply     = nonce_R[32] ‖ ct ‖ AEAD(Keys(hs_R), seq=0, IdR ‖ SigR ‖ FinR)
Confirm   = AEAD(Keys(hs_I), seq=0, IdI ‖ SigI ‖ FinI)
Admit     = AEAD(Keys(hs_R), seq=1, AdmitBody ‖ FinA)
AdmitBody = decision:u8 ‖ flags:u8 ‖ reason:u8
T(tag, v) = tag:u8 ‖ u32(len(v)) ‖ v                                              (DESIGN §7.3)
```

Handshake messages have fixed layouts and exact sizes per profile; their bytes are hashed, signed
and authenticated, so they are never built with a serialisation library. Inner messages inside
records (DESIGN §8.2) are MessagePack via ``msgspec``, decoded with a strict schema; they are never
hashed or signed.

Everything decoded here is peer data: sizes are checked before anything is allocated or parsed,
and every failure is a :class:`~qrp2p.core.errors.ProtocolError` with a named reason.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Annotated, Final, Self

import msgspec
from msgspec import Meta, Struct

from qrp2p.core.crypto.aead import TAG_LEN
from qrp2p.core.crypto.identity import BUNDLE_LEN
from qrp2p.core.crypto.kdf import HashFunction
from qrp2p.core.crypto.profiles import (
    FRAME_HEADER_LEN,
    MAX_FRAME_BODY,
    MAX_RECORD_PLAINTEXT,
    NONCE_LEN,
    Profile,
    ProfileId,
)
from qrp2p.core.errors import AdmitReason, CloseReason, FileCancelReason, ProtocolError

HELLO_VERSION: Final = 0x02
FLAG_GB_REQUEST: Final = 0x01
"""Hello ``flags`` bit 0; all other bits MUST be 0."""
FLAG_GLASS_BOX: Final = 0x01
"""AdmitBody ``flags`` bit 0; all other bits MUST be 0."""
ADMIT_BODY_LEN: Final = 3
MAX_RECORD_BODY: Final = MAX_RECORD_PLAINTEXT + TAG_LEN
"""A record's AEAD ciphertext is at most 16,384 + 16 bytes (DESIGN §8.1)."""
_MAX_U32: Final = 0xFFFF_FFFF
_HELLO_PREFIX_LEN: Final = 3

PROFILE_BITS: Final[dict[int, int]] = {ProfileId.HYBRID_1: 0x01, ProfileId.PQ_CNSA_1: 0x02}
"""Bitmask bits for ``ProfileUnsupported`` and the mDNS ``pf`` field (DESIGN §6.1). Lab-only
profiles have no bit."""


_SCHEMA: Final = CloseReason.SCHEMA_ERROR


# --- Frames -----------------------------------------------------------------------------------


@unique
class FrameType(IntEnum):
    """Frame types (DESIGN §6.3)."""

    HELLO = 0x10
    REPLY = 0x11
    CONFIRM = 0x12
    ADMIT = 0x13
    PROFILE_UNSUPPORTED = 0x1F
    RECORD = 0x20


def frame_header(frame_type: FrameType, length: int) -> bytes:
    """Return ``length:u32 ‖ type:u8``, the header that is also the AEAD associated data."""
    if not 0 <= length <= MAX_FRAME_BODY:
        msg = "frame body too large"
        raise ValueError(msg)
    return length.to_bytes(4, "big") + bytes([frame_type])


@dataclass(frozen=True, slots=True)
class Frame:
    """One frame: its type and body."""

    type: FrameType
    body: bytes

    @property
    def header(self) -> bytes:
        """The 5-byte header."""
        return frame_header(self.type, len(self.body))

    def encode(self) -> bytes:
        """Return ``header ‖ body``."""
        return self.header + self.body


def parse_header(header: bytes) -> tuple[FrameType, int]:
    """Parse a frame header and check the length **before** the body is read.

    Raises:
        ProtocolError: ``oversize`` for a body longer than 16,448 bytes; ``schema_error`` for an
            unknown frame type or a header that is not 5 bytes.
    """
    if len(header) != FRAME_HEADER_LEN:
        raise ProtocolError(_SCHEMA, "frame header must be 5 bytes")
    length = int.from_bytes(header[:4], "big")
    if length > MAX_FRAME_BODY:
        raise ProtocolError(CloseReason.OVERSIZE, "frame body exceeds the maximum")
    try:
        frame_type = FrameType(header[4])
    except ValueError:
        raise ProtocolError(_SCHEMA, "unknown frame type") from None
    return frame_type, length


class FrameReader:
    """Splits a byte stream into frames. Sans-I/O: the transport feeds it whatever it reads.

    It never holds more than one header and one maximum-size body, and it rejects an oversize or
    unknown frame as soon as its header is complete, before any body byte is kept.
    """

    __slots__ = ("_buffer", "_pending")

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._pending: tuple[FrameType, int] | None = None

    @property
    def needed(self) -> int:
        """How many more bytes complete the current header or body (for bounded reads)."""
        if self._pending is None:
            return FRAME_HEADER_LEN - len(self._buffer)
        return self._pending[1] - len(self._buffer)

    def feed(self, data: bytes) -> list[Frame]:
        """Consume ``data``; return every frame it completes.

        Raises:
            ProtocolError: As :func:`parse_header`. The reader is then unusable.
        """
        frames: list[Frame] = []
        view = memoryview(data)
        while view:
            take = min(self.needed, len(view))
            self._buffer += view[:take]
            view = view[take:]
            if self.needed:
                continue
            if self._pending is None:
                self._pending = parse_header(bytes(self._buffer))
                self._buffer.clear()
                if self._pending[1]:
                    continue
            frame_type, _ = self._pending
            frames.append(Frame(frame_type, bytes(self._buffer)))
            self._buffer.clear()
            self._pending = None
        return frames


# --- Handshake messages -----------------------------------------------------------------------


def hello_prefix(body: bytes) -> tuple[int, bool]:
    """Check a Hello's version and flags; return ``(profile_id, gb_request)``.

    The responder calls this first, looks the profile up among those it serves, and only then
    checks the exact size with :meth:`Hello.decode`.

    Raises:
        ProtocolError: ``schema_error`` for a truncated Hello, an unknown version or non-zero
            reserved flag bits.
    """
    if len(body) < _HELLO_PREFIX_LEN:
        raise ProtocolError(_SCHEMA, "Hello is truncated")
    version, profile_id, flags = body[0], body[1], body[2]
    if version != HELLO_VERSION:
        raise ProtocolError(_SCHEMA, "unknown Hello version")
    if flags & ~FLAG_GB_REQUEST:
        raise ProtocolError(_SCHEMA, "reserved Hello flag bits are set")
    return profile_id, bool(flags & FLAG_GB_REQUEST)


@dataclass(frozen=True, slots=True)
class Hello:
    """Message 1, plaintext."""

    profile_id: int
    gb_request: bool
    nonce: bytes
    ek: bytes

    def encode(self) -> bytes:
        """Return the Hello body."""
        flags = FLAG_GB_REQUEST if self.gb_request else 0
        return bytes([HELLO_VERSION, self.profile_id, flags]) + self.nonce + self.ek

    @classmethod
    def decode(cls, body: bytes, profile: Profile) -> Self:
        """Parse a Hello for ``profile``, the profile its prefix names.

        Raises:
            ProtocolError: ``schema_error`` as :func:`hello_prefix`, for a profile byte that is
                not ``profile``, or for a body that is not exactly ``profile.hello_body_len``.
        """
        profile_id, gb_request = hello_prefix(body)
        if profile_id != profile.id:
            raise ProtocolError(_SCHEMA, "Hello names a different profile")
        if len(body) != profile.hello_body_len:
            raise ProtocolError(_SCHEMA, "Hello has the wrong size for its profile")
        nonce_end = _HELLO_PREFIX_LEN + NONCE_LEN
        return cls(profile_id, gb_request, body[_HELLO_PREFIX_LEN:nonce_end], body[nonce_end:])


@dataclass(frozen=True, slots=True)
class Reply:
    """Message 2: ``nonce_R ‖ ct`` in plaintext, then the sealed ReplyInner."""

    nonce: bytes
    ct: bytes
    sealed: bytes

    def encode(self) -> bytes:
        """Return the Reply body."""
        return self.nonce + self.ct + self.sealed

    @classmethod
    def decode(cls, body: bytes, profile: Profile) -> Self:
        """Split a Reply body.

        Raises:
            ProtocolError: ``schema_error`` unless the body is exactly ``profile.reply_body_len``.
        """
        if len(body) != profile.reply_body_len:
            raise ProtocolError(_SCHEMA, "Reply has the wrong size for the profile")
        ct_end = NONCE_LEN + profile.ct_len
        return cls(body[:NONCE_LEN], body[NONCE_LEN:ct_end], body[ct_end:])

    @property
    def transcript_value(self) -> bytes:
        """``nonce_R ‖ ct``, the value of transcript entry ``0x11``."""
        return self.nonce + self.ct


@dataclass(frozen=True, slots=True)
class SignedInner:
    """ReplyInner or ConfirmInner: ``Id[4577] ‖ Sig[sig_len] ‖ Fin[Hlen]``."""

    identity: bytes
    signature: bytes
    finished: bytes

    def encode(self) -> bytes:
        """Return the plaintext to seal."""
        return self.identity + self.signature + self.finished

    @classmethod
    def decode(cls, plaintext: bytes, profile: Profile) -> Self:
        """Split a decrypted ReplyInner or ConfirmInner.

        Raises:
            ProtocolError: ``schema_error`` unless the plaintext has exactly the profile's size.
        """
        if len(plaintext) != profile.signed_inner_len:
            raise ProtocolError(_SCHEMA, "signed handshake message has the wrong size")
        sig_end = BUNDLE_LEN + profile.sig_len
        return cls(plaintext[:BUNDLE_LEN], plaintext[BUNDLE_LEN:sig_end], plaintext[sig_end:])


def check_sealed_len(body: bytes, expected: int) -> None:
    """Check the exact size of a Confirm or Admit body.

    Raises:
        ProtocolError: ``schema_error`` for any other size.
    """
    if len(body) != expected:
        raise ProtocolError(_SCHEMA, "handshake message has the wrong size for the profile")


@unique
class Decision(IntEnum):
    """``AdmitBody.decision``."""

    ACCEPT = 0
    REJECT = 1


@dataclass(frozen=True, slots=True)
class AdmitBody:
    """The responder's admission decision (DESIGN §7.2, §7.6).

    An accept carries reason ``none``; a reject carries a reason other than ``none`` and never
    sets ``glass_box``.
    """

    decision: Decision
    glass_box: bool
    reason: AdmitReason

    def __post_init__(self) -> None:
        if self.decision is Decision.ACCEPT and self.reason is not AdmitReason.NONE:
            raise ProtocolError(_SCHEMA, "an accept must carry reason none")
        if self.decision is Decision.REJECT and (self.reason is AdmitReason.NONE or self.glass_box):
            raise ProtocolError(_SCHEMA, "a reject needs a reason and cannot be glass-box")

    def encode(self) -> bytes:
        """Return the 3-byte AdmitBody."""
        return bytes([self.decision, FLAG_GLASS_BOX if self.glass_box else 0, self.reason])

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Parse an AdmitBody.

        Raises:
            ProtocolError: ``schema_error`` for a wrong size, an unknown decision or reason,
                reserved flag bits, or a combination that the rules above forbid.
        """
        if len(data) != ADMIT_BODY_LEN:
            raise ProtocolError(_SCHEMA, "AdmitBody must be 3 bytes")
        decision, flags, reason = data
        if flags & ~FLAG_GLASS_BOX:
            raise ProtocolError(_SCHEMA, "reserved AdmitBody flag bits are set")
        try:
            return cls(Decision(decision), bool(flags & FLAG_GLASS_BOX), AdmitReason(reason))
        except ValueError:
            raise ProtocolError(_SCHEMA, "unknown admission decision or reason") from None


def profile_bitmask(profiles: Iterable[Profile]) -> int:
    """The ``supported`` bitmask of ``ProfileUnsupported`` for the real profiles in ``profiles``."""
    mask = 0
    for profile in profiles:
        mask |= PROFILE_BITS.get(profile.id, 0)
    return mask


def decode_profile_unsupported(body: bytes) -> int:
    """Parse a ``ProfileUnsupported`` body; return its bitmask (an unauthenticated hint).

    Raises:
        ProtocolError: ``schema_error`` unless the body is exactly one byte.
    """
    if len(body) != 1:
        raise ProtocolError(_SCHEMA, "ProfileUnsupported must be 1 byte")
    return body[0]


# --- Transcript -------------------------------------------------------------------------------


@unique
class Tag(IntEnum):
    """Transcript entry tags (DESIGN §7.3, §8.4)."""

    HELLO = 0x10
    REPLY = 0x11
    ID_R = 0x21
    SIG_R = 0x22
    FIN_R = 0x23
    ID_I = 0x31
    SIG_I = 0x32
    FIN_I = 0x33
    ADMIT_BODY = 0x41
    FIN_A = 0x42
    REKEY_EK = 0x51
    REKEY_CT = 0x52
    REKEY_SIG_R = 0x53
    REKEY_SIG_I = 0x54


def transcript_entry(tag: Tag, value: bytes) -> bytes:
    """``T(tag, value) = tag:u8 ‖ u32(len(value)) ‖ value``."""
    if len(value) > _MAX_U32:
        msg = "transcript value too long"
        raise ValueError(msg)
    return bytes([tag]) + len(value).to_bytes(4, "big") + value


class Transcript:
    """The running transcript ``TR``: exact bytes of tagged entries, hashed on demand.

    Args:
        hash_function: The profile hash ``H``.
    """

    __slots__ = ("_data", "_hash")

    def __init__(self, hash_function: HashFunction) -> None:
        self._hash = hash_function
        self._data = bytearray()

    def add(self, tag: Tag, value: bytes) -> None:
        """Append ``T(tag, value)``."""
        self._data += transcript_entry(tag, value)

    def digest(self) -> bytes:
        """``H(TR)`` over everything added so far."""
        return self._hash.digest(bytes(self._data))

    def __bytes__(self) -> bytes:
        return bytes(self._data)


# --- Inner messages (DESIGN §8.2) -------------------------------------------------------------

MAX_TEXT_BYTES: Final = 16_000
MAX_CHUNK_BYTES: Final = 16_000
MAX_NAME_BYTES: Final = 255
MAX_MEDIA_TYPE_BYTES: Final = 127
MAX_U64: Final = 2**64 - 1

type Id16 = Annotated[bytes, Meta(min_length=16, max_length=16)]
type Sha256 = Annotated[bytes, Meta(min_length=32, max_length=32)]
type U64 = Annotated[int, Meta(ge=0)]  # msgspec cannot express the upper bound; see _check_u64
type KeyBlob = Annotated[bytes, Meta(max_length=MAX_RECORD_PLAINTEXT)]
"""Rekey keys, ciphertexts and signatures; the record layer checks their exact size."""


def _check_utf8_len(text: str, limit: int, what: str) -> None:
    if len(text.encode("utf-8", "surrogatepass")) > limit:
        msg = f"{what} exceeds {limit} bytes"
        raise ValueError(msg)


def _check_u64(value: int) -> None:
    if value > MAX_U64:
        msg = "value exceeds u64"
        raise ValueError(msg)


class _Inner(Struct, frozen=True, forbid_unknown_fields=True, tag_field="kind"):
    pass


class Chat(_Inner, tag="chat", frozen=True):
    """A chat message; ``text`` is at most 16,000 bytes of UTF-8."""

    id: Id16
    text: str

    def __post_init__(self) -> None:
        _check_utf8_len(self.text, MAX_TEXT_BYTES, "text")


class Receipt(_Inner, tag="receipt", frozen=True):
    """Delivery receipt for the chat with ``id``."""

    id: Id16


class FileOffer(_Inner, tag="file_offer", frozen=True):
    """Offer of a file; the receiver sanitises ``name`` (DESIGN §9)."""

    file_id: Id16
    name: str
    size: U64
    media_type: str

    def __post_init__(self) -> None:
        _check_utf8_len(self.name, MAX_NAME_BYTES, "name")
        _check_utf8_len(self.media_type, MAX_MEDIA_TYPE_BYTES, "media type")
        _check_u64(self.size)


class FileAccept(_Inner, tag="file_accept", frozen=True):
    """The receiver accepts a file offer."""

    file_id: Id16


class FileDecline(_Inner, tag="file_decline", frozen=True):
    """The receiver declines a file offer."""

    file_id: Id16


class FileChunk(_Inner, tag="file_chunk", frozen=True):
    """At most 16,000 bytes of file data."""

    file_id: Id16
    data: Annotated[bytes, Meta(max_length=MAX_CHUNK_BYTES)]


class FileProgress(_Inner, tag="file_progress", frozen=True):
    """Bytes received so far."""

    file_id: Id16
    received: U64

    def __post_init__(self) -> None:
        _check_u64(self.received)


class FileDone(_Inner, tag="file_done", frozen=True):
    """End of file with its SHA-256."""

    file_id: Id16
    sha256: Sha256


class FileCancel(_Inner, tag="file_cancel", frozen=True):
    """Cancel a transfer."""

    file_id: Id16
    reason: FileCancelReason


class KeyUpdate(_Inner, tag="key_update", frozen=True):
    """The sender's last record under its current traffic secret (DESIGN §8.4)."""


class RekeyOffer(_Inner, tag="rekey_offer", frozen=True):
    """PQ rekey step 1 (initiator): a fresh encapsulation key."""

    ek: KeyBlob


class RekeyAnswer(_Inner, tag="rekey_answer", frozen=True):
    """PQ rekey step 2 (responder): ciphertext and signature."""

    ct: KeyBlob
    sig: KeyBlob


class RekeyFinish(_Inner, tag="rekey_finish", frozen=True):
    """PQ rekey step 3 (initiator): signature."""

    sig: KeyBlob


class RekeySwitch(_Inner, tag="rekey_switch", frozen=True):
    """The sender's last record under its pre-rekey send key."""


class Ping(_Inner, tag="ping", frozen=True):
    """Liveness probe."""


class Pong(_Inner, tag="pong", frozen=True):
    """Answer to a ping."""


class Close(_Inner, tag="close", frozen=True):
    """Orderly close with a named reason."""

    reason: CloseReason


type Inner = (
    Chat
    | Receipt
    | FileOffer
    | FileAccept
    | FileDecline
    | FileChunk
    | FileProgress
    | FileDone
    | FileCancel
    | KeyUpdate
    | RekeyOffer
    | RekeyAnswer
    | RekeyFinish
    | RekeySwitch
    | Ping
    | Pong
    | Close
)
"""Every message a record can carry. The sender is always the session's peer."""

_ENCODER: Final = msgspec.msgpack.Encoder()
_DECODER: Final = msgspec.msgpack.Decoder(Inner)


def inner_kind(message: Inner) -> str:
    """The message's ``kind`` tag, e.g. ``"chat"``."""
    return type(message).__struct_config__.tag  # pyright: ignore[reportReturnType]


def encode_inner(message: Inner) -> bytes:
    """Encode an Inner message.

    Raises:
        ValueError: The encoding exceeds the 16,384-byte record plaintext limit.
    """
    data = _ENCODER.encode(message)
    if len(data) > MAX_RECORD_PLAINTEXT:
        msg = "Inner message exceeds the record plaintext limit"
        raise ValueError(msg)
    return data


def decode_inner(data: bytes) -> Inner:
    """Decode an Inner message from a record plaintext.

    Raises:
        ProtocolError: ``schema_error`` for malformed MessagePack, an unknown kind, extra or
            missing fields, wrong types or a limit violation.
    """
    if len(data) > MAX_RECORD_PLAINTEXT:
        raise ProtocolError(_SCHEMA, "record plaintext exceeds the limit")
    try:
        return _DECODER.decode(data)
    except msgspec.DecodeError:
        raise ProtocolError(_SCHEMA, "Inner message does not match the schema") from None
