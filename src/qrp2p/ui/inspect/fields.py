"""A captured frame as rows of named byte ranges, each with its explanation (UI_DESIGN §7.3).

The core's dissector gives body-relative ranges; here they become rows with both offsets, the
header's two fields, a value where one can be read off the bytes, the origin of the bytes, and a
one-line explanation with its specification section. A frame that is not the size its type
requires stays one unsplit range: it is never prettified into validity.

For an exposed session (glass-box or lab), a sealed part also gets the rows of its plaintext:
what was inside, from the values the session revealed. Those rows point into the plaintext, not
the frame, and say so.
"""

from dataclasses import dataclass
from typing import Final

from msgspec import Struct

from qrp2p.core.trace import Direction, Field, FrameTraced, RecordTraced
from qrp2p.core.wire import FrameType, decode_inner
from qrp2p.ui.inspect.model import ProfileFacts, RecordOpened
from qrp2p.ui.text import display_text

HEADER_LEN: Final = 5
BUNDLE_LEN: Final = 4577
"""An identity bundle's size (DESIGN §5.1)."""

WIRE: Final = "Captured wire bytes"
DECRYPTED: Final = "Decrypted with this session's revealed keys"
LOCAL: Final = "Local protocol state"

FRAME_NAMES: Final[dict[FrameType, str]] = {
    FrameType.HELLO: "Hello",
    FrameType.REPLY: "Reply",
    FrameType.CONFIRM: "Confirm",
    FrameType.ADMIT: "Admit",
    FrameType.PROFILE_UNSUPPORTED: "ProfileUnsupported",
    FrameType.RECORD: "Record",
}
PROFILE_IDS: Final[dict[int, str]] = {0x01: "HYBRID-1", 0x02: "PQ-CNSA-1", 0x7F: "LAB-CLASSICAL"}
_PROFILE_BITS: Final = ((0x01, "HYBRID-1"), (0x02, "PQ-CNSA-1"))


@dataclass(frozen=True, slots=True)
class Explanation:
    """What a field is, in one or two sentences, and where the specification defines it."""

    text: str
    section: str


EXPLANATIONS: Final[dict[str, Explanation]] = {
    "length": Explanation(
        "Body length, u32 big-endian. Checked against the 16,448-byte maximum before anything "
        "is allocated. The 5-byte header is also the AEAD associated data.",
        "6.3",
    ),
    "type": Explanation(
        "Frame type: 0x10 Hello, 0x11 Reply, 0x12 Confirm, 0x13 Admit, 0x1F ProfileUnsupported, "
        "0x20 Record.",
        "6.3",
    ),
    "version": Explanation(
        "Hello version, 0x02 for this protocol. Any other value closes the connection silently.",
        "7.2",
    ),
    "profile": Explanation(
        "The profile the initiator offers. It fixes every algorithm of the session, and it is in "
        "the transcript, so changing it in transit breaks the handshake.",
        "4",
    ),
    "flags": Explanation(
        "Bit 0 asks for a glass-box session (gb_request); the other bits must be 0. It is in the "
        "transcript: it cannot be added or stripped unnoticed.",
        "11.3",
    ),
    "nonce_I": Explanation(
        "32 random bytes from the initiator. They make every handshake's transcript unique.",
        "7.2",
    ),
    "ek_I": Explanation(
        "The initiator's ephemeral KEM public key, for this handshake only. The responder "
        "encapsulates a fresh shared secret to it.",
        "7.2",
    ),
    "pkM": Explanation(
        "X-Wing's post-quantum half: an ML-KEM-768 encapsulation key. Checked against the FIPS 203 "
        "modulus rule on import.",
        "4.2",
    ),
    "pkX": Explanation("X-Wing's classical half: an X25519 public key.", "4.2"),
    "nonce_R": Explanation("32 random bytes from the responder.", "7.2"),
    "ct": Explanation(
        "The KEM ciphertext, encapsulated to ek_I. Only the holder of the matching private key "
        "recovers the shared secret ss.",
        "7.2",
    ),
    "ctM": Explanation("X-Wing's post-quantum half: an ML-KEM-768 ciphertext.", "4.2"),
    "ctX": Explanation(
        "X-Wing's classical half: an ephemeral X25519 public key. It also enters the combiner "
        "that makes ss.",
        "4.2",
    ),
    "ReplyInner (sealed)": Explanation(
        "Encrypted under the responder's handshake keys (hs_R, sequence 0): its identity bundle, "
        "its signature over the transcript and its Finished MAC.",
        "7.2",
    ),
    "ConfirmInner (sealed)": Explanation(
        "Encrypted under hs_I (sequence 0): the initiator's identity, signature and Finished. "
        "The initiator sends it only after the responder proved the pinned identity.",
        "7.5",
    ),
    "AdmitInner (sealed)": Explanation(
        "Encrypted under hs_R (sequence 1): the admission decision, the glass-box flag, a reason, "
        "and Finished over the whole transcript.",
        "7.6",
    ),
    "record (sealed)": Explanation(
        "An application record, encrypted under the current traffic key. Its nonce is the IV XOR "
        "the sequence number, which is never sent: a replayed or reordered record cannot open.",
        "8.1",
    ),
    "ciphertext": Explanation(
        "The encrypted plaintext; it has the plaintext's length.",
        "8.1",
    ),
    "tag": Explanation(
        "The 16-byte authentication tag. Any change to the header, ciphertext or tag makes "
        "opening fail with decrypt_failed.",
        "8.1",
    ),
    "supported": Explanation(
        "An unauthenticated hint: the profiles the responder serves (bit 0 HYBRID-1, bit 1 "
        "PQ-CNSA-1). It must never change a contact's setting.",
        "7.7",
    ),
    "body": Explanation(
        "Not split: the body does not have the size its type and profile require.",
        "7.2",
    ),
    "Id": Explanation(
        "The sender's identity bundle: its Ed25519, ML-DSA-65 and ML-DSA-87 public keys "
        "(4,577 bytes). Its hash is the peer ID behind the short ID.",
        "5.1",
    ),
    "Sig": Explanation(
        "The sender's signature over the transcript hash so far, with its role "
        "(HybridSign: both halves must verify).",
        "4.4",
    ),
    "Fin": Explanation(
        "The Finished MAC: HMAC under the finished key over the transcript hash so far. It proves "
        "possession of the handshake secret.",
        "7.4",
    ),
    "decision": Explanation("0 accept, 1 reject.", "7.2"),
    "admit flags": Explanation("Bit 0: the session is glass-box. Only set if asked.", "7.2"),
    "reason": Explanation("Why a reject: declined, profile_policy, timeout or busy.", "Appendix B"),
    "FinA": Explanation(
        "Finished over the transcript including the decision, so the decision cannot be changed.",
        "7.4",
    ),
    "Inner": Explanation(
        "The record's plaintext: one Inner message, MessagePack with a strict schema. The sender "
        "is always the session's peer; no field can claim otherwise.",
        "8.2",
    ),
}

_NO_EXPLANATION: Final = Explanation("", "")


def explain(name: str) -> Explanation:
    """The explanation of a field name (an empty one for an unknown name)."""
    return EXPLANATIONS.get(name, _NO_EXPLANATION)


@dataclass(frozen=True, slots=True)
class FieldRow:
    """One named byte range of a frame (or, for an exposed session, of its plaintext)."""

    key: str
    name: str
    depth: int
    source: str
    """``frame`` for captured bytes, ``plaintext`` for a sealed part's decrypted contents."""
    start: int
    """Offset in the source: for ``frame``, from the first header byte."""
    length: int
    body_offset: int
    """Offset from the first body byte; -1 for header fields and plaintext rows."""
    value: str
    """A value read off the bytes where that is meaningful; empty otherwise."""
    origin: str
    explanation: str
    section: str


def _row(  # noqa: PLR0913  # one row's every column
    key: str,
    name: str,
    *,
    depth: int,
    source: str,
    start: int,
    length: int,
    body_offset: int,
    value: str = "",
    origin: str = WIRE,
    explain_as: str = "",
) -> FieldRow:
    explanation = explain(explain_as or name)
    return FieldRow(
        key=key,
        name=name,
        depth=depth,
        source=source,
        start=start,
        length=length,
        body_offset=body_offset,
        value=value,
        origin=origin,
        explanation=explanation.text,
        section=explanation.section,
    )


def frame_bytes(event: FrameTraced) -> bytes:
    """The frame as it crossed the wire: header and body."""
    return event.frame.encode()


def frame_name(event: FrameTraced) -> str:
    """``Hello``, ``Reply``… or ``Record``."""
    return FRAME_NAMES.get(event.frame.type, f"0x{int(event.frame.type):02x}")


def _value(field: Field, body: bytes) -> str:
    chunk = body[field.offset : field.offset + field.length]
    if len(chunk) != field.length or not chunk:
        return ""
    match field.name:
        case "version":
            return f"0x{chunk[0]:02x}"
        case "profile":
            return PROFILE_IDS.get(chunk[0], f"unknown (0x{chunk[0]:02x})")
        case "flags":
            return f"gb_request = {chunk[0] & 1}" if chunk[0] in {0, 1} else f"0x{chunk[0]:02x}"
        case "supported":
            names = [name for bit, name in _PROFILE_BITS if chunk[0] & bit]
            return ", ".join(names) or "none"
        case _:
            return ""


def frame_fields(event: FrameTraced) -> list[FieldRow]:
    """The captured frame's header and body fields, parents before their components."""
    body = event.frame.body
    rows = [
        _row("h:length", "length", depth=0, source="frame", start=0, length=4, body_offset=-1,
             value=f"{len(body):,} B"),
        _row("h:type", "type", depth=0, source="frame", start=4, length=1, body_offset=-1,
             value=f"0x{int(event.frame.type):02x} {frame_name(event)}"),
    ]  # fmt: skip
    rows.extend(
        _row(
            f"b:{field.parent}/{field.name}" if field.parent else f"b:{field.name}",
            field.name,
            depth=1 if field.parent else 0,
            source="frame",
            start=HEADER_LEN + field.offset,
            length=field.length,
            body_offset=field.offset,
            value=_value(field, body),
        )
        for field in event.fields
    )
    return rows


# -- exposed sessions: what a sealed part held ---------------------------------------------------

HANDSHAKE_KEYS: Final[dict[FrameType, tuple[str, int]]] = {
    FrameType.REPLY: ("hs_R.key", 0),
    FrameType.CONFIRM: ("hs_I.key", 0),
    FrameType.ADMIT: ("hs_R.key", 1),
}
"""Which handshake key and sequence number sealed each handshake frame (DESIGN §7.2)."""


def record_key(record: RecordTraced, *, initiator: bool) -> str:
    """The label of the key that sealed or opened a record, such as ``ap_R[1]+2.key``.

    The initiator sends under ``ap_I`` and receives under ``ap_R``; the responder the reverse.
    """
    sent_by_initiator = (record.direction is Direction.OUT) is initiator
    side = "I" if sent_by_initiator else "R"
    generation = f"+{record.generation}" if record.generation else ""
    return f"ap_{side}[{record.epoch}]{generation}.key"


def _hex(data: bytes, limit: int = 8) -> str:
    return data[:limit].hex() + ("…" if len(data) > limit else "")


def plaintext_fields(
    frame_type: FrameType, opened: RecordOpened, profile: ProfileFacts | None
) -> list[FieldRow]:
    """The rows of a sealed part's plaintext, from an exposed session's revealed record.

    Handshake plaintexts have fixed layouts (DESIGN §7.2); a record's plaintext is one Inner
    message, decoded with the same strict schema the engine uses.
    """
    plaintext = opened.plaintext
    rows = [
        _row("p:nonce", "nonce", depth=0, source="plaintext", start=0, length=0, body_offset=-1,
             value=opened.nonce.hex(), origin=DECRYPTED, explain_as="record (sealed)"),
    ]  # fmt: skip
    if frame_type is FrameType.RECORD:
        return rows + _inner_rows(plaintext)
    if profile is None:
        return rows
    if frame_type is FrameType.ADMIT:
        layout = [("decision", 1), ("admit flags", 1), ("reason", 1), ("FinA", profile.hash_len)]
    else:
        suffix = "R" if frame_type is FrameType.REPLY else "I"
        layout = [
            (f"Id{suffix}", BUNDLE_LEN),
            (f"Sig{suffix}", profile.sig_len),
            (f"Fin{suffix}", profile.hash_len),
        ]
    if sum(size for _, size in layout) != len(plaintext):
        return rows  # not the layout we know: show nothing rather than a guess
    offset = 0
    for name, size in layout:
        chunk = plaintext[offset : offset + size]
        explain_as = name.rstrip("RI") if name[:-1] in {"Id", "Sig", "Fin"} else name
        rows.append(
            _row(f"p:{name}", name, depth=0, source="plaintext", start=offset, length=size,
                 body_offset=-1, value=_admit_value(name, chunk) or _hex(chunk),
                 origin=DECRYPTED, explain_as=explain_as)
        )  # fmt: skip
        offset += size
    return rows


_DECISIONS: Final = {0: "accept", 1: "reject"}
_ADMIT_REASONS: Final = {0: "none", 1: "declined", 2: "profile_policy", 3: "timeout", 4: "busy"}


def _admit_value(name: str, chunk: bytes) -> str:
    match name:
        case "decision":
            return _DECISIONS.get(chunk[0], f"0x{chunk[0]:02x}")
        case "admit flags":
            return f"glass_box = {chunk[0] & 1}"
        case "reason":
            return _ADMIT_REASONS.get(chunk[0], f"0x{chunk[0]:02x}")
        case _:
            return ""


def _inner_rows(plaintext: bytes) -> list[FieldRow]:
    rows = [
        _row("p:inner", "Inner", depth=0, source="plaintext", start=0, length=len(plaintext),
             body_offset=-1, value=f"{len(plaintext):,} B", origin=DECRYPTED),
    ]  # fmt: skip
    try:
        message = decode_inner(plaintext)
    except Exception:  # noqa: BLE001  # any decoding failure: show the bytes, no fields
        return rows
    kind = type(message).__struct_config__.tag
    rows.append(
        _row("p:kind", "kind", depth=1, source="plaintext", start=0, length=0, body_offset=-1,
             value=str(kind), origin=DECRYPTED, explain_as="Inner")
    )  # fmt: skip
    rows.extend(
        _row(f"p:{name}", name, depth=1, source="plaintext", start=0, length=0,
             body_offset=-1, value=_inner_value(getattr(message, name)), origin=DECRYPTED,
             explain_as="Inner")
        for name in message.__struct_fields__
    )  # fmt: skip
    return rows


def _inner_value(value: object) -> str:
    match value:
        case bytes():
            return f"{_hex(value, 16)} ({len(value):,} B)"
        case str():
            return display_text(value, limit=200)  # peer text: plain and display-safe
        case Struct():
            return type(value).__name__
        case _:
            label = getattr(value, "label", None)
            return label if isinstance(label, str) else str(value)
