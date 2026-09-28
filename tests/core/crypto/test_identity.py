"""Identity bundles, peer IDs, short IDs and safety numbers (DESIGN §5)."""

import base64
import hashlib
import pickle

import pytest

from qrp2p.core.crypto.identity import (
    BUNDLE_LEN,
    IdentityBundle,
    IdentityKeyPair,
    safety_number,
    short_id,
)
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError
from tests.support import DeterministicRandom
from tests.vectors import load_json

KAT = load_json("identity.json")


def pair_from_kat(name: str) -> IdentityKeyPair:
    seeds = [Secret(bytes.fromhex(s), "seed") for s in KAT[name]["seeds"]]
    return IdentityKeyPair(*seeds)


def ref_safety_digits(pid: bytes) -> list[str]:
    """DESIGN §5.2, written independently: u40(SHAKE256(...)[5i:5i+5]) mod 100000."""
    stream = hashlib.shake_256(b"qrp2p2 safety" + pid).digest(30)
    return [f"{int.from_bytes(stream[5 * i : 5 * i + 5], 'big') % 100000:05d}" for i in range(6)]


def test_bundle_layout_and_size() -> None:
    bundle = pair_from_kat("alice").bundle
    encoded = bundle.encode()
    assert len(encoded) == BUNDLE_LEN == 4577
    assert encoded[0] == 0x01
    assert encoded[1:33] == bundle.ed25519
    assert encoded[33 : 33 + 1952] == bundle.mldsa65
    assert encoded[33 + 1952 :] == bundle.mldsa87


@pytest.mark.parametrize("name", ["alice", "bob"])
def test_identity_kats(name: str) -> None:
    kat = KAT[name]
    pair = pair_from_kat(name)
    bundle_bytes = bytes.fromhex(kat["bundle"])
    assert pair.bundle.encode() == bundle_bytes
    assert pair.bundle.peer_id.hex() == kat["peer_id"]
    assert pair.bundle.short_id == kat["short_id"]
    # Recomputed from DESIGN §5.1 without the module under test:
    assert hashlib.sha384(b"qrp2p2 identity" + bundle_bytes).hexdigest() == kat["peer_id"]
    raw = base64.b32encode(bytes.fromhex(kat["peer_id"])[:5]).decode()
    assert kat["short_id"] == f"{raw[:4]}-{raw[4:]}"


def test_safety_number_kat_and_symmetry() -> None:
    a, b = (bytes.fromhex(KAT[n]["peer_id"]) for n in ("alice", "bob"))
    number = safety_number(a, b)
    assert list(number) == KAT["safety_number"]
    assert safety_number(b, a) == number
    low, high = sorted((a, b))
    assert list(number) == ref_safety_digits(low) + ref_safety_digits(high)
    assert len(number) == 12
    assert all(len(group) == 5 and group.isdigit() for group in number)


def test_safety_number_rejects_wrong_sizes() -> None:
    with pytest.raises(ValueError, match="48 bytes"):
        safety_number(bytes(47), bytes(48))


def test_short_id_format() -> None:
    assert short_id(bytes(48)) == "AAAA-AAAA"
    assert short_id(b"\xff" * 5 + bytes(43)) == "7777-7777"


def test_decode_round_trip() -> None:
    bundle = pair_from_kat("bob").bundle
    assert IdentityBundle.decode(bundle.encode()) == bundle


def test_decode_rejects_unknown_version() -> None:
    encoded = pair_from_kat("alice").bundle.encode()
    for version in (0x00, 0x02, 0xFF):
        with pytest.raises(ProtocolError) as info:
            IdentityBundle.decode(bytes([version]) + encoded[1:])
        assert info.value.reason is CloseReason.SCHEMA_ERROR


@pytest.mark.parametrize("delta", [-1, 1, -4577])
def test_decode_rejects_wrong_size(delta: int) -> None:
    encoded = pair_from_kat("alice").bundle.encode()
    data = encoded[:delta] if delta < 0 else encoded + b"\0"
    with pytest.raises(ProtocolError) as info:
        IdentityBundle.decode(data)
    assert info.value.reason is CloseReason.SCHEMA_ERROR


def test_bundle_fields_are_size_checked() -> None:
    with pytest.raises(ProtocolError) as info:
        IdentityBundle(ed25519=bytes(31), mldsa65=bytes(1952), mldsa87=bytes(2592))
    assert info.value.reason is CloseReason.SCHEMA_ERROR


def test_generate_uses_injected_randomness() -> None:
    first = IdentityKeyPair.generate(DeterministicRandom("x"))
    second = IdentityKeyPair.generate(DeterministicRandom("x"))
    other = IdentityKeyPair.generate(DeterministicRandom("y"))
    assert first.bundle == second.bundle
    assert first.bundle.peer_id != other.bundle.peer_id
    assert [s.label for s in first.seeds] == [
        "identity.ed25519",
        "identity.mldsa65",
        "identity.mldsa87",
    ]


def test_seeds_are_validated() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        IdentityKeyPair(Secret(bytes(32), "a"), Secret(bytes(31), "b"), Secret(bytes(32), "c"))


def test_key_pair_does_not_leak_or_pickle() -> None:
    pair = pair_from_kat("alice")
    text = repr(pair)
    assert pair.bundle.short_id in text
    for seed in KAT["alice"]["seeds"]:
        assert seed not in text
    with pytest.raises(TypeError):
        pickle.dumps(pair)
