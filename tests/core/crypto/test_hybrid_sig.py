"""HybridSign (DESIGN §4.4): both halves checked, roles bound, exact layouts."""

import itertools

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa

from qrp2p.core.crypto.hybrid_sig import (
    HYBRID_ED25519_MLDSA65,
    MLDSA87,
    Role,
    SignatureScheme,
    ed25519_message,
    signature_context,
)
from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError
from tests.support import identity_from_label
from tests.vectors import load_json

ALICE = identity_from_label("alice")
BOB = identity_from_label("bob")
TH = bytes(range(32))
SCHEMES: list[SignatureScheme] = [HYBRID_ED25519_MLDSA65, MLDSA87]


def assert_invalid(scheme: SignatureScheme, role: Role, th: bytes, sig: bytes) -> None:
    with pytest.raises(ProtocolError) as info:
        scheme.verify(ALICE.bundle, role, th, sig)
    assert info.value.reason is CloseReason.SIGNATURE_INVALID


def test_role_strings_and_layouts() -> None:
    assert [r.value for r in Role] == ["responder", "initiator", "rekey-answer", "rekey-finish"]
    assert signature_context(Role.REKEY_ANSWER) == b"qrp2p2 rekey-answer"
    assert ed25519_message(Role.RESPONDER, b"th") == b"qrp2p2 responder\x00th"
    assert all(len(signature_context(r)) <= 255 for r in Role)  # FIPS 204 context limit


def test_sizes() -> None:
    assert HYBRID_ED25519_MLDSA65.sig_len == 3373
    assert MLDSA87.sig_len == 4627
    assert len(HYBRID_ED25519_MLDSA65.sign(ALICE, Role.RESPONDER, TH)) == 3373
    assert len(MLDSA87.sign(ALICE, Role.RESPONDER, TH)) == 4627


@pytest.mark.parametrize("scheme", SCHEMES, ids=lambda s: s.name)
@pytest.mark.parametrize("role", list(Role))
def test_sign_verify_round_trip(scheme: SignatureScheme, role: Role) -> None:
    scheme.verify(ALICE.bundle, role, TH, scheme.sign(ALICE, role, TH))


@pytest.mark.parametrize("scheme", SCHEMES, ids=lambda s: s.name)
def test_cross_role_replay_fails(scheme: SignatureScheme) -> None:
    for signed, verified in itertools.permutations(Role, 2):
        assert_invalid(scheme, verified, TH, scheme.sign(ALICE, signed, TH))


@pytest.mark.parametrize("scheme", SCHEMES, ids=lambda s: s.name)
def test_wrong_transcript_or_signer_fails(scheme: SignatureScheme) -> None:
    sig = scheme.sign(ALICE, Role.INITIATOR, TH)
    assert_invalid(scheme, Role.INITIATOR, TH[:-1] + b"\xff", sig)
    with pytest.raises(ProtocolError):
        scheme.verify(BOB.bundle, Role.INITIATOR, TH, sig)


@pytest.mark.parametrize("scheme", SCHEMES, ids=lambda s: s.name)
def test_wrong_length_fails(scheme: SignatureScheme) -> None:
    sig = scheme.sign(ALICE, Role.RESPONDER, TH)
    assert_invalid(scheme, Role.RESPONDER, TH, sig[:-1])
    assert_invalid(scheme, Role.RESPONDER, TH, sig + b"\0")
    assert_invalid(scheme, Role.RESPONDER, TH, b"")


def test_tampered_ed25519_half_is_rejected() -> None:
    sig = bytearray(HYBRID_ED25519_MLDSA65.sign(ALICE, Role.RESPONDER, TH))
    sig[10] ^= 0x01
    assert_invalid(HYBRID_ED25519_MLDSA65, Role.RESPONDER, TH, bytes(sig))


def test_tampered_mldsa_half_is_rejected() -> None:
    sig = bytearray(HYBRID_ED25519_MLDSA65.sign(ALICE, Role.RESPONDER, TH))
    sig[64 + 100] ^= 0x01
    assert_invalid(HYBRID_ED25519_MLDSA65, Role.RESPONDER, TH, bytes(sig))


def test_each_half_binds_the_role() -> None:
    """Splice halves signed for different roles: each half alone must make verification fail."""
    responder = HYBRID_ED25519_MLDSA65.sign(ALICE, Role.RESPONDER, TH)
    initiator = HYBRID_ED25519_MLDSA65.sign(ALICE, Role.INITIATOR, TH)
    spliced = responder[:64] + initiator[64:]
    assert_invalid(HYBRID_ED25519_MLDSA65, Role.RESPONDER, TH, spliced)
    assert_invalid(HYBRID_ED25519_MLDSA65, Role.INITIATOR, TH, spliced)


def test_wrong_profile_scheme_fails() -> None:
    assert_invalid(
        MLDSA87, Role.RESPONDER, TH, HYBRID_ED25519_MLDSA65.sign(ALICE, Role.RESPONDER, TH)
    )
    assert_invalid(
        HYBRID_ED25519_MLDSA65, Role.RESPONDER, TH, MLDSA87.sign(ALICE, Role.RESPONDER, TH)
    )


def test_ed25519_half_matches_kat() -> None:
    """Ed25519 is deterministic, so its half pins the exact message layout."""
    kat = load_json("identity.json")["alice"]
    pair = IdentityKeyPair(*(Secret(bytes.fromhex(s), "seed") for s in kat["seeds"]))
    sig = HYBRID_ED25519_MLDSA65.sign(pair, Role.RESPONDER, bytes.fromhex(kat["th"]))
    assert sig[:64].hex() == kat["ed25519_sig_responder"]


def test_mldsa_half_uses_the_role_context() -> None:
    sig = HYBRID_ED25519_MLDSA65.sign(ALICE, Role.REKEY_FINISH, TH)
    public = mldsa.MLDSA65PublicKey.from_public_bytes(ALICE.bundle.mldsa65)
    public.verify(sig[64:], TH, b"qrp2p2 rekey-finish")  # raises if the layout differs


def test_mldsa_signing_is_hedged() -> None:
    """pyca's ML-DSA is randomised, which is why replay records signatures (DESIGN §11.6)."""
    assert MLDSA87.sign(ALICE, Role.RESPONDER, TH) != MLDSA87.sign(ALICE, Role.RESPONDER, TH)
