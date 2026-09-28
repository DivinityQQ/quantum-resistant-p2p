"""LAB-CLASSICAL (DESIGN §4, §4.3): sizes, X25519-KEM, Ed25519-only signatures, containment."""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from qrp2p.core.crypto.hybrid_sig import HYBRID_ED25519_MLDSA65, Role
from qrp2p.core.crypto.provider import PlainProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError
from qrp2p.lab.classical import ED25519_ONLY, LAB_CLASSICAL, LAB_PROFILES, X25519_KEM
from tests.support import identity_from_label

ALICE = identity_from_label("alice")
TH = bytes(range(32))


def expect(reason: CloseReason) -> pytest.RaisesExc[ProtocolError]:
    return pytest.raises(ProtocolError, check=lambda e: e.reason is reason)


def test_appendix_a_column() -> None:
    p = LAB_CLASSICAL
    assert (p.id, p.lab_only) == (0x7F, True)
    assert (p.ek_len, p.ct_len, p.kem.ss_len, p.sig_len, p.hash_len) == (32, 32, 32, 64, 32)
    assert (p.hello_body_len, p.reply_body_len) == (67, 4753)
    assert (p.confirm_body_len, p.admit_body_len) == (4689, 51)
    assert round(p.handshake_total_len / 1000, 1) == 9.6


def test_real_sessions_cannot_use_it() -> None:
    with expect(CloseReason.POLICY):
        PlainProvider(os.urandom).kem_keygen(LAB_CLASSICAL)
    lab = PlainProvider(os.urandom, profiles=LAB_PROFILES)
    dk, ek = lab.kem_keygen(LAB_CLASSICAL)
    shared, ct = lab.kem_encapsulate(LAB_CLASSICAL, ek)
    assert lab.kem_decapsulate(LAB_CLASSICAL, dk, ct) == shared


def test_x25519_kem_matches_design_4_3() -> None:
    dk, ek = X25519_KEM.keygen(Secret(os.urandom(32), "seed"))
    shared, ct = X25519_KEM.encapsulate(ek)
    assert X25519_KEM.decapsulate(dk, ct) == shared
    private = x25519.X25519PrivateKey.from_private_bytes(dk.reveal())
    ss_x = private.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
    expected = hashlib.sha256(ss_x + ct + ek + b"qrp2p2 x25519kem").digest()
    assert shared.ss.reveal() == expected
    assert [c.label for c in shared.components] == ["ssX"]
    assert shared.components[0].reveal() == ss_x


def test_x25519_kem_errors() -> None:
    dk, _ = X25519_KEM.keygen(Secret(os.urandom(32), "seed"))
    with expect(CloseReason.KEM_FAILURE):
        X25519_KEM.encapsulate(bytes(32))
    with expect(CloseReason.KEM_FAILURE):
        X25519_KEM.decapsulate(dk, bytes(32))
    with expect(CloseReason.INVALID_KEM_KEY):
        X25519_KEM.encapsulate(bytes(31))
    with expect(CloseReason.KEM_FAILURE):
        X25519_KEM.decapsulate(dk, bytes(33))
    with expect(CloseReason.INTERNAL):
        X25519_KEM.decapsulate(Secret(bytes(31), "dk"), bytes(32))


def test_ed25519_only_signature() -> None:
    sig = ED25519_ONLY.sign(ALICE, Role.RESPONDER, TH)
    assert len(sig) == 64
    ED25519_ONLY.verify(ALICE.bundle, Role.RESPONDER, TH, sig)
    # It is exactly the Ed25519 half of HybridSign (Ed25519 is deterministic).
    assert sig == HYBRID_ED25519_MLDSA65.sign(ALICE, Role.RESPONDER, TH)[:64]
    for bad_role in (Role.INITIATOR, Role.REKEY_ANSWER):
        with expect(CloseReason.SIGNATURE_INVALID):
            ED25519_ONLY.verify(ALICE.bundle, bad_role, TH, sig)
    with expect(CloseReason.SIGNATURE_INVALID):
        ED25519_ONLY.verify(ALICE.bundle, Role.RESPONDER, TH, sig[:-1])
    with expect(CloseReason.SIGNATURE_INVALID):
        ED25519_ONLY.verify(ALICE.bundle, Role.RESPONDER, TH, bytes([sig[0] ^ 1]) + sig[1:])
