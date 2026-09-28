"""Profile constants (DESIGN Appendix A), checked against the table and the live primitives."""

import os

import pytest

from qrp2p.core.crypto import profiles
from qrp2p.core.crypto.aead import TAG_LEN, AeadAlgorithm
from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import BUNDLE_LEN, PEER_ID_LEN
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, REAL_PROFILES, Profile, ProfileId
from qrp2p.core.crypto.secret import Secret
from tests.support import identity_from_label

# DESIGN Appendix A, transcribed independently of src/.
APPENDIX_A = {
    "HYBRID-1": {
        "id": 0x01,
        "ek": 1216,
        "ct": 1120,
        "ss": 32,
        "sig": 3373,
        "hlen": 32,
        "hello": 1251,
        "reply": 9150,
        "confirm": 7998,
        "admit": 51,
        "total_kb": 18.5,
    },
    "PQ-CNSA-1": {
        "id": 0x02,
        "ek": 1568,
        "ct": 1568,
        "ss": 32,
        "sig": 4627,
        "hlen": 48,
        "hello": 1603,
        "reply": 10868,
        "confirm": 9268,
        "admit": 67,
        "total_kb": 21.8,
    },
}
REAL = {p.name: p for p in REAL_PROFILES}


def test_real_profiles_are_exactly_hybrid_and_cnsa() -> None:
    assert [p.name for p in REAL_PROFILES] == ["HYBRID-1", "PQ-CNSA-1"]
    assert REAL_PROFILES[0] is HYBRID_1  # the default
    assert all(not p.lab_only for p in REAL_PROFILES)
    assert 0x7F not in {p.id for p in REAL_PROFILES}
    assert [int(i) for i in ProfileId] == [0x01, 0x02]


@pytest.mark.parametrize("name", APPENDIX_A)
def test_appendix_a_table(name: str) -> None:
    row, profile = APPENDIX_A[name], REAL[name]
    assert profile.id == row["id"]
    assert (profile.ek_len, profile.ct_len, profile.kem.ss_len) == (row["ek"], row["ct"], row["ss"])
    assert (profile.sig_len, profile.hash_len) == (row["sig"], row["hlen"])
    assert profile.hello_body_len == row["hello"]
    assert profile.reply_body_len == row["reply"]
    assert profile.confirm_body_len == row["confirm"]
    assert profile.admit_body_len == row["admit"]
    assert round(profile.handshake_total_len / 1000, 1) == row["total_kb"]


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_appendix_a_formulas(profile: Profile) -> None:
    inner = BUNDLE_LEN + profile.sig_len + profile.hash_len + TAG_LEN
    assert profile.reply_body_len == 32 + profile.ct_len + inner
    assert profile.confirm_body_len == inner
    assert profile.admit_body_len == 3 + profile.hash_len + 16


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_sizes_match_live_primitives(profile: Profile) -> None:
    dk, ek = profile.kem.keygen(Secret(os.urandom(profile.kem.seed_len), "seed"))
    shared, ct = profile.kem.encapsulate(ek)
    assert len(ek) == profile.ek_len
    assert len(ct) == profile.ct_len
    assert len(shared.ss) == profile.kem.ss_len
    assert profile.kem.decapsulate(dk, ct) == shared
    sig = profile.sig.sign(identity_from_label("alice"), Role.RESPONDER, bytes(profile.hash_len))
    assert len(sig) == profile.sig_len
    assert len(profile.hash.digest(b"")) == profile.hash_len


def test_algorithm_choices() -> None:
    assert (HYBRID_1.kem.name, HYBRID_1.aead, HYBRID_1.hash.name) == (
        "X-Wing",
        AeadAlgorithm.CHACHA20_POLY1305,
        "SHA-256",
    )
    assert (PQ_CNSA_1.kem.name, PQ_CNSA_1.aead, PQ_CNSA_1.hash.name) == (
        "ML-KEM-1024",
        AeadAlgorithm.AES_256_GCM,
        "SHA-384",
    )
    assert HYBRID_1.sig.name == "Ed25519 + ML-DSA-65"
    assert PQ_CNSA_1.sig.name == "ML-DSA-87"


def test_other_constants() -> None:
    assert BUNDLE_LEN == 4577
    assert PEER_ID_LEN == 48
    assert profiles.MAX_FRAME_BODY == 16_448
    assert profiles.MAX_RECORD_PLAINTEXT == 16_384
    assert profiles.DEFAULT_PORT == 47_470
    assert profiles.NONCE_LEN == 32
    assert profiles.FRAME_HEADER_LEN == 5


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_every_frame_fits_the_frame_limit(profile: Profile) -> None:
    bodies = (
        profile.hello_body_len,
        profile.reply_body_len,
        profile.confirm_body_len,
        profile.admit_body_len,
        profiles.MAX_RECORD_PLAINTEXT + TAG_LEN,
    )
    assert max(bodies) <= profiles.MAX_FRAME_BODY
