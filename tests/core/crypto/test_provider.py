"""Crypto providers (DESIGN §11.3, §11.6): profile gating, injected randomness, containment."""

import dataclasses
import os

import pytest

from qrp2p.core.crypto import aead
from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.kdf import SHA256
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, REAL_PROFILES, Profile
from qrp2p.core.crypto.provider import (
    AeadRevealed,
    CryptoProvider,
    PlainProvider,
    Revealed,
    RevealingProvider,
    epoch_name,
)
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError
from tests.support import DeterministicRandom, identity_from_label

ALICE = identity_from_label("alice")


def run_exchange(provider: CryptoProvider, profile: Profile) -> None:
    """Every provider operation once, in handshake order, checking the results agree."""
    dk, ek = provider.kem_keygen(profile)
    shared, ct = provider.kem_encapsulate(profile, ek)
    assert provider.kem_decapsulate(profile, dk, ct) == shared
    zeros = bytes(profile.hash_len)
    hs = provider.extract(profile, zeros, shared.ss, name="hs")
    th = profile.hash.digest(provider.random(32))
    hs_r = provider.derive_secret(profile, hs, "r hs traffic", th, name="hs_R")
    fk_r = provider.expand_label(profile, hs_r, "finished", b"", profile.hash_len, name="fk_R")
    assert len(provider.hmac(profile, fk_r, th)) == profile.hash_len
    keys = provider.traffic_keys(profile, hs_r)
    sealed = provider.seal(profile, keys, 0, b"hdr", b"inner")
    assert provider.unseal(profile, keys, 0, b"hdr", sealed) == b"inner"
    sig = provider.sign(profile, ALICE, Role.RESPONDER, th)
    provider.verify(profile, ALICE.bundle, Role.RESPONDER, th, sig)


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_plain_provider_runs_every_operation(profile: Profile) -> None:
    run_exchange(PlainProvider(os.urandom), profile)


def test_plain_provider_refuses_profiles_it_was_not_built_with() -> None:
    provider = PlainProvider(os.urandom, profiles=[HYBRID_1])
    with pytest.raises(ProtocolError) as info:
        provider.kem_keygen(PQ_CNSA_1)
    assert info.value.reason is CloseReason.POLICY


def test_plain_provider_refuses_a_look_alike_profile() -> None:
    """Gating is by identity: a forged Profile reusing a real ID gets nowhere."""
    forged = dataclasses.replace(HYBRID_1, hash=SHA256, name="HYBRID-1")
    assert forged is not HYBRID_1
    provider = PlainProvider(os.urandom)
    for call in (
        lambda: provider.kem_keygen(forged),
        lambda: provider.kem_encapsulate(forged, bytes(1216)),
        lambda: provider.extract(forged, b"", b"", name="x"),
        lambda: provider.sign(forged, ALICE, Role.RESPONDER, bytes(32)),
    ):
        with pytest.raises(ProtocolError) as info:
            call()
        assert info.value.reason is CloseReason.POLICY


def test_keygen_uses_injected_randomness() -> None:
    first = PlainProvider(DeterministicRandom("r")).kem_keygen(HYBRID_1)
    second = PlainProvider(DeterministicRandom("r")).kem_keygen(HYBRID_1)
    assert first[1] == second[1]
    assert PlainProvider(DeterministicRandom("s")).kem_keygen(HYBRID_1)[1] != first[1]


def test_short_random_source_is_internal() -> None:
    provider = PlainProvider(lambda n: bytes(n - 1))
    with pytest.raises(ProtocolError) as info:
        provider.random(32)
    assert info.value.reason is CloseReason.INTERNAL


def test_plain_provider_has_no_way_to_emit() -> None:
    """Containment is structural (DESIGN §11.3): no sink, no callback, no extra state."""
    provider = PlainProvider(os.urandom)
    assert set(PlainProvider.__slots__) == {"_profiles", "_random"}
    assert not hasattr(provider, "__dict__")


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_revealing_provider_emits_every_derived_secret(profile: Profile) -> None:
    revealed: list[Revealed] = []
    run_exchange(RevealingProvider(PlainProvider(os.urandom), revealed.append), profile)
    labels = [s.label for s in revealed if isinstance(s, Secret)]
    hybrid = ["ssM", "ssX"] if profile is HYBRID_1 else []
    kem = ["dk", *hybrid, "ss", *hybrid, "ss"]  # dk, then encapsulate and decapsulate
    assert labels == [*kem, "hs", "hs_R", "fk_R", "hs_R.key", "hs_R.iv"]


def test_revealing_provider_reveals_each_record_nonce_and_plaintext() -> None:
    revealed: list[Revealed] = []
    provider = RevealingProvider(PlainProvider(os.urandom), revealed.append)
    secret = provider.extract(HYBRID_1, bytes(32), bytes(32), name="ap_I[0]")
    keys = provider.traffic_keys(HYBRID_1, secret)
    sealed = provider.seal(HYBRID_1, keys, 7, b"hdr", b"inner")
    provider.unseal(HYBRID_1, keys, 7, b"hdr", sealed)
    with pytest.raises(ProtocolError):  # a forged record reveals nothing
        provider.unseal(HYBRID_1, keys, 8, b"hdr", sealed)
    records = [r for r in revealed if isinstance(r, AeadRevealed)]
    assert [(r.key, r.seq, r.opened) for r in records] == [
        ("ap_I[0].key", 7, False),
        ("ap_I[0].key", 7, True),
    ]
    nonce = aead.nonce(keys.iv.reveal(), 7)
    assert all(r.nonce.reveal() == nonce and r.plaintext.reveal() == b"inner" for r in records)
    assert all(r.nonce.label == "ap_I[0].key.nonce" for r in records)


@pytest.mark.parametrize("profile", REAL_PROFILES, ids=lambda p: p.name)
def test_kem_outputs_are_named_by_epoch(profile: Profile) -> None:
    """Labels are unique per session: a rekey's KEM outputs carry their epoch."""
    provider = PlainProvider(os.urandom)
    dk, ek = provider.kem_keygen(profile, epoch=2)
    shared, ct = provider.kem_encapsulate(profile, ek, epoch=2)
    opened = provider.kem_decapsulate(profile, dk, ct, epoch=2)
    hybrid = ["ssM[2]", "ssX[2]"] if profile is HYBRID_1 else []
    assert dk.label == "dk[2]"
    for result in (shared, opened):
        assert [result.ss.label, *(c.label for c in result.components)] == ["ss[2]", *hybrid]
    assert opened == shared
    assert (epoch_name("ss", 0), epoch_name("ss", 1)) == ("ss", "ss[1]")


def test_revealing_provider_names_kem_outputs_by_epoch() -> None:
    revealed: list[Revealed] = []
    provider = RevealingProvider(PlainProvider(os.urandom), revealed.append)
    dk, ek = provider.kem_keygen(HYBRID_1, epoch=1)
    shared, ct = provider.kem_encapsulate(HYBRID_1, ek, epoch=1)
    opened = provider.kem_decapsulate(HYBRID_1, dk, ct, epoch=1)
    assert [dk.label, shared.ss.label, opened.ss.label] == ["dk[1]", "ss[1]", "ss[1]"]
    emitted = [s.label for s in revealed if isinstance(s, Secret)]
    assert emitted == ["dk[1]", *(["ssM[1]", "ssX[1]", "ss[1]"] * 2)]


def test_revealing_provider_emits_nothing_for_public_operations() -> None:
    revealed: list[Revealed] = []
    provider = RevealingProvider(PlainProvider(os.urandom), revealed.append)
    th = bytes(32)
    provider.random(32)
    sig = provider.sign(HYBRID_1, ALICE, Role.INITIATOR, th)
    provider.verify(HYBRID_1, ALICE.bundle, Role.INITIATOR, th, sig)
    assert revealed == []


def test_revealing_provider_keeps_the_inner_gate() -> None:
    provider = RevealingProvider(PlainProvider(os.urandom, profiles=[HYBRID_1]), lambda _: None)
    with pytest.raises(ProtocolError) as info:
        provider.kem_keygen(PQ_CNSA_1)
    assert info.value.reason is CloseReason.POLICY
