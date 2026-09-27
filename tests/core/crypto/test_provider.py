"""Crypto providers (DESIGN §11.3, §11.6): profile gating, injected randomness, containment."""

import dataclasses
import os

import pytest

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.kdf import SHA256
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, REAL_PROFILES, Profile
from qrp2p.core.crypto.provider import CryptoProvider, PlainProvider, RevealingProvider
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
    revealed: list[Secret] = []
    run_exchange(RevealingProvider(PlainProvider(os.urandom), revealed.append), profile)
    labels = [s.label for s in revealed]
    hybrid = ["ssM", "ssX"] if profile is HYBRID_1 else []
    kem = [labels[0], *hybrid, "ss", *hybrid, "ss"]  # dk, then encapsulate and decapsulate
    assert labels == [*kem, "hs", "hs_R", "fk_R", "hs_R.key", "hs_R.iv"]


def test_revealing_provider_emits_nothing_for_public_operations() -> None:
    revealed: list[Secret] = []
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
