"""ML-KEM-1024 for PQ-CNSA-1 (DESIGN §4): round trip, sizes and error mapping."""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem

from qrp2p.core.crypto import mlkem1024
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError


def expect(reason: CloseReason) -> pytest.RaisesExc[ProtocolError]:
    return pytest.raises(ProtocolError, check=lambda e: e.reason is reason)


def test_round_trip_and_sizes() -> None:
    dk, ek = mlkem1024.keygen(Secret(os.urandom(64), "seed"))
    shared, ct = mlkem1024.encapsulate(ek)
    assert (len(dk), len(ek), len(ct), len(shared.ss)) == (64, 1568, 1568, 32)
    assert mlkem1024.decapsulate(dk, ct) == shared
    assert shared.components == ()


def test_keygen_is_the_fips203_seed_expansion() -> None:
    seed = os.urandom(64)
    _, ek = mlkem1024.MLKEM1024.keygen(Secret(seed, "seed"))
    expected = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()
    assert ek == expected


def test_interoperates_with_pyca_directly() -> None:
    private = mlkem.MLKEM1024PrivateKey.generate()
    shared, ct = mlkem1024.encapsulate(private.public_key().public_bytes_raw())
    assert private.decapsulate(ct) == shared.ss.reveal()


def test_modulus_violation_is_invalid_kem_key() -> None:
    _, ek = mlkem1024.keygen(Secret(os.urandom(64), "seed"))
    bad = b"\xff\xff" + ek[2:]  # coefficient 0 becomes 0xFFF >= q
    with expect(CloseReason.INVALID_KEM_KEY):
        mlkem1024.encapsulate(bad)


@pytest.mark.parametrize("size", [0, 1184, 1567, 1569])
def test_wrong_size_public_key_is_invalid_kem_key(size: int) -> None:
    with expect(CloseReason.INVALID_KEM_KEY):
        mlkem1024.encapsulate(bytes(size))


@pytest.mark.parametrize("size", [0, 1088, 1567, 1569])
def test_wrong_size_ciphertext_is_kem_failure(size: int) -> None:
    dk, _ = mlkem1024.keygen(Secret(os.urandom(64), "seed"))
    with expect(CloseReason.KEM_FAILURE):
        mlkem1024.decapsulate(dk, bytes(size))


def test_wrong_size_own_key_is_internal() -> None:
    with expect(CloseReason.INTERNAL):
        mlkem1024.keygen(Secret(bytes(32), "seed"))
