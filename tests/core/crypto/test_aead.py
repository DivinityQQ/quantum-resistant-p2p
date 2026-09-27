"""AEAD with implicit sequence numbers (DESIGN §7.2, §8.1)."""

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from hypothesis import given
from hypothesis import strategies as st

from qrp2p.core.crypto import aead
from qrp2p.core.crypto.aead import MAX_SEQ, AeadAlgorithm
from qrp2p.core.crypto.kdf import TrafficKeys
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

KEY = bytes(range(32))
IV = bytes.fromhex("0102030405060708090a0b0c")
KEYS = TrafficKeys(Secret(KEY, "k"), Secret(IV, "iv"))
AAD = b"\x00\x00\x00\x20\x20"  # a frame header
ALGORITHMS = list(AeadAlgorithm)


def ref_nonce(iv: bytes, seq: int) -> bytes:
    padded = bytes(4) + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv, padded, strict=True))


def test_nonce_is_iv_xor_u96_seq() -> None:
    assert aead.nonce(IV, 0) == IV
    assert aead.nonce(IV, 1) == IV[:-1] + bytes([IV[-1] ^ 1])
    assert aead.nonce(IV, MAX_SEQ) == IV[:4] + bytes(b ^ 0xFF for b in IV[4:])
    for seq in (2, 255, 256, 2**32, 2**63 + 5):
        assert aead.nonce(IV, seq) == ref_nonce(IV, seq)


def test_nonce_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="sequence"):
        aead.nonce(IV, MAX_SEQ + 1)
    with pytest.raises(ValueError, match="sequence"):
        aead.nonce(IV, -1)
    with pytest.raises(ValueError, match="12 bytes"):
        aead.nonce(IV[:-1], 0)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_seal_matches_pyca_with_reference_nonce(algorithm: AeadAlgorithm) -> None:
    cipher = ChaCha20Poly1305(KEY) if algorithm is AeadAlgorithm.CHACHA20_POLY1305 else AESGCM(KEY)
    for seq in (0, 1, 7, MAX_SEQ):
        expected = cipher.encrypt(ref_nonce(IV, seq), b"hello", AAD)
        assert aead.seal(algorithm, KEYS, seq, AAD, b"hello") == expected


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_round_trip_and_tag_length(algorithm: AeadAlgorithm) -> None:
    sealed = aead.seal(algorithm, KEYS, 3, AAD, b"message")
    assert len(sealed) == len(b"message") + aead.TAG_LEN
    assert aead.unseal(algorithm, KEYS, 3, AAD, sealed) == b"message"
    assert aead.seal(algorithm, KEYS, 4, AAD, b"message") != sealed


def assert_decrypt_failed(
    algorithm: AeadAlgorithm, keys: TrafficKeys, seq: int, aad: bytes, sealed: bytes
) -> None:
    with pytest.raises(ProtocolError) as info:
        aead.unseal(algorithm, keys, seq, aad, sealed)
    assert info.value.reason is CloseReason.DECRYPT_FAILED


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_wrong_sequence_number_is_decrypt_failed(algorithm: AeadAlgorithm) -> None:
    """Replay and reordering fail because the receiver's own counter decides (DESIGN §8.1)."""
    sealed = aead.seal(algorithm, KEYS, 5, AAD, b"message")
    for seq in (4, 6, 0):
        assert_decrypt_failed(algorithm, KEYS, seq, AAD, sealed)


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_wrong_aad_key_or_truncation_is_decrypt_failed(algorithm: AeadAlgorithm) -> None:
    sealed = aead.seal(algorithm, KEYS, 0, AAD, b"message")
    assert_decrypt_failed(algorithm, KEYS, 0, AAD[:-1] + b"\x21", sealed)
    other = TrafficKeys(Secret(bytes(32), "k"), Secret(IV, "iv"))
    assert_decrypt_failed(algorithm, other, 0, AAD, sealed)
    assert_decrypt_failed(algorithm, KEYS, 0, AAD, sealed[:-1])
    assert_decrypt_failed(algorithm, KEYS, 0, AAD, sealed[: aead.TAG_LEN - 1])
    assert_decrypt_failed(algorithm, KEYS, 0, AAD, b"")


@given(data=st.data())
def test_any_bit_flip_is_decrypt_failed(data: st.DataObject) -> None:
    algorithm = data.draw(st.sampled_from(ALGORITHMS))
    plaintext = data.draw(st.binary(max_size=64))
    sealed = bytearray(aead.seal(algorithm, KEYS, 9, AAD, plaintext))
    position = data.draw(st.integers(min_value=0, max_value=len(sealed) * 8 - 1))
    sealed[position // 8] ^= 1 << (position % 8)
    assert_decrypt_failed(algorithm, KEYS, 9, AAD, bytes(sealed))


def test_key_must_be_32_bytes() -> None:
    short = TrafficKeys(Secret(bytes(16), "k"), Secret(IV, "iv"))
    with pytest.raises(ValueError, match="32 bytes"):
        aead.seal(AeadAlgorithm.AES_256_GCM, short, 0, b"", b"")


def test_empty_plaintext_is_just_a_tag() -> None:
    keys = TrafficKeys(Secret(bytes(32), "k"), Secret(bytes(12), "iv"))
    for algorithm in AeadAlgorithm:
        sealed = aead.seal(algorithm, keys, 0, b"aad", b"")
        assert len(sealed) == aead.TAG_LEN
        assert aead.unseal(algorithm, keys, 0, b"aad", sealed) == b""
