"""Profile AEADs with implicit sequence-number nonces (DESIGN §7.2, §8.1).

``nonce = iv XOR u96(seq)``. The sequence number is never transmitted: the receiver's own counter
decides, so a replayed or reordered record fails to open (``decrypt_failed``).
"""

from enum import Enum
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from qrp2p.core.crypto.kdf import AEAD_IV_LEN, AEAD_KEY_LEN, TrafficKeys
from qrp2p.core.errors import CloseReason, ProtocolError

TAG_LEN: Final = 16
MAX_SEQ: Final = 2**64 - 1
"""``seq`` is a 64-bit counter per direction and traffic secret (DESIGN §8.1)."""


class AeadAlgorithm(Enum):
    """The AEADs used by the profiles (DESIGN §4)."""

    CHACHA20_POLY1305 = "ChaCha20-Poly1305"
    AES_256_GCM = "AES-256-GCM"


def nonce(iv: bytes, seq: int) -> bytes:
    """Return ``iv XOR u96(seq)``.

    Raises:
        ValueError: ``iv`` is not 12 bytes or ``seq`` is outside ``0..2^64-1``.
    """
    if len(iv) != AEAD_IV_LEN:
        msg = "AEAD IV must be 12 bytes"
        raise ValueError(msg)
    if not 0 <= seq <= MAX_SEQ:
        msg = "sequence number out of range"
        raise ValueError(msg)
    return (int.from_bytes(iv, "big") ^ seq).to_bytes(AEAD_IV_LEN, "big")


def _cipher(algorithm: AeadAlgorithm, keys: TrafficKeys) -> ChaCha20Poly1305 | AESGCM:
    key = keys.key.reveal()
    if len(key) != AEAD_KEY_LEN:
        msg = "AEAD key must be 32 bytes"
        raise ValueError(msg)
    if algorithm is AeadAlgorithm.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    return AESGCM(key)


def seal(
    algorithm: AeadAlgorithm, keys: TrafficKeys, seq: int, aad: bytes, plaintext: bytes
) -> bytes:
    """Encrypt ``plaintext`` under ``keys`` with sequence number ``seq``; returns ``ct ‖ tag``."""
    return _cipher(algorithm, keys).encrypt(nonce(keys.iv.reveal(), seq), plaintext, aad)


def unseal(
    algorithm: AeadAlgorithm, keys: TrafficKeys, seq: int, aad: bytes, ciphertext: bytes
) -> bytes:
    """Decrypt and authenticate ``ciphertext`` (``ct ‖ tag``).

    Raises:
        ProtocolError: ``decrypt_failed`` if authentication fails for any reason, including a
            wrong key, sequence number or associated data.
    """
    if len(ciphertext) < TAG_LEN:
        raise ProtocolError(CloseReason.DECRYPT_FAILED, "ciphertext shorter than the tag")
    try:
        return _cipher(algorithm, keys).decrypt(nonce(keys.iv.reveal(), seq), ciphertext, aad)
    except InvalidTag:
        raise ProtocolError(CloseReason.DECRYPT_FAILED, "AEAD authentication failed") from None
