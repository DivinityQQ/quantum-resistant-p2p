"""ML-KEM-1024 (FIPS 203) for the ``PQ-CNSA-1`` profile (DESIGN §4).

The decapsulation key is the 64-byte FIPS 203 seed ``d ‖ z``.
"""

from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric import mlkem

from qrp2p.core.crypto.kem import SharedSecret
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

SEED_LEN: Final = 64
EK_LEN: Final = 1568
CT_LEN: Final = 1568
SS_LEN: Final = 32


def _private_key(dk: Secret) -> mlkem.MLKEM1024PrivateKey:
    if len(dk) != SEED_LEN:
        raise ProtocolError(CloseReason.INTERNAL, "ML-KEM-1024 decapsulation key must be 64 bytes")
    return mlkem.MLKEM1024PrivateKey.from_seed_bytes(dk.reveal())


def keygen(seed: Secret) -> tuple[Secret, bytes]:
    """Return ``(dk, ek)``; ``dk`` is the 64-byte seed."""
    dk = Secret(seed.reveal(), "mlkem1024.dk")
    return dk, _private_key(dk).public_key().public_bytes_raw()


def encapsulate(ek: bytes) -> tuple[SharedSecret, bytes]:
    """Encapsulate to ``ek``.

    Raises:
        ProtocolError: ``invalid_kem_key`` if ``ek`` has the wrong size or fails the FIPS 203
            modulus check.
    """
    if len(ek) != EK_LEN:
        raise ProtocolError(
            CloseReason.INVALID_KEM_KEY, "ML-KEM-1024 public key has the wrong size"
        )
    try:
        public = mlkem.MLKEM1024PublicKey.from_public_bytes(ek)
    except ValueError:
        raise ProtocolError(
            CloseReason.INVALID_KEM_KEY, "ML-KEM-1024 public key fails the modulus check"
        ) from None
    ss, ct = public.encapsulate()
    return SharedSecret(Secret(ss, "ss")), ct


def decapsulate(dk: Secret, ct: bytes) -> SharedSecret:
    """Decapsulate ``ct`` (implicit rejection for a malformed ciphertext of the right size).

    Raises:
        ProtocolError: ``kem_failure`` if ``ct`` has the wrong size.
    """
    if len(ct) != CT_LEN:
        raise ProtocolError(CloseReason.KEM_FAILURE, "ML-KEM-1024 ciphertext has the wrong size")
    return SharedSecret(Secret(_private_key(dk).decapsulate(ct), "ss"))


@dataclass(frozen=True, slots=True)
class MlKem1024:
    """ML-KEM-1024 as a :class:`~qrp2p.core.crypto.kem.KemScheme`."""

    name: str = "ML-KEM-1024"
    seed_len: int = SEED_LEN
    ek_len: int = EK_LEN
    ct_len: int = CT_LEN
    ss_len: int = SS_LEN

    def keygen(self, seed: Secret) -> tuple[Secret, bytes]:
        """See :func:`keygen`."""
        return keygen(seed)

    def encapsulate(self, ek: bytes) -> tuple[SharedSecret, bytes]:
        """See :func:`encapsulate`."""
        return encapsulate(ek)

    def decapsulate(self, dk: Secret, ct: bytes) -> SharedSecret:
        """See :func:`decapsulate`."""
        return decapsulate(dk, ct)


MLKEM1024: Final = MlKem1024()
