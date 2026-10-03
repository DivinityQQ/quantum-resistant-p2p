"""The ``LAB-CLASSICAL`` profile (``0x7F``): classical-only crypto for the solo lab (DESIGN §4).

It exists so learners can compare a classical channel with the hybrid one, e.g. in the
"harvest now, decrypt later" scenario (DESIGN §11.7, scenario 7). It MUST be refused in normal
sessions: it lives here, outside ``qrp2p.core``, and only a provider built explicitly with
:data:`LAB_PROFILES` can serve it.

```text
X25519-KEM:  ek = pkX;  ct = ctX (ephemeral public key);  ss = SHA-256(ssX ‖ ctX ‖ pkX ‖ "qrp2p2 x25519kem")
Signature:   the Ed25519 half of HybridSign alone
```
"""

import hashlib
from dataclasses import dataclass
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import x25519

from qrp2p.core.crypto.aead import AeadAlgorithm
from qrp2p.core.crypto.hybrid_sig import ED25519_SIG_LEN, Role, ed25519_message
from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.kdf import LABEL_PREFIX, SHA256
from qrp2p.core.crypto.kem import SharedSecret
from qrp2p.core.crypto.profiles import REAL_PROFILES, Profile
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

LAB_CLASSICAL_ID: Final = 0x7F
X25519_LEN: Final = 32

_KEM_LABEL: Final = LABEL_PREFIX + b"x25519kem"


def _combine(ss_x: bytes, ct_x: bytes, pk_x: bytes) -> SharedSecret:
    ss = hashlib.sha256(ss_x + ct_x + pk_x + _KEM_LABEL).digest()
    return SharedSecret(ss=Secret(ss, "ss"), components=(Secret(ss_x, "ssX"),))


@dataclass(frozen=True, slots=True)
class X25519Kem:
    """X25519 as a KEM (DESIGN §4.3); the decapsulation key is the X25519 private scalar."""

    name: str = "X25519-KEM"
    seed_len: int = X25519_LEN
    ek_len: int = X25519_LEN
    ct_len: int = X25519_LEN
    ss_len: int = 32
    ek_parts: tuple[tuple[str, int], ...] = ()
    ct_parts: tuple[tuple[str, int], ...] = ()

    def keygen(self, seed: Secret) -> tuple[Secret, bytes]:
        """Return ``(dk, ek)`` from a 32-byte seed."""
        dk = Secret(seed.reveal(), "x25519kem.dk")
        return dk, self._private_key(dk).public_key().public_bytes_raw()

    def encapsulate(self, ek: bytes) -> tuple[SharedSecret, bytes]:
        """Encapsulate to ``ek``.

        Raises:
            ProtocolError: ``invalid_kem_key`` for a wrong size; ``kem_failure`` for a low-order
                point.
        """
        if len(ek) != X25519_LEN:
            raise ProtocolError(CloseReason.INVALID_KEM_KEY, "X25519 public key has the wrong size")
        ephemeral = x25519.X25519PrivateKey.generate()
        ct = ephemeral.public_key().public_bytes_raw()
        try:
            ss_x = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(ek))
        except ValueError:
            raise ProtocolError(CloseReason.KEM_FAILURE, "X25519 low-order public key") from None
        return _combine(ss_x, ct, ek), ct

    def decapsulate(self, dk: Secret, ct: bytes) -> SharedSecret:
        """Decapsulate ``ct``.

        Raises:
            ProtocolError: ``kem_failure`` for a wrong size or a low-order point.
        """
        if len(ct) != X25519_LEN:
            raise ProtocolError(CloseReason.KEM_FAILURE, "X25519 ciphertext has the wrong size")
        private = self._private_key(dk)
        try:
            ss_x = private.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
        except ValueError:
            raise ProtocolError(CloseReason.KEM_FAILURE, "X25519 low-order ciphertext") from None
        return _combine(ss_x, ct, private.public_key().public_bytes_raw())

    @staticmethod
    def _private_key(dk: Secret) -> x25519.X25519PrivateKey:
        if len(dk) != X25519_LEN:
            raise ProtocolError(CloseReason.INTERNAL, "X25519 decapsulation key must be 32 bytes")
        return x25519.X25519PrivateKey.from_private_bytes(dk.reveal())


@dataclass(frozen=True, slots=True)
class Ed25519Only:
    """The Ed25519 half of HybridSign alone (DESIGN §4.4)."""

    name: str = "Ed25519"
    sig_len: int = ED25519_SIG_LEN

    def sign(self, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """Return the 64-byte Ed25519 signature over ``"qrp2p2 " ‖ role ‖ 0x00 ‖ th``."""
        return keys.ed25519.sign(ed25519_message(role, th))

    def verify(self, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes) -> None:
        """Verify; any failure is ``signature_invalid``."""
        if len(sig) != self.sig_len:
            raise ProtocolError(CloseReason.SIGNATURE_INVALID, "signature has the wrong size")
        try:
            bundle.ed25519_key().verify(sig, ed25519_message(role, th))
        except InvalidSignature, ValueError:
            raise ProtocolError(
                CloseReason.SIGNATURE_INVALID, "signature verification failed"
            ) from None


X25519_KEM: Final = X25519Kem()
ED25519_ONLY: Final = Ed25519Only()

LAB_CLASSICAL: Final = Profile(
    id=LAB_CLASSICAL_ID,
    name="LAB-CLASSICAL",
    kem=X25519_KEM,
    sig=ED25519_ONLY,
    aead=AeadAlgorithm.CHACHA20_POLY1305,
    hash=SHA256,
    lab_only=True,
)

LAB_PROFILES: Final[tuple[Profile, ...]] = (*REAL_PROFILES, LAB_CLASSICAL)
"""Every profile a solo-lab node may use."""
