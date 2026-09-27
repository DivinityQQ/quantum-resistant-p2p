"""X-Wing (ML-KEM-768 + X25519) per ``draft-connolly-cfrg-xwing-kem`` (DESIGN §4.2).

```text
expand(sk[32]):  e = SHAKE256(sk, 96)
                 skM = ML-KEM-768.from_seed(e[0:64]);  skX = e[64:96];  pkX = X25519(skX, base)
                 pk  = pkM[1184] ‖ pkX[32]
Encaps(pk):      (ssM, ctM) = ML-KEM-768.Encaps(pk[0:1184])
                 eX random;  ctX = X25519(eX, base);  ssX = X25519(eX, pk[1184:1216])
                 ss = SHA3-256(ssM ‖ ssX ‖ ctX ‖ pkX ‖ 0x5c2e2f2f5e5c);  ct = ctM[1088] ‖ ctX[32]
Decaps(sk, ct):  ssM = ML-KEM-768.Decaps(skM, ct[0:1088]);  ssX = X25519(skX, ct[1088:1120])
                 ss = SHA3-256(ssM ‖ ssX ‖ ct[1088:1120] ‖ pkX ‖ 0x5c2e2f2f5e5c)
```

Built from pyca/cryptography primitives (pyca's HPKE ``MLKEM768_X25519`` is X-Wing but exposes
no raw KEM API). pyca's ML-KEM encapsulation takes no caller randomness, so the ephemeral X25519
key is drawn from OpenSSL as well; replay records outputs at the provider boundary (DESIGN §11.6).
"""

import hashlib
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from qrp2p.core.crypto.kem import SharedSecret
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

SEED_LEN: Final = 32
EK_LEN: Final = 1216
CT_LEN: Final = 1120
SS_LEN: Final = 32

_MLKEM_EK_LEN: Final = 1184
_MLKEM_CT_LEN: Final = 1088
_LABEL: Final = bytes.fromhex("5c2e2f2f5e5c")  # "\./" "/^\"


def _expand(
    sk: Secret,
) -> tuple[mlkem.MLKEM768PrivateKey, x25519.X25519PrivateKey, bytes, bytes]:
    if len(sk) != SEED_LEN:
        raise ProtocolError(CloseReason.INTERNAL, "X-Wing decapsulation key must be 32 bytes")
    expanded = hashlib.shake_256(sk.reveal()).digest(96)
    sk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])
    sk_x = x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])
    return sk_m, sk_x, sk_m.public_key().public_bytes_raw(), sk_x.public_key().public_bytes_raw()


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> SharedSecret:
    ss = hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _LABEL).digest()
    return SharedSecret(
        ss=Secret(ss, "ss"),
        components=(Secret(ss_m, "ssM"), Secret(ss_x, "ssX")),
    )


def public_key(sk: Secret) -> bytes:
    """Return the 1,216-byte encapsulation key for decapsulation key ``sk``."""
    _, _, pk_m, pk_x = _expand(sk)
    return pk_m + pk_x


def keygen(seed: Secret) -> tuple[Secret, bytes]:
    """Return ``(sk, pk)``; the X-Wing decapsulation key *is* the 32-byte seed."""
    sk = Secret(seed.reveal(), "xwing.sk")
    return sk, public_key(sk)


def encapsulate(pk: bytes) -> tuple[SharedSecret, bytes]:
    """Encapsulate to ``pk``.

    Raises:
        ProtocolError: ``invalid_kem_key`` if ``pk`` has the wrong size or its ML-KEM part fails
            the FIPS 203 modulus check; ``kem_failure`` if its X25519 part is a low-order point.
    """
    if len(pk) != EK_LEN:
        raise ProtocolError(CloseReason.INVALID_KEM_KEY, "X-Wing public key has the wrong size")
    pk_m, pk_x = pk[:_MLKEM_EK_LEN], pk[_MLKEM_EK_LEN:]
    try:
        # With the size already checked, pyca's only remaining reason to reject is the FIPS 203
        # modulus check, which it reports with a misleading "wrong length" message.
        mlkem_pk = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m)
    except ValueError:
        raise ProtocolError(
            CloseReason.INVALID_KEM_KEY, "ML-KEM-768 public key fails the modulus check"
        ) from None
    ss_m, ct_m = mlkem_pk.encapsulate()
    ephemeral = x25519.X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes_raw()
    try:
        ss_x = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(pk_x))
    except ValueError:
        raise ProtocolError(CloseReason.KEM_FAILURE, "X25519 low-order public key") from None
    return _combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def decapsulate(sk: Secret, ct: bytes) -> SharedSecret:
    """Decapsulate ``ct`` with ``sk``.

    Raises:
        ProtocolError: ``kem_failure`` if ``ct`` has the wrong size or its X25519 part is a
            low-order point.
    """
    if len(ct) != CT_LEN:
        raise ProtocolError(CloseReason.KEM_FAILURE, "X-Wing ciphertext has the wrong size")
    sk_m, sk_x, _, pk_x = _expand(sk)
    ss_m = sk_m.decapsulate(ct[:_MLKEM_CT_LEN])
    ct_x = ct[_MLKEM_CT_LEN:]
    try:
        ss_x = sk_x.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
    except ValueError:
        raise ProtocolError(CloseReason.KEM_FAILURE, "X25519 low-order ciphertext") from None
    return _combine(ss_m, ss_x, ct_x, pk_x)


@dataclass(frozen=True, slots=True)
class XWing:
    """X-Wing as a :class:`~qrp2p.core.crypto.kem.KemScheme`."""

    name: str = "X-Wing"
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


XWING: Final = XWing()
