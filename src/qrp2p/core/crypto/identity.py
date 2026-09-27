"""Identity bundles, peer IDs and safety numbers (DESIGN §5.1, §5.2).

```text
IdentityBundle = version:u8 (=0x01) ‖ ed25519_pk[32] ‖ mldsa65_pk[1952] ‖ mldsa87_pk[2592]     # 4,577 B
peer_id        = SHA-384("qrp2p2 identity" ‖ IdentityBundle)                                  # 48 B
short_id       = Base32(peer_id[0:5])  →  8 characters, shown as XXXX-XXXX
digits(p)      = for i in 0..5:  u40(SHAKE256("qrp2p2 safety" ‖ peer_id_p, 30)[5i : 5i+5]) mod 100000
safety         = digits(lower peer_id) ‖ digits(higher peer_id)
```

One bundle per installation, shared by all profiles. Private keys are held as 32-byte seeds.
"""

import base64
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, NoReturn, Self, override

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from qrp2p.core.crypto.kdf import LABEL_PREFIX
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

BUNDLE_VERSION: Final = 0x01
ED25519_PK_LEN: Final = 32
MLDSA65_PK_LEN: Final = 1952
MLDSA87_PK_LEN: Final = 2592
BUNDLE_LEN: Final = 1 + ED25519_PK_LEN + MLDSA65_PK_LEN + MLDSA87_PK_LEN
PEER_ID_LEN: Final = 48
SEED_LEN: Final = 32

_SAFETY_GROUPS: Final = 6
_SAFETY_GROUP_BYTES: Final = 5
_SAFETY_MODULUS: Final = 100_000


@dataclass(frozen=True, slots=True)
class IdentityBundle:
    """One installation's long-term public keys, in the exact bytes of DESIGN §5.1."""

    ed25519: bytes
    mldsa65: bytes
    mldsa87: bytes

    def __post_init__(self) -> None:
        if (len(self.ed25519), len(self.mldsa65), len(self.mldsa87)) != (
            ED25519_PK_LEN,
            MLDSA65_PK_LEN,
            MLDSA87_PK_LEN,
        ):
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "identity key has the wrong size")

    def encode(self) -> bytes:
        """Return the 4,577-byte wire encoding."""
        return bytes([BUNDLE_VERSION]) + self.ed25519 + self.mldsa65 + self.mldsa87

    @classmethod
    def decode(cls, data: bytes) -> Self:
        """Parse and validate a bundle received from a peer.

        Raises:
            ProtocolError: ``schema_error`` for a wrong size, an unknown version or a public key
                that pyca refuses to load.
        """
        if len(data) != BUNDLE_LEN:
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "identity bundle has the wrong size")
        if data[0] != BUNDLE_VERSION:
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "unknown identity bundle version")
        a = 1 + ED25519_PK_LEN
        b = a + MLDSA65_PK_LEN
        bundle = cls(ed25519=data[1:a], mldsa65=data[a:b], mldsa87=data[b:])
        try:
            bundle.ed25519_key()
            bundle.mldsa65_key()
            bundle.mldsa87_key()
        except ValueError:
            raise ProtocolError(CloseReason.SCHEMA_ERROR, "invalid identity public key") from None
        return bundle

    def ed25519_key(self) -> ed25519.Ed25519PublicKey:
        """The Ed25519 public key as a pyca object."""
        return ed25519.Ed25519PublicKey.from_public_bytes(self.ed25519)

    def mldsa65_key(self) -> mldsa.MLDSA65PublicKey:
        """The ML-DSA-65 public key as a pyca object."""
        return mldsa.MLDSA65PublicKey.from_public_bytes(self.mldsa65)

    def mldsa87_key(self) -> mldsa.MLDSA87PublicKey:
        """The ML-DSA-87 public key as a pyca object."""
        return mldsa.MLDSA87PublicKey.from_public_bytes(self.mldsa87)

    @property
    def peer_id(self) -> bytes:
        """``SHA-384("qrp2p2 identity" ‖ IdentityBundle)`` over the exact bundle bytes."""
        return peer_id(self.encode())

    @property
    def short_id(self) -> str:
        """The 8-character short ID, formatted ``XXXX-XXXX``."""
        return short_id(self.peer_id)


def peer_id(bundle_bytes: bytes) -> bytes:
    """Return the 48-byte peer ID of an encoded bundle."""
    return hashlib.sha384(LABEL_PREFIX + b"identity" + bundle_bytes).digest()


def short_id(pid: bytes) -> str:
    """Return ``Base32(peer_id[0:5])`` formatted as ``XXXX-XXXX``."""
    text = base64.b32encode(pid[:5]).decode("ascii")
    return f"{text[:4]}-{text[4:]}"


def _safety_digits(pid: bytes) -> tuple[str, ...]:
    stream = hashlib.shake_256(LABEL_PREFIX + b"safety" + pid).digest(
        _SAFETY_GROUPS * _SAFETY_GROUP_BYTES
    )
    return tuple(
        f"{int.from_bytes(stream[i : i + _SAFETY_GROUP_BYTES], 'big') % _SAFETY_MODULUS:05d}"
        for i in range(0, len(stream), _SAFETY_GROUP_BYTES)
    )


def safety_number(pid_a: bytes, pid_b: bytes) -> tuple[str, ...]:
    """Return the 60-digit safety number as 12 groups of 5 digits, the same on both sides.

    Raises:
        ValueError: A peer ID is not 48 bytes.
    """
    if len(pid_a) != PEER_ID_LEN or len(pid_b) != PEER_ID_LEN:
        msg = "peer IDs must be 48 bytes"
        raise ValueError(msg)
    low, high = sorted((pid_a, pid_b))
    return _safety_digits(low) + _safety_digits(high)


class IdentityKeyPair:
    """Our own identity: three private keys held as seeds, and the matching bundle.

    Identity private keys are never exposed, not even in glass-box sessions (DESIGN §11.4).
    """

    __slots__ = ("_bundle", "_ed25519", "_mldsa65", "_mldsa87", "_seeds")

    def __init__(self, ed25519_seed: Secret, mldsa65_seed: Secret, mldsa87_seed: Secret) -> None:
        seeds = (ed25519_seed, mldsa65_seed, mldsa87_seed)
        if any(len(seed) != SEED_LEN for seed in seeds):
            msg = "identity seeds must be 32 bytes each"
            raise ValueError(msg)
        self._seeds = seeds
        self._ed25519 = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed.reveal())
        self._mldsa65 = mldsa.MLDSA65PrivateKey.from_seed_bytes(mldsa65_seed.reveal())
        self._mldsa87 = mldsa.MLDSA87PrivateKey.from_seed_bytes(mldsa87_seed.reveal())
        self._bundle = IdentityBundle(
            ed25519=self._ed25519.public_key().public_bytes_raw(),
            mldsa65=self._mldsa65.public_key().public_bytes_raw(),
            mldsa87=self._mldsa87.public_key().public_bytes_raw(),
        )

    @classmethod
    def generate(cls, random_bytes: Callable[[int], bytes]) -> Self:
        """Create a new identity from injected randomness."""
        return cls(
            Secret(random_bytes(SEED_LEN), "identity.ed25519"),
            Secret(random_bytes(SEED_LEN), "identity.mldsa65"),
            Secret(random_bytes(SEED_LEN), "identity.mldsa87"),
        )

    @property
    def seeds(self) -> tuple[Secret, Secret, Secret]:
        """The Ed25519, ML-DSA-65 and ML-DSA-87 seeds, for the vault (DESIGN §10)."""
        return self._seeds

    @property
    def bundle(self) -> IdentityBundle:
        """The public identity bundle."""
        return self._bundle

    @property
    def ed25519(self) -> ed25519.Ed25519PrivateKey:
        """The Ed25519 signing key."""
        return self._ed25519

    @property
    def mldsa65(self) -> mldsa.MLDSA65PrivateKey:
        """The ML-DSA-65 signing key."""
        return self._mldsa65

    @property
    def mldsa87(self) -> mldsa.MLDSA87PrivateKey:
        """The ML-DSA-87 signing key."""
        return self._mldsa87

    @override
    def __repr__(self) -> str:
        return f"IdentityKeyPair({self._bundle.short_id}, private keys redacted)"

    @override
    def __reduce_ex__(self, protocol: object) -> NoReturn:
        msg = "IdentityKeyPair cannot be pickled or copied"
        raise TypeError(msg)
