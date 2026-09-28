"""Cryptographic profiles and protocol constants (DESIGN §4, Appendix A).

A profile fixes every algorithm of a session; there is no per-algorithm negotiation. This module
defines the two real profiles. ``LAB-CLASSICAL`` (``0x7F``) is defined in ``qrp2p.lab.classical``
and is unreachable from here by construction.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from qrp2p.core.crypto.aead import TAG_LEN, AeadAlgorithm
from qrp2p.core.crypto.hybrid_sig import HYBRID_ED25519_MLDSA65, MLDSA87, SignatureScheme
from qrp2p.core.crypto.identity import BUNDLE_LEN
from qrp2p.core.crypto.kdf import SHA256, SHA384, HashFunction
from qrp2p.core.crypto.kem import KemScheme
from qrp2p.core.crypto.mlkem1024 import MLKEM1024
from qrp2p.core.crypto.xwing import XWING

NONCE_LEN: Final = 32
"""``nonce_I`` and ``nonce_R`` (DESIGN §7.2)."""
FRAME_HEADER_LEN: Final = 5
"""``length:u32 ‖ type:u8`` (DESIGN §6.3)."""
MAX_FRAME_BODY: Final = 16_448
MAX_RECORD_PLAINTEXT: Final = 16_384
DEFAULT_PORT: Final = 47_470

_HELLO_FIXED_LEN: Final = 3 + NONCE_LEN  # version, profile, flags, nonce_I
_ADMIT_BODY_LEN: Final = 3  # decision, flags, reason


class ProfileId(IntEnum):
    """Wire IDs of the real profiles (DESIGN §4)."""

    HYBRID_1 = 0x01
    PQ_CNSA_1 = 0x02


@dataclass(frozen=True, slots=True, kw_only=True)
class Profile:
    """Every algorithm of a session, and the message sizes that follow from them."""

    id: int
    name: str
    kem: KemScheme
    sig: SignatureScheme
    aead: AeadAlgorithm
    hash: HashFunction
    lab_only: bool = False

    @property
    def ek_len(self) -> int:
        """KEM encapsulation key length."""
        return self.kem.ek_len

    @property
    def ct_len(self) -> int:
        """KEM ciphertext length."""
        return self.kem.ct_len

    @property
    def sig_len(self) -> int:
        """Identity signature length."""
        return self.sig.sig_len

    @property
    def hash_len(self) -> int:
        """``Hlen``."""
        return self.hash.length

    @property
    def hello_body_len(self) -> int:
        """``version ‖ profile ‖ flags ‖ nonce_I ‖ ek_I``."""
        return _HELLO_FIXED_LEN + self.ek_len

    @property
    def signed_inner_len(self) -> int:
        """ReplyInner and ConfirmInner: ``Id ‖ Sig ‖ Fin``."""
        return BUNDLE_LEN + self.sig_len + self.hash_len

    @property
    def reply_body_len(self) -> int:
        """``nonce_R ‖ ct ‖ AEAD(ReplyInner)``."""
        return NONCE_LEN + self.ct_len + self.signed_inner_len + TAG_LEN

    @property
    def confirm_body_len(self) -> int:
        """``AEAD(ConfirmInner)``."""
        return self.signed_inner_len + TAG_LEN

    @property
    def admit_body_len(self) -> int:
        """``AEAD(AdmitBody ‖ FinA)``."""
        return _ADMIT_BODY_LEN + self.hash_len + TAG_LEN

    @property
    def handshake_total_len(self) -> int:
        """All four handshake frames including their 5-byte headers."""
        bodies = (
            self.hello_body_len + self.reply_body_len + self.confirm_body_len + self.admit_body_len
        )
        return bodies + 4 * FRAME_HEADER_LEN


HYBRID_1: Final = Profile(
    id=ProfileId.HYBRID_1,
    name="HYBRID-1",
    kem=XWING,
    sig=HYBRID_ED25519_MLDSA65,
    aead=AeadAlgorithm.CHACHA20_POLY1305,
    hash=SHA256,
)

PQ_CNSA_1: Final = Profile(
    id=ProfileId.PQ_CNSA_1,
    name="PQ-CNSA-1",
    kem=MLKEM1024,
    sig=MLDSA87,
    aead=AeadAlgorithm.AES_256_GCM,
    hash=SHA384,
)

REAL_PROFILES: Final[tuple[Profile, ...]] = (HYBRID_1, PQ_CNSA_1)
"""The profiles a real session may use. ``HYBRID-1`` is the default."""
