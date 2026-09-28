"""Handshake and rekey signatures (DESIGN §4.4).

```text
ed_msg = "qrp2p2 " ‖ role ‖ 0x00 ‖ th
sig    = Ed25519.Sign(sk_ed, ed_msg)[64] ‖ ML-DSA-65.Sign(sk_ml65, th, context = "qrp2p2 " ‖ role)[3309]
```

``PQ-CNSA-1`` uses ML-DSA-87 alone with the same context. The Ed25519-only scheme of
``LAB-CLASSICAL`` lives in ``qrp2p.lab.classical``. Roles are distinct, so a signature can never be
replayed across roles or protocols. ML-DSA signing in pyca is hedged, so signatures are not
reproducible.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from cryptography.exceptions import InvalidSignature

from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.kdf import LABEL_PREFIX
from qrp2p.core.errors import CloseReason, ProtocolError

ED25519_SIG_LEN: Final = 64
MLDSA65_SIG_LEN: Final = 3309
MLDSA87_SIG_LEN: Final = 4627


class Role(StrEnum):
    """Who signs, and for which step. Part of every signed message."""

    RESPONDER = "responder"
    INITIATOR = "initiator"
    REKEY_ANSWER = "rekey-answer"
    REKEY_FINISH = "rekey-finish"


def signature_context(role: Role) -> bytes:
    """The ML-DSA context string ``"qrp2p2 " ‖ role``."""
    return LABEL_PREFIX + role.value.encode("ascii")


def ed25519_message(role: Role, th: bytes) -> bytes:
    """The Ed25519 message ``"qrp2p2 " ‖ role ‖ 0x00 ‖ th``."""
    return signature_context(role) + b"\x00" + th


class SignatureScheme(Protocol):
    """A profile's identity signature over a transcript hash ``th``."""

    @property
    def name(self) -> str:
        """Human-readable scheme name."""
        ...

    @property
    def sig_len(self) -> int:
        """Exact signature length."""
        ...

    def sign(self, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """Sign ``th`` for ``role`` with our identity."""
        ...

    def verify(self, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes) -> None:
        """Verify ``sig``; raise ``ProtocolError(signature_invalid)`` on any failure."""
        ...


def _invalid() -> ProtocolError:
    return ProtocolError(CloseReason.SIGNATURE_INVALID, "signature verification failed")


@dataclass(frozen=True, slots=True)
class HybridEd25519MlDsa65:
    """``HYBRID-1``: Ed25519 and ML-DSA-65; both halves must verify."""

    name: str = "Ed25519 + ML-DSA-65"
    sig_len: int = ED25519_SIG_LEN + MLDSA65_SIG_LEN

    def sign(self, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """Return ``Ed25519 sig[64] ‖ ML-DSA-65 sig[3309]``."""
        ed_sig = keys.ed25519.sign(ed25519_message(role, th))
        ml_sig = keys.mldsa65.sign(th, signature_context(role))
        return ed_sig + ml_sig

    def verify(self, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes) -> None:
        """Verify both halves; failure of either is ``signature_invalid``."""
        if len(sig) != self.sig_len:
            raise _invalid()
        ed_sig, ml_sig = sig[:ED25519_SIG_LEN], sig[ED25519_SIG_LEN:]
        try:
            bundle.ed25519_key().verify(ed_sig, ed25519_message(role, th))
            bundle.mldsa65_key().verify(ml_sig, th, signature_context(role))
        except InvalidSignature, ValueError:
            raise _invalid() from None


@dataclass(frozen=True, slots=True)
class MlDsa87:
    """``PQ-CNSA-1``: ML-DSA-87 alone (CNSA 2.0)."""

    name: str = "ML-DSA-87"
    sig_len: int = MLDSA87_SIG_LEN

    def sign(self, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """Return the 4,627-byte ML-DSA-87 signature."""
        return keys.mldsa87.sign(th, signature_context(role))

    def verify(self, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes) -> None:
        """Verify; any failure is ``signature_invalid``."""
        if len(sig) != self.sig_len:
            raise _invalid()
        try:
            bundle.mldsa87_key().verify(sig, th, signature_context(role))
        except InvalidSignature, ValueError:
            raise _invalid() from None


HYBRID_ED25519_MLDSA65: Final = HybridEd25519MlDsa65()
MLDSA87: Final = MlDsa87()
