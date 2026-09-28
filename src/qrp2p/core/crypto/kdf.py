"""Hash functions and the TLS 1.3-style key-schedule helpers (DESIGN §1, §7.4).

```text
HkdfLabel(L, label, ctx)       = u16(L) ‖ u8(len("qrp2p2 " ‖ label)) ‖ "qrp2p2 " ‖ label ‖ u8(len(ctx)) ‖ ctx
Expand-Label(S, label, ctx, L) = HKDF-Expand(S, HkdfLabel(L, label, ctx), L)
Derive-Secret(S, label, th)    = Expand-Label(S, label, th, Hlen)
Keys(S)                        = key = Expand-Label(S, "key", "", 32),  iv = Expand-Label(S, "iv", "", 12)
```

HKDF and HMAC come from pyca/cryptography; SHA-2 digests from stdlib ``hashlib``.
"""

import hashlib
import hmac
from dataclasses import dataclass
from typing import Final, Literal

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from qrp2p.core.crypto.secret import Secret

LABEL_PREFIX: Final = b"qrp2p2 "
"""The protocol's label prefix (DESIGN §1)."""

AEAD_KEY_LEN: Final = 32
AEAD_IV_LEN: Final = 12

_MAX_U8: Final = 0xFF
_MAX_U16: Final = 0xFFFF


@dataclass(frozen=True, slots=True)
class HashFunction:
    """A profile's hash ``H`` with output length ``Hlen``."""

    name: Literal["SHA-256", "SHA-384"]
    length: int

    def digest(self, data: bytes) -> bytes:
        """Return ``H(data)``."""
        if self.name == "SHA-256":
            return hashlib.sha256(data).digest()
        return hashlib.sha384(data).digest()

    def algorithm(self) -> hashes.HashAlgorithm:
        """Return the pyca algorithm object for HKDF and HMAC."""
        if self.name == "SHA-256":
            return hashes.SHA256()
        return hashes.SHA384()


SHA256: Final = HashFunction("SHA-256", 32)
SHA384: Final = HashFunction("SHA-384", 48)


@dataclass(frozen=True, slots=True)
class TrafficKeys:
    """``Keys(S)``: an AEAD key and a static IV derived from one traffic secret."""

    key: Secret
    iv: Secret


def _bytes_of(value: Secret | bytes) -> bytes:
    return value.reveal() if isinstance(value, Secret) else value


def hkdf_extract(
    h: HashFunction, salt: Secret | bytes, ikm: Secret | bytes, *, name: str
) -> Secret:
    """``HKDF-Extract(salt, ikm)`` (RFC 5869). ``salt`` and ``ikm`` may be public zero strings."""
    return Secret(HKDF.extract(h.algorithm(), _bytes_of(salt), _bytes_of(ikm)), name)


def hkdf_expand(h: HashFunction, prk: Secret, info: bytes, length: int, *, name: str) -> Secret:
    """``HKDF-Expand(prk, info, length)`` (RFC 5869).

    Raises:
        ValueError: ``prk`` is shorter than ``Hlen`` or ``length`` exceeds ``255 * Hlen``.
    """
    if len(prk) < h.length:
        msg = "HKDF-Expand needs a PRK of at least Hlen bytes"
        raise ValueError(msg)
    if not 0 < length <= 255 * h.length:
        msg = "HKDF-Expand length out of range"
        raise ValueError(msg)
    return Secret(HKDFExpand(h.algorithm(), length, info).derive(prk.reveal()), name)


def hkdf_label(length: int, label: str, context: bytes) -> bytes:
    """Encode ``HkdfLabel(L, label, ctx)``; ``label`` excludes the ``"qrp2p2 "`` prefix.

    Raises:
        ValueError: A field does not fit its length prefix, or ``label`` is not ASCII.
    """
    full_label = LABEL_PREFIX + label.encode("ascii")
    if not 0 <= length <= _MAX_U16:
        msg = "HkdfLabel length does not fit u16"
        raise ValueError(msg)
    if len(full_label) > _MAX_U8 or len(context) > _MAX_U8:
        msg = "HkdfLabel label or context does not fit u8"
        raise ValueError(msg)
    return (
        length.to_bytes(2, "big")
        + len(full_label).to_bytes(1, "big")
        + full_label
        + len(context).to_bytes(1, "big")
        + context
    )


def expand_label(
    h: HashFunction,
    secret: Secret,
    label: str,
    context: bytes,
    length: int,
    *,
    name: str | None = None,
) -> Secret:
    """``Expand-Label(S, label, ctx, L)``. The result is named ``name`` (default: ``label``)."""
    info = hkdf_label(length, label, context)
    return hkdf_expand(h, secret, info, length, name=name or label)


def derive_secret(
    h: HashFunction,
    secret: Secret,
    label: str,
    transcript_hash: bytes,
    *,
    name: str | None = None,
) -> Secret:
    """``Derive-Secret(S, label, th) = Expand-Label(S, label, th, Hlen)``."""
    return expand_label(h, secret, label, transcript_hash, h.length, name=name)


def traffic_keys(h: HashFunction, secret: Secret) -> TrafficKeys:
    """``Keys(S)``: a 32-byte AEAD key and a 12-byte IV, named after ``secret``."""
    return TrafficKeys(
        key=expand_label(h, secret, "key", b"", AEAD_KEY_LEN, name=f"{secret.label}.key"),
        iv=expand_label(h, secret, "iv", b"", AEAD_IV_LEN, name=f"{secret.label}.iv"),
    )


def hmac_digest(h: HashFunction, key: Secret, data: bytes) -> bytes:
    """``HMAC-H(key, data)`` (RFC 2104), used for Finished values (DESIGN §7.4)."""
    return hmac.digest(key.reveal(), data, "sha256" if h.name == "SHA-256" else "sha384")
