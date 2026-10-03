"""The KEM interface shared by every profile (DESIGN §4).

Decapsulation keys are held as their seed (a :class:`Secret`), so the provider can record them at
its boundary (DESIGN §11.6) and nothing else needs a key-object lifecycle.
"""

from dataclasses import dataclass
from typing import Protocol

from qrp2p.core.crypto.secret import Secret


@dataclass(frozen=True, slots=True)
class SharedSecret:
    """A KEM's shared secret ``ss`` and, for hybrids, its component secrets.

    The components (for X-Wing ``ssM`` and ``ssX``) are exposed only in glass-box and lab
    sessions (DESIGN §11.4) and by the lab's simulated quantum oracle (DESIGN §11.7, scenario 7).
    """

    ss: Secret
    components: tuple[Secret, ...] = ()


class KemScheme(Protocol):
    """A key-encapsulation mechanism with fixed sizes.

    Errors caused by peer input raise ``ProtocolError``: ``invalid_kem_key`` for a bad
    encapsulation key and ``kem_failure`` for a bad ciphertext. A malformed ciphertext of the
    right size may instead yield an unrelated shared secret (implicit rejection); the handshake
    then fails at the first AEAD check.
    """

    @property
    def name(self) -> str:
        """Human-readable algorithm name."""
        ...

    @property
    def seed_len(self) -> int:
        """Length of the decapsulation-key seed passed to :meth:`keygen`."""
        ...

    @property
    def ek_len(self) -> int:
        """Encapsulation (public) key length."""
        ...

    @property
    def ct_len(self) -> int:
        """Ciphertext length."""
        ...

    @property
    def ss_len(self) -> int:
        """Shared-secret length."""
        ...

    @property
    def ek_parts(self) -> tuple[tuple[str, int], ...]:
        """A hybrid's encapsulation key as its components' names and sizes, in order; else ``()``."""
        ...

    @property
    def ct_parts(self) -> tuple[tuple[str, int], ...]:
        """A hybrid's ciphertext as its components' names and sizes, in order; else ``()``."""
        ...

    def keygen(self, seed: Secret) -> tuple[Secret, bytes]:
        """Derive ``(dk, ek)`` deterministically from ``seed``."""
        ...

    def encapsulate(self, ek: bytes) -> tuple[SharedSecret, bytes]:
        """Return ``(shared secret, ciphertext)`` for the peer's ``ek``."""
        ...

    def decapsulate(self, dk: Secret, ct: bytes) -> SharedSecret:
        """Recover the shared secret from ``ct`` with our ``dk``."""
        ...
