"""Shared test helpers."""

import hashlib

from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.secret import Secret


class DeterministicRandom:
    """A reproducible random source: SHAKE-256 over a label and a counter. Tests only."""

    def __init__(self, label: str) -> None:
        self._label = label.encode()
        self._counter = 0

    def __call__(self, n: int) -> bytes:
        self._counter += 1
        return hashlib.shake_256(self._label + self._counter.to_bytes(8, "big")).digest(n)


def identity_from_label(label: str) -> IdentityKeyPair:
    """A reproducible identity for tests."""
    rng = DeterministicRandom(f"identity:{label}")
    return IdentityKeyPair(
        Secret(rng(32), "identity.ed25519"),
        Secret(rng(32), "identity.mldsa65"),
        Secret(rng(32), "identity.mldsa87"),
    )
