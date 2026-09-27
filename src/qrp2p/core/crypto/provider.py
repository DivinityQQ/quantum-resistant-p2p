"""The crypto provider: the one boundary between the protocol core and cryptography (DESIGN §11).

The protocol engine performs every operation that creates or uses key material through a
:class:`CryptoProvider`. That gives the learning layer two structural guarantees:

- **Containment (DESIGN §11.3).** :class:`PlainProvider`, used by normal sessions, has no path from
  secret values to anything outside the engine. Only :class:`RevealingProvider`, installed for
  glass-box and lab sessions, forwards secrets to a sink.
- **Replay (DESIGN §11.6).** Randomised outputs (generated keys, encapsulations, signatures,
  nonces) all pass this boundary, so a recording provider can log them and a replay provider can
  feed them back. Both arrive with recordings in M4; their shape follows the ``.qrlab`` format.

A provider serves only the profiles it was built with. ``LAB-CLASSICAL`` is therefore
unreachable from a provider built with :data:`~qrp2p.core.crypto.profiles.REAL_PROFILES`.
"""

from collections.abc import Callable, Iterable
from typing import Protocol, override

from qrp2p.core.crypto import aead, kdf
from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.kdf import TrafficKeys
from qrp2p.core.crypto.kem import SharedSecret
from qrp2p.core.crypto.profiles import REAL_PROFILES, Profile
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import CloseReason, ProtocolError

type RandomSource = Callable[[int], bytes]
"""Injected randomness: returns ``n`` uniformly random bytes (``os.urandom`` in production)."""

type SecretSink = Callable[[Secret], None]
"""Where :class:`RevealingProvider` sends secrets (the glass-box buffer and trace bus in M4)."""


class CryptoProvider(Protocol):
    """Every cryptographic operation the protocol engine performs, per profile."""

    def random(self, n: int) -> bytes:
        """Return ``n`` random bytes for public values such as handshake nonces."""
        ...

    def kem_keygen(self, profile: Profile) -> tuple[Secret, bytes]:
        """Generate an ephemeral KEM key pair ``(dk, ek)``."""
        ...

    def kem_encapsulate(self, profile: Profile, ek: bytes) -> tuple[SharedSecret, bytes]:
        """Encapsulate to the peer's ``ek``; returns ``(shared secret, ct)``."""
        ...

    def kem_decapsulate(self, profile: Profile, dk: Secret, ct: bytes) -> SharedSecret:
        """Decapsulate ``ct`` with our ``dk``."""
        ...

    def sign(self, profile: Profile, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """Sign transcript hash ``th`` for ``role``."""
        ...

    def verify(
        self, profile: Profile, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes
    ) -> None:
        """Verify a peer's signature; raise ``ProtocolError(signature_invalid)`` on failure."""
        ...

    def extract(
        self, profile: Profile, salt: Secret | bytes, ikm: Secret | bytes, *, name: str
    ) -> Secret:
        """``HKDF-Extract`` with the profile hash."""
        ...

    def expand_label(
        self,
        profile: Profile,
        secret: Secret,
        label: str,
        context: bytes,
        length: int,
        *,
        name: str | None = None,
    ) -> Secret:
        """``Expand-Label`` with the profile hash."""
        ...

    def derive_secret(
        self, profile: Profile, secret: Secret, label: str, th: bytes, *, name: str | None = None
    ) -> Secret:
        """``Derive-Secret`` with the profile hash."""
        ...

    def traffic_keys(self, profile: Profile, secret: Secret) -> TrafficKeys:
        """``Keys(S)``."""
        ...

    def hmac(self, profile: Profile, key: Secret, data: bytes) -> bytes:
        """``HMAC-H(key, data)``."""
        ...

    def seal(
        self, profile: Profile, keys: TrafficKeys, seq: int, aad: bytes, plaintext: bytes
    ) -> bytes:
        """AEAD-encrypt with the profile AEAD and nonce ``iv XOR u96(seq)``."""
        ...

    def unseal(
        self, profile: Profile, keys: TrafficKeys, seq: int, aad: bytes, ciphertext: bytes
    ) -> bytes:
        """AEAD-decrypt; raise ``ProtocolError(decrypt_failed)`` on failure."""
        ...


class PlainProvider:
    """The provider for normal sessions: computes, and emits nothing.

    Args:
        random_source: Injected randomness, e.g. ``os.urandom``.
        profiles: The profiles this provider may serve. Anything else is refused with
            ``policy``. Defaults to the real profiles.
    """

    __slots__ = ("_profiles", "_random")

    def __init__(
        self, random_source: RandomSource, profiles: Iterable[Profile] = REAL_PROFILES
    ) -> None:
        self._random = random_source
        self._profiles = {p.id: p for p in profiles}

    def _check(self, profile: Profile) -> None:
        if self._profiles.get(profile.id) is not profile:
            raise ProtocolError(CloseReason.POLICY, "profile not enabled for this provider")

    def random(self, n: int) -> bytes:
        """See :meth:`CryptoProvider.random`."""
        data = self._random(n)
        if len(data) != n:
            raise ProtocolError(CloseReason.INTERNAL, "random source returned the wrong length")
        return data

    def kem_keygen(self, profile: Profile) -> tuple[Secret, bytes]:
        """See :meth:`CryptoProvider.kem_keygen`."""
        self._check(profile)
        seed = Secret(self.random(profile.kem.seed_len), "kem.seed")
        return profile.kem.keygen(seed)

    def kem_encapsulate(self, profile: Profile, ek: bytes) -> tuple[SharedSecret, bytes]:
        """See :meth:`CryptoProvider.kem_encapsulate`."""
        self._check(profile)
        return profile.kem.encapsulate(ek)

    def kem_decapsulate(self, profile: Profile, dk: Secret, ct: bytes) -> SharedSecret:
        """See :meth:`CryptoProvider.kem_decapsulate`."""
        self._check(profile)
        return profile.kem.decapsulate(dk, ct)

    def sign(self, profile: Profile, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """See :meth:`CryptoProvider.sign`."""
        self._check(profile)
        return profile.sig.sign(keys, role, th)

    def verify(
        self, profile: Profile, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes
    ) -> None:
        """See :meth:`CryptoProvider.verify`."""
        self._check(profile)
        profile.sig.verify(bundle, role, th, sig)

    def extract(
        self, profile: Profile, salt: Secret | bytes, ikm: Secret | bytes, *, name: str
    ) -> Secret:
        """See :meth:`CryptoProvider.extract`."""
        self._check(profile)
        return kdf.hkdf_extract(profile.hash, salt, ikm, name=name)

    def expand_label(
        self,
        profile: Profile,
        secret: Secret,
        label: str,
        context: bytes,
        length: int,
        *,
        name: str | None = None,
    ) -> Secret:
        """See :meth:`CryptoProvider.expand_label`."""
        self._check(profile)
        return kdf.expand_label(profile.hash, secret, label, context, length, name=name)

    def derive_secret(
        self, profile: Profile, secret: Secret, label: str, th: bytes, *, name: str | None = None
    ) -> Secret:
        """See :meth:`CryptoProvider.derive_secret`."""
        self._check(profile)
        return kdf.derive_secret(profile.hash, secret, label, th, name=name)

    def traffic_keys(self, profile: Profile, secret: Secret) -> TrafficKeys:
        """See :meth:`CryptoProvider.traffic_keys`."""
        self._check(profile)
        return kdf.traffic_keys(profile.hash, secret)

    def hmac(self, profile: Profile, key: Secret, data: bytes) -> bytes:
        """See :meth:`CryptoProvider.hmac`."""
        self._check(profile)
        return kdf.hmac_digest(profile.hash, key, data)

    def seal(
        self, profile: Profile, keys: TrafficKeys, seq: int, aad: bytes, plaintext: bytes
    ) -> bytes:
        """See :meth:`CryptoProvider.seal`."""
        self._check(profile)
        return aead.seal(profile.aead, keys, seq, aad, plaintext)

    def unseal(
        self, profile: Profile, keys: TrafficKeys, seq: int, aad: bytes, ciphertext: bytes
    ) -> bytes:
        """See :meth:`CryptoProvider.unseal`."""
        self._check(profile)
        return aead.unseal(profile.aead, keys, seq, aad, ciphertext)


class RevealingProvider:
    """Glass-box and lab sessions only: delegates to ``inner`` and sends every secret to ``sink``.

    It reveals KEM secrets (including hybrid components), every derived secret and traffic keys
    (DESIGN §11.4). Identity private keys never pass through a provider and so are never revealed.
    Per-record nonces and plaintexts, and the bounded pre-admission buffer, arrive with the
    Inspector in M4.

    Args:
        inner: The provider that does the work, normally a :class:`PlainProvider`.
        sink: Receives each secret as it is produced.
    """

    __slots__ = ("_inner", "_sink")

    def __init__(self, inner: CryptoProvider, sink: SecretSink) -> None:
        self._inner = inner
        self._sink = sink

    def _emit(self, *secrets: Secret) -> None:
        for secret in secrets:
            self._sink(secret)

    def _emit_shared(self, shared: SharedSecret) -> None:
        self._emit(*shared.components, shared.ss)

    def random(self, n: int) -> bytes:
        """See :meth:`CryptoProvider.random`."""
        return self._inner.random(n)

    def kem_keygen(self, profile: Profile) -> tuple[Secret, bytes]:
        """See :meth:`CryptoProvider.kem_keygen`."""
        dk, ek = self._inner.kem_keygen(profile)
        self._emit(dk)
        return dk, ek

    def kem_encapsulate(self, profile: Profile, ek: bytes) -> tuple[SharedSecret, bytes]:
        """See :meth:`CryptoProvider.kem_encapsulate`."""
        shared, ct = self._inner.kem_encapsulate(profile, ek)
        self._emit_shared(shared)
        return shared, ct

    def kem_decapsulate(self, profile: Profile, dk: Secret, ct: bytes) -> SharedSecret:
        """See :meth:`CryptoProvider.kem_decapsulate`."""
        shared = self._inner.kem_decapsulate(profile, dk, ct)
        self._emit_shared(shared)
        return shared

    def sign(self, profile: Profile, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """See :meth:`CryptoProvider.sign`."""
        return self._inner.sign(profile, keys, role, th)

    def verify(
        self, profile: Profile, bundle: IdentityBundle, role: Role, th: bytes, sig: bytes
    ) -> None:
        """See :meth:`CryptoProvider.verify`."""
        self._inner.verify(profile, bundle, role, th, sig)

    def extract(
        self, profile: Profile, salt: Secret | bytes, ikm: Secret | bytes, *, name: str
    ) -> Secret:
        """See :meth:`CryptoProvider.extract`."""
        out = self._inner.extract(profile, salt, ikm, name=name)
        self._emit(out)
        return out

    def expand_label(
        self,
        profile: Profile,
        secret: Secret,
        label: str,
        context: bytes,
        length: int,
        *,
        name: str | None = None,
    ) -> Secret:
        """See :meth:`CryptoProvider.expand_label`."""
        out = self._inner.expand_label(profile, secret, label, context, length, name=name)
        self._emit(out)
        return out

    def derive_secret(
        self, profile: Profile, secret: Secret, label: str, th: bytes, *, name: str | None = None
    ) -> Secret:
        """See :meth:`CryptoProvider.derive_secret`."""
        out = self._inner.derive_secret(profile, secret, label, th, name=name)
        self._emit(out)
        return out

    def traffic_keys(self, profile: Profile, secret: Secret) -> TrafficKeys:
        """See :meth:`CryptoProvider.traffic_keys`."""
        keys = self._inner.traffic_keys(profile, secret)
        self._emit(keys.key, keys.iv)
        return keys

    def hmac(self, profile: Profile, key: Secret, data: bytes) -> bytes:
        """See :meth:`CryptoProvider.hmac`."""
        return self._inner.hmac(profile, key, data)

    def seal(
        self, profile: Profile, keys: TrafficKeys, seq: int, aad: bytes, plaintext: bytes
    ) -> bytes:
        """See :meth:`CryptoProvider.seal`."""
        return self._inner.seal(profile, keys, seq, aad, plaintext)

    def unseal(
        self, profile: Profile, keys: TrafficKeys, seq: int, aad: bytes, ciphertext: bytes
    ) -> bytes:
        """See :meth:`CryptoProvider.unseal`."""
        return self._inner.unseal(profile, keys, seq, aad, ciphertext)

    @override
    def __repr__(self) -> str:
        return f"RevealingProvider({self._inner!r})"
