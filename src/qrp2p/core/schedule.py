"""The key schedule (DESIGN §7.4, §8.4), as functions of the shared secret and transcript hashes.

```text
hs         = HKDF-Extract(salt = 0^Hlen, ikm = ss)
hs_R, hs_I = Derive-Secret(hs, "r hs traffic" | "i hs traffic", th_hello)
fk_R, fk_I = Expand-Label(hs_R | hs_I, "finished", "", Hlen)
cs_0       = HKDF-Extract(salt = Derive-Secret(hs, "derived", H("")), ikm = 0^Hlen)
cs_{n+1}   = HKDF-Extract(salt = Derive-Secret(cs_n, "derived", H("")), ikm = ss')
ap_I, ap_R = Derive-Secret(cs, "i ap traffic" | "r ap traffic", th)     th = th_final | th_rekey
exporter   = Derive-Secret(cs, "exporter", th)
ap'        = Expand-Label(ap, "traffic upd", "", Hlen)                   KeyUpdate
rekey_salt = Derive-Secret(cs, "derived", H(""))                         retain instead of cs
```

Every step goes through the session's :class:`~qrp2p.core.crypto.provider.CryptoProvider`, so a
glass-box or lab session can reveal each value and normal sessions cannot.
"""

from dataclasses import dataclass

from qrp2p.core.crypto.kdf import TrafficKeys
from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.crypto.provider import CryptoProvider
from qrp2p.core.crypto.secret import Secret


@dataclass(frozen=True, slots=True)
class HandshakeSecrets:
    """Everything derived from ``ss`` and ``th_hello``."""

    hs: Secret
    hs_r: Secret
    hs_i: Secret
    fk_r: Secret
    fk_i: Secret
    keys_r: TrafficKeys
    keys_i: TrafficKeys

    def all(self) -> tuple[Secret, ...]:
        """Every secret, for tracing labels and sizes."""
        return (
            self.hs,
            self.hs_r,
            self.hs_i,
            self.fk_r,
            self.fk_i,
            self.keys_r.key,
            self.keys_r.iv,
            self.keys_i.key,
            self.keys_i.iv,
        )


@dataclass(frozen=True, slots=True)
class EpochState:
    """Retained rekey state; neither secret can reconstruct this epoch's traffic keys."""

    epoch: int
    rekey_salt: Secret
    exporter: Secret


@dataclass(frozen=True, slots=True)
class EpochSecrets:
    """Temporary derivation results, consumed when installing directional traffic state."""

    epoch: int
    cs: Secret
    ap_i: Secret
    ap_r: Secret
    exporter: Secret
    rekey_salt: Secret

    def retained(self) -> EpochState:
        """Discard the root and traffic-secret references from retained epoch state."""
        return EpochState(self.epoch, self.rekey_salt, self.exporter)

    def all(self) -> tuple[Secret, ...]:
        """Every secret, for tracing labels and sizes."""
        return (self.cs, self.ap_i, self.ap_r, self.exporter, self.rekey_salt)


def handshake_secrets(
    provider: CryptoProvider, profile: Profile, ss: Secret, th_hello: bytes
) -> HandshakeSecrets:
    """Derive the handshake secrets."""
    zero = bytes(profile.hash_len)
    hs = provider.extract(profile, zero, ss, name="hs")
    hs_r = provider.derive_secret(profile, hs, "r hs traffic", th_hello, name="hs_R")
    hs_i = provider.derive_secret(profile, hs, "i hs traffic", th_hello, name="hs_I")
    fk_r = provider.expand_label(profile, hs_r, "finished", b"", profile.hash_len, name="fk_R")
    fk_i = provider.expand_label(profile, hs_i, "finished", b"", profile.hash_len, name="fk_I")
    return HandshakeSecrets(
        hs=hs,
        hs_r=hs_r,
        hs_i=hs_i,
        fk_r=fk_r,
        fk_i=fk_i,
        keys_r=provider.traffic_keys(profile, hs_r),
        keys_i=provider.traffic_keys(profile, hs_i),
    )


def _epoch(
    provider: CryptoProvider, profile: Profile, epoch: int, cs: Secret, th: bytes
) -> EpochSecrets:
    return EpochSecrets(
        epoch=epoch,
        cs=cs,
        ap_i=provider.derive_secret(profile, cs, "i ap traffic", th, name=f"ap_I[{epoch}]"),
        ap_r=provider.derive_secret(profile, cs, "r ap traffic", th, name=f"ap_R[{epoch}]"),
        exporter=provider.derive_secret(profile, cs, "exporter", th, name=f"exporter_{epoch}"),
        rekey_salt=_derived(provider, profile, cs, epoch + 1),
    )


def _derived(provider: CryptoProvider, profile: Profile, secret: Secret, epoch: int) -> Secret:
    empty_hash = profile.hash.digest(b"")
    return provider.derive_secret(profile, secret, "derived", empty_hash, name=f"derived[{epoch}]")


def first_epoch(
    provider: CryptoProvider, profile: Profile, hs: Secret, th_final: bytes
) -> tuple[Secret, EpochSecrets]:
    """Derive epoch 0 from the handshake secret and ``th_final``.

    Returns the salt ``cs_0`` was extracted with (``derived[0]``) as well, so the handshake can
    report it; like ``cs_0`` it is a derivation input, never retained.
    """
    salt = _derived(provider, profile, hs, 0)
    cs = provider.extract(profile, salt, bytes(profile.hash_len), name="cs_0")
    return salt, _epoch(provider, profile, 0, cs, th_final)


def next_epoch(
    provider: CryptoProvider, profile: Profile, current: EpochState, ss: Secret, th_rekey: bytes
) -> EpochSecrets:
    """Derive epoch ``n+1`` from the precomputed salt and the rekey's shared secret ``ss'``."""
    n = current.epoch + 1
    cs = provider.extract(profile, current.rekey_salt, ss, name=f"cs_{n}")
    return _epoch(provider, profile, n, cs, th_rekey)


def updated_traffic_secret(provider: CryptoProvider, profile: Profile, ap: Secret) -> Secret:
    """KeyUpdate: ``ap' = Expand-Label(ap, "traffic upd", "", Hlen)``."""
    base, _, generation = ap.label.partition("+")
    name = f"{base}+{int(generation or 0) + 1}"
    return provider.expand_label(profile, ap, "traffic upd", b"", profile.hash_len, name=name)
