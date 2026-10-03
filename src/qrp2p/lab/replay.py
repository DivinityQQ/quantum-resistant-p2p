"""Recording and replaying a lab node's randomised crypto (DESIGN §11.6).

pyca's ML-KEM encapsulation and ML-DSA signing take no caller-supplied randomness, so a lab run
cannot be regenerated from a seed. Instead :class:`LabProvider` records, **at the provider
boundary**, every output that randomness went into:

- each draw from the random source (handshake nonces, and the seeds ephemeral key pairs are
  derived from: a key pair is recomputed from its seed on replay);
- each encapsulation, with the key it encapsulated to, its ciphertext and its secrets;
- each signature, with the role and transcript hash it signs.

Everything else (decapsulation, verification, hashes, HKDF, AEAD) is deterministic and is
recomputed. Given a recorded prefix, the provider first **replays** it: each call must ask for
what was recorded (same kind, same size, same ``ek``, same role and hash) and a recorded
signature must still verify; any difference is a :class:`ReplayDivergence` naming the entry. When
the prefix runs out it continues **live** with fresh randomness, or, for a strict replay, fails.
Its :attr:`LabProvider.log` always holds the whole run, prefix included, so a forked run can be
saved and replayed in turn.

The log holds secret values (``ss``, the seeds): it belongs to a lab run, whose values are all
revealed anyway, and is written to disk only inside a sealed recording (DESIGN §11.5).
"""

from collections.abc import Iterable, Sequence
from typing import Annotated, override

from msgspec import Meta, Struct

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.kem import SharedSecret
from qrp2p.core.crypto.profiles import Profile
from qrp2p.core.crypto.provider import PlainProvider, RandomSource
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import ProtocolError
from qrp2p.lab.trace_schema import Counter, Label


class Draw(Struct, frozen=True, tag="draw", forbid_unknown_fields=True):
    """Bytes from the random source."""

    data: Annotated[bytes, Meta(min_length=1, max_length=64)]


class Encapsulation(Struct, frozen=True, tag="encapsulation", forbid_unknown_fields=True):
    """One encapsulation: to ``ek``, giving ``ct`` and the named secrets (``ss`` last)."""

    profile: Annotated[int, Meta(ge=0, le=255)]
    epoch: Counter
    ek: Annotated[bytes, Meta(max_length=1568)]
    ct: Annotated[bytes, Meta(max_length=1568)]
    secrets: Annotated[
        list[tuple[Label, Annotated[bytes, Meta(max_length=32)]]], Meta(min_length=1, max_length=3)
    ]


class Signature(Struct, frozen=True, tag="signature", forbid_unknown_fields=True):
    """One signature by ``role`` over transcript hash ``th``."""

    profile: Annotated[int, Meta(ge=0, le=255)]
    role: Annotated[str, Meta(max_length=32)]
    th: Annotated[bytes, Meta(max_length=48)]
    sig: Annotated[bytes, Meta(max_length=4627)]


type Entry = Draw | Encapsulation | Signature


class ReplayDivergence(Exception):  # noqa: N818  # a divergence, not an error of the engine
    """The run asked for something other than what was recorded at ``index``.

    The message names the operation and what differed, never a value.
    """

    def __init__(self, index: int, detail: str) -> None:
        super().__init__(f"replay diverged at provider entry {index}: {detail}")
        self.index = index
        self.detail = detail


class LabProvider(PlainProvider):
    """A lab node's provider: records its randomised outputs, after replaying ``replay``.

    Args:
        profiles: The profiles it serves (the lab's include ``LAB-CLASSICAL``).
        random_source: Fresh randomness once ``replay`` is used up; ``None`` for a strict replay,
            where running out is a divergence.
        replay: A recorded log to replay first.
    """

    __slots__ = ("_cursor", "_live", "_replay", "log")

    def __init__(
        self,
        profiles: Iterable[Profile],
        *,
        random_source: RandomSource | None,
        replay: Sequence[Entry] = (),
    ) -> None:
        super().__init__(self._draw, profiles)
        self._live = random_source
        self._replay = tuple(replay)
        self._cursor = 0
        self.log: list[Entry] = []

    @property
    def replaying(self) -> bool:
        """Recorded entries remain to be replayed."""
        return self._cursor < len(self._replay)

    def continue_live(self, random_source: RandomSource | None) -> None:
        """Enable continuation only after the recorded prefix was consumed completely."""
        if self.replaying:
            raise ReplayDivergence(self._cursor, "unused entries at the restored boundary")
        self._live = random_source

    def _next[E: Entry](self, kind: type[E]) -> E | None:
        """The next recorded entry, which must be a ``kind``; ``None`` once running live."""
        index = self._cursor
        if index >= len(self._replay):
            if self._live is None:
                raise ReplayDivergence(index, f"{kind.__name__.lower()} after the recording ended")
            return None
        entry = self._replay[index]
        if not isinstance(entry, kind):
            got, wanted = type(entry).__name__.lower(), kind.__name__.lower()
            raise ReplayDivergence(index, f"asked for a {wanted}, the recording has a {got}")
        self._cursor += 1
        return entry

    def _draw(self, n: int) -> bytes:
        entry = self._next(Draw)
        if entry is None:
            assert self._live is not None  # noqa: S101  # _next returns None only when live
            entry = Draw(self._live(n))
        elif len(entry.data) != n:
            msg = f"asked for {n} random bytes, the recording has {len(entry.data)}"
            raise ReplayDivergence(self._cursor - 1, msg)
        self.log.append(entry)
        return entry.data

    @override
    def kem_encapsulate(
        self, profile: Profile, ek: bytes, *, epoch: int = 0
    ) -> tuple[SharedSecret, bytes]:
        """Encapsulate live, or return the recorded result for the same ``ek``."""
        self._check(profile)
        entry = self._next(Encapsulation)
        if entry is None:
            shared, ct = super().kem_encapsulate(profile, ek, epoch=epoch)
            named = [(s.label, s.reveal()) for s in (*shared.components, shared.ss)]
            self.log.append(Encapsulation(profile.id, epoch, ek, ct, named))
            return shared, ct
        index = self._cursor - 1
        if (entry.profile, entry.epoch) != (profile.id, epoch):
            raise ReplayDivergence(index, "an encapsulation for another profile or epoch")
        if entry.ek != ek:
            raise ReplayDivergence(index, "an encapsulation to a different ek")
        if not entry.secrets:
            raise ReplayDivergence(index, "an encapsulation without its shared secret")
        *components, (label, ss) = entry.secrets
        self.log.append(entry)
        shared = SharedSecret(Secret(ss, label), tuple(Secret(v, n) for n, v in components))
        return shared, entry.ct

    @override
    def sign(self, profile: Profile, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:
        """Sign live, or return the recorded signature over the same hash, if it still verifies."""
        self._check(profile)
        entry = self._next(Signature)
        if entry is None:
            sig = super().sign(profile, keys, role, th)
            self.log.append(Signature(profile.id, role.value, th, sig))
            return sig
        index = self._cursor - 1
        if (entry.profile, entry.role, entry.th) != (profile.id, role.value, th):
            raise ReplayDivergence(index, f"a {role.value} signature over a different hash")
        try:
            profile.sig.verify(keys.bundle, role, th, entry.sig)
        except ProtocolError:
            raise ReplayDivergence(index, "a recorded signature that does not verify") from None
        self.log.append(entry)
        return entry.sig
