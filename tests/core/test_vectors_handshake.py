"""Full-handshake and rekey vectors from the independent reference (DESIGN §15 row 2).

``tests/reference/`` produced ``handshake.json`` with every random input fixed. Here the real
machines run with a provider that replays the reference's randomised outputs at the provider
boundary (as DESIGN §11.6 describes): nonces and KEM seeds, each encapsulation's ``(ss, ct)`` and
each signature. Everything else is computed by ``qrp2p`` with pyca, so:

- every frame must match the reference byte for byte;
- pyca must decapsulate the reference's ciphertexts to the same secret and accept its signatures
  (otherwise the handshake closes);
- the traffic secrets, exporters and the rekey's epoch-1 secrets must match.
"""

from collections.abc import Iterator
from dataclasses import fields, is_dataclass
from typing import Any

import pytest

from qrp2p.core.crypto.hybrid_sig import Role
from qrp2p.core.crypto.identity import IdentityKeyPair
from qrp2p.core.crypto.kem import SharedSecret
from qrp2p.core.crypto.profiles import HYBRID_1, PQ_CNSA_1, Profile
from qrp2p.core.crypto.provider import PlainProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import ProtocolError
from qrp2p.core.events import Deliver, Queue
from qrp2p.core.handshake import Established, Initiator, Responder
from qrp2p.core.record import Channel
from qrp2p.core.wire import Chat, Frame, FrameType, KeyUpdate, RekeyAnswer, RekeyFinish, RekeyOffer
from tests.core.harness import Link, one, sent
from tests.reference import protocol as reference
from tests.vectors import load_json

VECTORS: dict[str, Any] = load_json("handshake.json")
PROFILES = {1: HYBRID_1, 2: PQ_CNSA_1}


def b(hex_value: str) -> bytes:
    return bytes.fromhex(hex_value)


class Replay(PlainProvider):
    """Replays recorded randomised outputs, checking the inputs they were recorded for."""

    def __init__(
        self,
        randoms: list[bytes],
        encapsulations: list[tuple[bytes, SharedSecret, bytes]],
        signatures: dict[Role, bytes],
    ) -> None:
        super().__init__(self._next_random)
        self._randoms: Iterator[bytes] = iter(randoms)
        self._encapsulations = iter(encapsulations)
        self._signatures = signatures
        self.signed: list[Role] = []

    def _next_random(self, n: int) -> bytes:
        value = next(self._randoms)
        assert len(value) == n
        return value

    def kem_encapsulate(
        self,
        profile: Profile,  # noqa: ARG002
        ek: bytes,
        *,
        epoch: int = 0,  # noqa: ARG002
    ) -> tuple[SharedSecret, bytes]:
        expected_ek, shared, ct = next(self._encapsulations)
        assert ek == expected_ek, "encapsulation to a different key than the reference's"
        return shared, ct

    def sign(self, profile: Profile, keys: IdentityKeyPair, role: Role, th: bytes) -> bytes:  # noqa: ARG002
        self.signed.append(role)
        return self._signatures[role]


def keypair(seeds: list[str]) -> IdentityKeyPair:
    return IdentityKeyPair(*(Secret(b(s), "identity") for s in seeds))


def shared(out: dict[str, str], prefix: str = "") -> SharedSecret:
    components = tuple(
        Secret(b(out[f"{prefix}{name}"]), name)
        for name in ("ssM", "ssX")
        if f"{prefix}{name}" in out
    )
    return SharedSecret(Secret(b(out[f"{prefix}ss"]), "ss"), components)


def frame(hex_value: str) -> Frame:
    data = b(hex_value)
    return Frame(FrameType(data[4]), data[5:])


@pytest.fixture(params=list(VECTORS), ids=list(VECTORS))
def vector(request: pytest.FixtureRequest) -> dict[str, Any]:
    return VECTORS[request.param]


def run(vector: dict[str, Any]) -> tuple[Any, ...]:
    profile = PROFILES[vector["profile"]]
    x, out = vector["inputs"], vector["outputs"]
    alice, bob = keypair(x["initiator_seeds"]), keypair(x["responder_seeds"])
    i_prov = Replay(
        [b(x["kem_seed"]), b(x["nonce_I"]), b(x["rekey_seed"])],
        [],
        {Role.INITIATOR: b(out["sig_I"]), Role.REKEY_FINISH: b(out["rekey_sig_I"])},
    )
    r_prov = Replay(
        [b(x["nonce_R"])],
        [
            (b(out["hello"])[5 + 35 :], shared(out), b(out["ct"])),
            (b(out["rekey_ek"]), shared(out, "rekey_"), b(out["rekey_ct"])),
        ],
        {Role.RESPONDER: b(out["sig_R"]), Role.REKEY_ANSWER: b(out["rekey_sig_R"])},
    )
    i = Initiator(
        provider=i_prov,
        profile=profile,
        identity=alice,
        pinned=bob.bundle,
        glass_box_request=x["gb_request"],
        now=0.0,
    )
    r = Responder(provider=r_prov, profiles=[profile], identity=bob, own_ephemeral_keys=(), now=0.0)
    hello = sent(i.start())
    reply = sent(r.receive(hello[0], 1.0))
    confirm = sent(i.receive(reply[0], 2.0))
    r.receive(confirm[0], 2.5)
    decision = r.accept(glass_box=x["glass_box"], now=3.0)
    on_admit = i.receive(sent(decision)[0], 3.0)
    return profile, out, hello, reply, confirm, decision, on_admit, i_prov, r_prov


def test_frames_match_the_reference_byte_for_byte(vector: dict[str, Any]) -> None:
    _, out, hello, reply, confirm, decision, on_admit, *_ = run(vector)
    assert hello[0].encode() == b(out["hello"])
    assert reply[0].encode() == b(out["reply"])
    assert confirm[0].encode() == b(out["confirm"])
    assert sent(decision)[0].encode() == b(out["admit"])
    assert one(on_admit, Established).glass_box is vector["inputs"]["glass_box"]


def test_traffic_secrets_match_the_reference(vector: dict[str, Any]) -> None:
    _, out, *_, decision, on_admit, _, _ = run(vector)
    i, r = one(on_admit, Established).channel, one(decision, Established).channel
    for channel in (i, r):
        assert_rekey_salt(channel, out["cs_0"], vector["profile"])
        ap_i, ap_r = (
            (channel._send.secret, channel._recv.secret)
            if channel.is_initiator
            else (channel._recv.secret, channel._send.secret)
        )
        assert ap_i.reveal() == b(out["ap_I_0"])
        assert ap_r.reveal() == b(out["ap_R_0"])
        assert channel._epoch.exporter.reveal() == b(out["exporter_0"])
    # The reference's first record opens with our keys.
    delivered = r.receive(frame(out["record_I_0"]), 4.0)
    assert [e.message for e in delivered if isinstance(e, Deliver)] == [
        Chat(id=bytes(16), text="hello")
    ]


def test_rekey_matches_the_reference(vector: dict[str, Any]) -> None:
    _, out, *_, decision, on_admit, i_prov, r_prov = run(vector)
    net = Link(one(on_admit, Established).channel, one(decision, Established).channel)
    i, r = net["i"].channel, net["r"].channel
    offer = one(i.start_rekey(10.0), Queue).message
    assert offer == RekeyOffer(ek=b(out["rekey_ek"]))
    net.push("i", offer)
    net.run()
    assert i.epoch == r.epoch == 1
    for channel in (i, r):
        assert_rekey_salt(channel, out["cs_1"], vector["profile"])
        ap_i, ap_r = (
            (channel._send.secret, channel._recv.secret)
            if channel.is_initiator
            else (channel._recv.secret, channel._send.secret)
        )
        assert ap_i.reveal() == b(out["ap_I_1"])
        assert ap_r.reveal() == b(out["ap_R_1"])
        assert channel._epoch.exporter.reveal() == b(out["exporter_1"])
    wire = [m for side in ("i", "r") for m in net[side].events if isinstance(m, Queue)]
    assert RekeyAnswer(ct=b(out["rekey_ct"]), sig=b(out["rekey_sig_R"])) in [
        q.message for q in wire
    ]
    assert RekeyFinish(sig=b(out["rekey_sig_I"])) in [q.message for q in wire]
    assert i_prov.signed == [Role.INITIATOR, Role.REKEY_FINISH]
    assert r_prov.signed == [Role.RESPONDER, Role.REKEY_ANSWER]


def assert_rekey_salt(channel: Channel, root: str, profile_id: int) -> None:
    p = reference.HYBRID_1 if profile_id == 1 else reference.PQ_CNSA_1
    expected = reference.derive_secret(p, b(root), "derived", reference.h(p, b""))
    assert channel._epoch.rekey_salt.reveal() == expected
    assert channel._epoch.rekey_salt.label == f"derived[{channel.epoch + 1}]"


def retained_secrets(value: object) -> list[Secret]:
    """Walk retained key state, including pending rekey state; avoid test/provider fixtures."""
    if isinstance(value, Secret):
        return [value]
    if isinstance(value, (list, tuple)):
        return [s for child in value for s in retained_secrets(child)]
    if is_dataclass(value):
        return [s for f in fields(value) for s in retained_secrets(getattr(value, f.name))]
    return []


@pytest.mark.parametrize("epoch", [0, 1])
def test_retained_state_cannot_open_earlier_generations(vector: dict[str, Any], epoch: int) -> None:
    profile, out, *_, decision, on_admit, _, _ = run(vector)
    net = Link(one(on_admit, Established).channel, one(decision, Established).channel)
    if epoch:
        net.absorb("i", net["i"].channel.start_rekey(10.0))
        net.run()
    originals = []
    for side in ("i", "r"):
        channel = net[side].channel
        old = sent(channel.seal_next(Chat(id=bytes(16), text="earlier"), 11.0))[0]
        net["r" if side == "i" else "i"].channel.receive(old, 11.0)
        originals.append((old, channel._send.seq - 1, channel._send.secret.reveal()))
    for _ in range(3):
        for side in ("i", "r"):
            net.push(side, KeyUpdate())
        net.run()
    root = b(out[f"cs_{epoch}"])
    for side in ("i", "r"):
        channel = net[side].channel
        retained = retained_secrets((channel._epoch, channel._send, channel._recv, channel._rekey))
        assert root not in [s.reveal() for s in retained]
        assert all(original[2] not in [s.reveal() for s in retained] for original in originals)
        for old, seq, _ in originals:
            for candidate in retained:
                if len(candidate) < profile.hash_len:
                    continue  # keys/IVs shorter than Hlen cannot be HKDF roots
                th = b(out["th_rekey" if epoch else "th_final"])
                possible = [candidate] + [
                    channel._provider.derive_secret(profile, candidate, label, th)
                    for label in ("i ap traffic", "r ap traffic")
                ]
                for secret in possible:
                    with pytest.raises(ProtocolError):
                        channel._provider.unseal(
                            profile,
                            channel._provider.traffic_keys(profile, secret),
                            seq,
                            old.header,
                            old.body,
                        )


@pytest.mark.parametrize("side", ["i", "r"])
def test_key_update_during_partial_rekey_drops_consumed_pending_secret(
    vector: dict[str, Any], side: str
) -> None:
    _, out, *_, decision, on_admit, _, _ = run(vector)
    net = Link(one(on_admit, Established).channel, one(decision, Established).channel)
    net.absorb("i", net["i"].channel.start_rekey(10.0))
    net.step("i")  # offer
    net.step("r")  # answer
    net.step("i")  # finish
    net.step(side)  # only this direction switches
    channel = net[side].channel
    assert channel.rekey_in_progress
    for name in ("i", "r"):
        pending = net[name].channel._rekey
        assert pending is not None
        if pending.send_switched:
            assert pending.send is None
        if pending.recv_switched:
            assert pending.recv is None
    previous = channel._send.secret.reveal()
    update = sent(channel.seal_next(KeyUpdate(), 11.0))[0]
    net[net.other(side)].channel.receive(update, 11.0)
    retained = retained_secrets((channel._epoch, channel._send, channel._recv, channel._rekey))
    assert previous not in [s.reveal() for s in retained]
    assert b(out["cs_1"]) not in [s.reveal() for s in retained]
    net.run()
    assert channel.epoch == 1
    assert channel._send.generation == 1
    message = Chat(id=bytes(16), text="after partial switch")
    net.push(side, message)
    net.run()
    assert net[net.other(side)].delivered[-1] == message
