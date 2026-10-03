"""Real traces for the Inspector's builders: a scripted session driven through the core engine."""

from dataclasses import dataclass, field

from qrp2p.core.crypto.profiles import HYBRID_1, Profile
from qrp2p.core.crypto.provider import AeadRevealed, PlainProvider, Revealed, RevealingProvider
from qrp2p.core.events import Trace
from qrp2p.core.wire import Chat, KeyUpdate
from qrp2p.ui.inspect.model import (
    Item,
    ProfileFacts,
    RecordOpened,
    SessionFacts,
    TraceItem,
)
from qrp2p.ui.inspect.model import Revealed as RevealedItem
from tests.core.harness import Link, handshake, initiator, responder
from tests.support import DeterministicRandom


def profile_facts(profile: Profile = HYBRID_1) -> ProfileFacts:
    return ProfileFacts(
        name=profile.name,
        kem=profile.kem.name,
        signature="Ed25519 + ML-DSA-65" if profile is HYBRID_1 else "ML-DSA-87",
        aead=profile.aead.value,
        hash=profile.hash.name,
        hash_len=profile.hash_len,
        sig_len=profile.sig_len,
        ek_len=profile.ek_len,
        ct_len=profile.ct_len,
        ek_parts=profile.kem.ek_parts,
        ct_parts=profile.kem.ct_parts,
        lab_only=profile.lab_only,
    )


def session_facts(**changes: object) -> SessionFacts:
    values: dict[str, object] = {
        "session_id": 1,
        "initiator": True,
        "address": "10.0.0.2:47470",
        "profile": profile_facts(),
        "local_name": "You",
        "peer_name": "Bob",
        "peer_short_id": "BOBB-BOBB",
        "contact_id": "ab" * 16,
        "trust": "pinned",
        "pinned_before": True,
        "glass_box_requested": False,
        "glass_box": False,
        "exposed": False,
        "lab": False,
        "established": True,
        "ended": False,
        "end_reason": "",
        "admit_reason": "",
        "by_peer": False,
    }
    values.update(changes)
    return SessionFacts(**values)  # type: ignore[arg-type]


@dataclass
class Side:
    """One node's view: its trace items in order, and what its provider revealed."""

    items: list[TraceItem] = field(default_factory=list)
    revealed: list[Revealed] = field(default_factory=list)

    def add(self, events: list[object]) -> None:
        for event in events:
            if isinstance(event, Trace):
                self._push(event.event)
        for value in self.revealed:
            self._push(_item(value))
        self.revealed.clear()

    def _push(self, event: Item) -> None:
        self.items.append(TraceItem(len(self.items), 0.5 * len(self.items), event))


def _item(value: Revealed) -> Item:
    if isinstance(value, AeadRevealed):
        return RecordOpened(
            value.key, value.seq, value.nonce.reveal(), value.plaintext.reveal(), value.opened
        )
    return RevealedItem(value.label, value.reveal())


@dataclass
class Scripted:
    i: Side
    r: Side
    link: Link


def scripted(
    *,
    exposed: bool = False,
    rekey: bool = True,
    close: bool = True,
    secrets: list[Revealed] | None = None,
) -> Scripted:
    """Handshake, chats both ways, a KeyUpdate each way, a PQ rekey and a close.

    ``secrets`` collects every value the initiator's provider handled, beside the trace: for a
    normal session they are what a canary must not find (the KEMs draw their own randomness, so
    another run of the script derives other values).
    """
    i_side, r_side = Side(), Side()

    def provider(label: str, side: Side) -> PlainProvider | RevealingProvider:
        plain = PlainProvider(DeterministicRandom(label))
        if exposed:
            return RevealingProvider(plain, side.revealed.append)
        if secrets is not None and label == "i":
            return RevealingProvider(plain, secrets.append)  # never reaches the trace
        return plain

    run = handshake(
        initiator(gb=exposed, prov=provider("i", i_side)),
        responder(prov=provider("r", r_side)),
        glass_box=exposed,
    )
    i_side.add([*run.start])
    r_side.add([*run.on_hello])
    i_side.add([*run.on_reply])
    r_side.add([*run.on_confirm, *run.on_decision])
    i_side.add([*run.on_admit])
    net = Link(*run.channels())
    sides = {"i": i_side, "r": r_side}

    def flush() -> None:
        for name, side in sides.items():
            side.add(net[name].events)
            net[name].events.clear()

    for n in range(3):
        net.push("i", Chat(id=n.to_bytes(16, "big"), text=f"hello {n}"))
        net.push("r", Chat(id=(n + 100).to_bytes(16, "big"), text=f"hi {n}"))
    net.run()
    net.push("i", KeyUpdate())
    net.push("r", KeyUpdate())
    net.run()
    flush()
    if rekey:
        net.advance(80.0)
        net.absorb("i", net["i"].channel.start_rekey(80.0))
        net.run()
        net.push("r", Chat(id=bytes(16), text="after the rekey"))
        net.run()
        flush()
    if close:
        net.absorb("i", net["i"].channel.close())
        net.run()
        flush()
    return Scripted(i_side, r_side, net)


def secret_hexes(values: list[Revealed], *, minimum: int = 8) -> set[str]:
    """Every value as lowercase hex: secrets, record nonces and plaintexts of ``minimum`` bytes+."""
    found: set[bytes] = set()
    for value in values:
        if isinstance(value, AeadRevealed):
            found |= {value.nonce.reveal(), value.plaintext.reveal()}
        else:
            found.add(value.reveal())
    return {v.hex() for v in found if len(v) >= minimum}
