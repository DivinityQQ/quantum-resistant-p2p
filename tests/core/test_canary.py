"""Canary leak test (DESIGN §15): secrets of a normal session appear nowhere they could leak.

1. A recording provider remembers every secret the session creates; identity seeds are added.
2. A scripted normal session runs: handshake, chat both ways, KeyUpdate, PQ rekey, a failure and
   a close. Every event, trace field, frame, error message and ``repr`` of the machines' state is
   collected.
3. Each secret is searched for in raw, hex and base64 form. Any hit fails.
4. The same search over a glass-box run, where the revealed secrets are part of what is shown,
   MUST find them; otherwise the search itself is broken.
"""

import base64
import dataclasses
from collections.abc import Iterable

from qrp2p.core.crypto.provider import PlainProvider, RevealingProvider
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import ProtocolError
from qrp2p.core.events import Trace
from qrp2p.core.wire import Chat, Frame
from tests.core.harness import Link, alice, bob, handshake, initiator, responder
from tests.support import DeterministicRandom


class Recorder:
    def __init__(self) -> None:
        self.secrets: list[Secret] = []

    def __call__(self, secret: Secret) -> None:
        self.secrets.append(secret)


def recording(label: str, recorder: Recorder) -> RevealingProvider:
    return RevealingProvider(PlainProvider(DeterministicRandom(label)), recorder)


def public_bytes(obj: object) -> Iterable[bytes]:
    """Every bytes value reachable in an event or trace dataclass."""
    if isinstance(obj, bytes):
        yield obj
    elif isinstance(obj, Frame):
        yield obj.encode()
    elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for f in dataclasses.fields(obj):
            yield from public_bytes(getattr(obj, f.name))
    elif isinstance(obj, (tuple, list)):
        for item in obj:
            yield from public_bytes(item)


def scripted_session(*, glass_box: bool) -> tuple[list[Secret], bytes, str]:
    recorder = Recorder()
    run = handshake(
        initiator(gb=glass_box, prov=recording("canary-i", recorder)),
        responder(prov=recording("canary-r", recorder)),
        glass_box=glass_box,
    )
    i, r = run.channels()
    net = Link(i, r)
    for n in range(3):
        net.push("i", Chat(id=n.to_bytes(16, "big"), text=f"hello {n}"))
        net.push("r", Chat(id=n.to_bytes(16, "big"), text=f"hi {n}"))
    net.run()
    net.absorb("i", i.start_rekey(20.0))
    net.run()
    net.advance(20.0 + 700)  # includes a KeyUpdate in each direction
    errors: list[str] = []
    try:
        i.receive(Frame(net["i"].wire[0].type, net["i"].wire[0].body), 800.0)
    except ProtocolError as error:  # the channel handles it; kept for completeness
        errors.append(str(error))
    net.absorb("i", i.close())
    net.run()

    events: list[object] = [
        *run.start,
        *run.on_hello,
        *run.on_reply,
        *run.on_confirm,
        *run.on_decision,
        *run.on_admit,
        *net["i"].events,
        *net["r"].events,
    ]
    binary = b"".join(
        [
            *(b for e in events if isinstance(e, Trace) for b in public_bytes(e.event)),
            *(f.encode() for side in ("i", "r") for f in net[side].wire),
        ]
    )
    text = "\n".join(
        [
            *(repr(e) for e in events),
            *errors,
            repr(i._send),
            repr(i._recv),
            repr(i._epoch),
            repr(r._send),
            repr(r._epoch),
            repr(alice()),
            repr(bob()),
        ]
    )
    secrets = [*recorder.secrets, *alice().seeds, *bob().seeds]
    if glass_box:  # what the glass-box Inspector shows (M4): every revealed value
        text += "\n" + "\n".join(s.reveal().hex() for s in recorder.secrets)
    return secrets, binary, text


def leaks(secrets: list[Secret], binary: bytes, text: str) -> list[str]:
    lowered = text.lower()
    found = []
    for secret in secrets:
        value = secret.reveal()
        forms = [value.hex(), base64.b64encode(value).decode(), base64.b32encode(value).decode()]
        if value in binary or any(form.lower() in lowered for form in forms):
            found.append(secret.label)
    return found


def test_normal_session_leaks_no_secret() -> None:
    secrets, binary, text = scripted_session(glass_box=False)
    labels = {s.label for s in secrets}
    # The recorder saw the whole schedule, so the search below means something.
    assert {"hs", "hs_R", "fk_I", "cs_0", "cs_1", "ap_I[0]", "ap_R[1]", "exporter_1"} <= labels
    assert {"ap_I[1]+1", "ssM", "ssX", "identity.mldsa65"} <= labels
    assert leaks(secrets, binary, text) == []


def test_search_finds_secrets_in_a_glass_box_run() -> None:
    secrets, binary, text = scripted_session(glass_box=True)
    found = set(leaks(secrets, binary, text))
    revealed = {s.label for s in secrets if not s.label.startswith("identity.")}
    assert revealed <= found
    # Identity private keys are never exposed, not even in glass-box sessions (DESIGN §11.4).
    assert not any(label.startswith("identity.") for label in found)
