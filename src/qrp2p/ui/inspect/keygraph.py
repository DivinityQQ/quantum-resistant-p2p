"""The key schedule as a dependency graph (UI_DESIGN §7.4; DESIGN §4.2, §7.4, §8.4).

Nodes are the session's secrets and the transcript hashes they bind to; edges are the
specification's derivations. Every node says where its knowledge comes from:

- **observed**: the engine reported deriving it (``SecretDerived``); in a normal session its
  value is hidden, and no view can reveal it;
- **revealed**: an exposed session (glass-box or lab) revealed its value;
- **spec**: the specification says it comes next, but the engine has not derived it yet;
- **unavailable**: something observed depends on it, but its event is no longer retained.

A node the engine dropped its references to carries the ``SecretsReleased`` cause; that is a
lifecycle fact, not a claim of zeroization, and a revealed value stays in the exposed trace.

Names are unique within a session (DESIGN §11.4), so the graph is built from names alone: the
grammar below is the specification's naming, not inference from timing.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Final

from qrp2p.core.trace import SecretDerived, SecretsReleased, TranscriptHashed
from qrp2p.ui.inspect.model import ProfileFacts, Revealed, SessionFacts, TraceItem

_TRAFFIC: Final = re.compile(r"^ap_(?P<side>[IR])\[(?P<epoch>\d+)\](?:\+(?P<gen>\d+))?$")
_ROOT: Final = re.compile(r"^(?P<base>cs|exporter)_(?P<epoch>\d+)$")
_INDEXED: Final = re.compile(r"^(?P<base>[A-Za-z_]+?)(?:\[(?P<epoch>\d+)\])?$")

PENDING_HANDSHAKE: Final = ("derived[0]", "cs_0", "ap_I[0]", "ap_R[0]", "exporter_0", "derived[1]")
"""What a handshake still in progress derives at its end (DESIGN §7.4)."""
LAB_IDENTITY_SEEDS: Final = frozenset({"identity.ed25519", "identity.mldsa65", "identity.mldsa87"})
"""The private seeds the solo lab reveals for its own identities (DESIGN §11.4)."""
HEAD_SIZE: Final = 64
"""Names always on the graph: the handshake's, which the bus always retains."""
PAGE_SIZE: Final = 128
"""Later names (key updates, rekeys) per page."""


@dataclass(frozen=True, slots=True)
class KeyNode:
    """One secret (or transcript hash) of the schedule."""

    key: str
    """The secret's name (unique within the session)."""
    kind: str
    """``kem`` (KEM output or key), ``secret``, ``key`` (AEAD key or IV), ``hash``, or
    ``identity`` (a lab identity's private seed)."""
    epoch: int
    column: int
    row: int
    operation: str
    """How the specification derives it, e.g. ``Derive-Secret(hs, "r hs traffic", th_hello)``."""
    inputs: tuple[str, ...]
    section: str
    size: int
    """Bytes: as observed, else from the profile; 0 when neither says."""
    state: str
    """``observed``, ``revealed``, ``spec`` or ``unavailable``."""
    released: str
    """The ``SecretsReleased`` cause, or empty."""
    value: str
    """Hex: a revealed value, or a transcript hash's public digest; empty when hidden."""
    ordinal: int
    """The event that reported it; -1 if none."""


@dataclass(frozen=True, slots=True)
class KeyEdge:
    """``source`` is an input of ``target``."""

    key: str
    source: str
    target: str


@dataclass(frozen=True, slots=True)
class KeyGraph:
    """Nodes in layout order, and edges."""

    nodes: tuple[KeyNode, ...]
    edges: tuple[KeyEdge, ...]
    columns: int
    rows: int
    pages: int = 1
    page: int = 0


@dataclass(frozen=True, slots=True)
class Spec:
    """What the specification says about one name."""

    kind: str
    epoch: int
    operation: str
    inputs: tuple[str, ...]
    section: str


# -- the naming grammar --------------------------------------------------------------------------


def _th(epoch: int) -> str:
    return "th_final" if epoch == 0 else f"th_rekey[{epoch}]"


def _spec_keys(name: str) -> Spec:
    parent, _, part = name.rpartition(".")
    size = "32" if part == "key" else "12"
    operation = f'Keys({parent}): Expand-Label({parent}, "{part}", "", {size})'
    return Spec("key", _epoch_of(parent), operation, (parent,), "7.4")


def _spec_traffic(match: re.Match[str]) -> Spec:
    side, epoch, gen = match["side"], int(match["epoch"]), int(match["gen"] or 0)
    if gen:
        parent = f"ap_{side}[{epoch}]" + (f"+{gen - 1}" if gen > 1 else "")
        operation = f'Expand-Label({parent}, "traffic upd", "", Hlen): KeyUpdate'
        return Spec("secret", epoch, operation, (parent,), "8.4")
    label = "i ap traffic" if side == "I" else "r ap traffic"
    cs, th = f"cs_{epoch}", _th(epoch)
    return Spec("secret", epoch, f'Derive-Secret({cs}, "{label}", {th})', (cs, th), "7.4")


def _spec_root(match: re.Match[str]) -> Spec:
    base, epoch = match["base"], int(match["epoch"])
    if base == "exporter":
        cs, th = f"cs_{epoch}", _th(epoch)
        return Spec("secret", epoch, f'Derive-Secret({cs}, "exporter", {th})', (cs, th), "7.4")
    salt = f"derived[{epoch}]"
    if epoch == 0:
        return Spec("secret", 0, f"HKDF-Extract(salt = {salt}, ikm = 0^Hlen)", (salt,), "7.4")
    ss = f"ss[{epoch}]"
    return Spec("secret", epoch, f"HKDF-Extract(salt = {salt}, ikm = {ss})", (salt, ss), "8.4")


_HANDSHAKE: Final[dict[str, Spec]] = {
    "hs": Spec("secret", 0, "HKDF-Extract(salt = 0^Hlen, ikm = ss)", ("ss",), "7.4"),
    "hs_R": Spec(
        "secret", 0, 'Derive-Secret(hs, "r hs traffic", th_hello)', ("hs", "th_hello"), "7.4"
    ),
    "hs_I": Spec(
        "secret", 0, 'Derive-Secret(hs, "i hs traffic", th_hello)', ("hs", "th_hello"), "7.4"
    ),
    "fk_R": Spec("secret", 0, 'Expand-Label(hs_R, "finished", "", Hlen)', ("hs_R",), "7.4"),
    "fk_I": Spec("secret", 0, 'Expand-Label(hs_I, "finished", "", Hlen)', ("hs_I",), "7.4"),
    "th_hello": Spec("hash", 0, "H(T(0x10, Hello) ‖ T(0x11, nonce_R ‖ ct))", (), "7.3"),
    "th_sig_R": Spec("hash", 0, "H(TR through T(0x21, IdR)): what SigR signs", (), "7.3"),
    "th_fin_R": Spec("hash", 0, "H(TR through T(0x22, SigR)): what FinR authenticates", (), "7.3"),
    "th_sig_I": Spec(
        "hash", 0, "H(TR through T(0x23, FinR) ‖ T(0x31, IdI)): what SigI signs", (), "7.3"
    ),
    "th_fin_I": Spec("hash", 0, "H(TR through T(0x32, SigI)): what FinI authenticates", (), "7.3"),
    "th_fin_A": Spec(
        "hash",
        0,
        "H(TR through T(0x33, FinI) ‖ T(0x41, AdmitBody)): what FinA authenticates",
        (),
        "7.3",
    ),
    "th_final": Spec("hash", 0, "H(TR through T(0x42, FinA)): the whole handshake", (), "7.3"),
}


def _spec_kem(base: str, epoch: int, facts: SessionFacts) -> Spec:
    """A KEM output.

    The initiator generates and decapsulates, in the handshake and in a rekey; the responder
    encapsulates with fresh randomness of its own.
    """
    suffix = f"[{epoch}]" if epoch else ""
    profile = facts.profile
    kem = profile.kem if profile is not None else "KEM"
    hybrid = profile is not None and bool(profile.ct_parts)
    decaps = facts.initiator
    dk = (f"dk{suffix}",) if decaps else ()
    match base:
        case "dk":
            operation, inputs = f"{kem}: a fresh key pair from new randomness", ()
        case "ssM":
            operation = "ML-KEM-768.Decaps(dk, ctM)" if decaps else "ML-KEM-768.Encaps(pkM)"
            inputs = dk
        case "ssX":
            operation = "X25519(dk's scalar, ctX)" if decaps else "X25519(fresh scalar, pkX)"
            inputs = dk
        case _ if hybrid:
            operation = "SHA3-256(ssM ‖ ssX ‖ ctX ‖ pkX ‖ X-Wing label): X-Wing's combiner"
            inputs = (f"ssM{suffix}", f"ssX{suffix}")
        case _ if profile is not None and profile.lab_only:
            operation = 'SHA-256(ssX ‖ ctX ‖ pkX ‖ "qrp2p2 x25519kem")'
            inputs = (f"ssX{suffix}",)
        case _:
            operation = f"{kem}.Decaps(dk, ct)" if decaps else f"{kem}.Encaps(ek)"
            inputs = dk
    section = "8.4" if epoch else ("4.2" if base in {"ssM", "ssX"} else "7.4")
    return Spec("kem", epoch, operation, inputs, section)


def spec_of(name: str, facts: SessionFacts) -> Spec | None:  # noqa: C901, PLR0911  # the grammar
    """What the specification says about a name; ``None`` if it is not a schedule name."""
    if facts.lab and name in LAB_IDENTITY_SEEDS:
        operation = "A private key's seed of this lab's throwaway identity; it exists only here"
        return Spec("identity", 0, operation, (), "5.1")
    if name.endswith((".key", ".iv")):
        return _spec_keys(name)
    if (traffic := _TRAFFIC.match(name)) is not None:
        return _spec_traffic(traffic)
    if (root := _ROOT.match(name)) is not None:
        return _spec_root(root)
    if name in _HANDSHAKE:
        return _HANDSHAKE[name]
    indexed = _INDEXED.match(name)
    if indexed is None:
        return None
    base, epoch = indexed["base"], int(indexed["epoch"] or 0)
    if base == "th_rekey" and epoch:
        return Spec("hash", epoch, "H(RT ‖ T(0x53, SigR') ‖ T(0x54, SigI'))", (), "8.4")
    if base == "derived":
        source = "hs" if epoch == 0 else f"cs_{epoch - 1}"
        operation = f'Derive-Secret({source}, "derived", H(""))'
        if epoch:
            operation += ": the rekey salt, kept instead of the root"
        return Spec("secret", epoch, operation, (source,), "8.4" if epoch else "7.4")
    if base in {"dk", "ss", "ssM", "ssX"}:
        return _spec_kem(base, epoch, facts)
    return None


def _epoch_of(name: str) -> int:
    for pattern in (_TRAFFIC, _ROOT, _INDEXED):
        found = pattern.match(name)
        if found is not None and found.groupdict().get("epoch"):
            return int(found["epoch"])
    return 0


# -- building ------------------------------------------------------------------------------------


@dataclass(slots=True)
class _Seen:
    derived: dict[str, tuple[int, int]] = field(default_factory=dict[str, tuple[int, int]])
    """Name to (size, ordinal)."""
    hashes: dict[str, tuple[bytes, int]] = field(default_factory=dict[str, tuple[bytes, int]])
    released: dict[str, str] = field(default_factory=dict[str, str])
    values: dict[str, bytes] = field(default_factory=dict[str, bytes])
    order: list[str] = field(default_factory=list[str])


def _collect(items: Iterable[TraceItem]) -> _Seen:
    seen = _Seen()
    for item in items:
        match item.event:
            case SecretDerived(label=label, length=length) if label not in seen.derived:
                seen.derived[label] = (length, item.ordinal)
                seen.order.append(label)
            case TranscriptHashed(name=name, digest=digest):
                seen.hashes.setdefault(name, (digest, item.ordinal))
                seen.order.append(name)
            case SecretsReleased(labels=labels, cause=cause):
                for label in labels:
                    seen.released[label] = cause.value
            case Revealed(label=label, value=value):
                seen.values[label] = value
                seen.order.append(label)  # possibly before its derivation event
            case _:
                pass
    return seen


def _expected_size(name: str, spec: Spec, profile: ProfileFacts | None) -> int:
    if name.endswith(".key"):
        return 32
    if name.endswith(".iv"):
        return 12
    if spec.kind == "kem":
        return 0 if name.startswith("dk") else 32
    return profile.hash_len if profile is not None else 0


def _node(name: str, spec: Spec, seen: _Seen, facts: SessionFacts, *, pending: bool) -> KeyNode:
    size, ordinal = seen.derived.get(name, (0, -1))
    value = seen.values.get(name)
    shown = ""
    if spec.kind == "hash":
        digest = seen.hashes.get(name)
        state = "observed" if digest is not None else "spec"
        if digest is not None:
            shown, size, ordinal = digest[0].hex(), len(digest[0]), digest[1]
    elif value is not None:
        state, shown, size = "revealed", value.hex(), len(value)
    elif name in seen.derived:
        state = "observed"
    elif pending:  # nothing is evicted during a handshake: what is missing comes next
        state = "spec"
    else:
        state = "unavailable"
    return KeyNode(
        key=name,
        kind=spec.kind,
        epoch=spec.epoch,
        column=0,
        row=0,
        operation=spec.operation,
        inputs=spec.inputs,
        section=spec.section,
        size=size or _expected_size(name, spec, facts.profile),
        state=state,
        released=seen.released.get(name, ""),
        value=shown,
        ordinal=ordinal,
    )


def build(items: Iterable[TraceItem], facts: SessionFacts, *, page: int = 0) -> KeyGraph:
    """One page of the key graph of a session's retained trace.

    The first :data:`HEAD_SIZE` names (the handshake's) are always on it; the later ones (key
    updates and rekeys, which a long session has thousands of) are paged, newest first.
    """
    seen = _collect(items)
    pending = facts.profile is not None and not facts.established and not facts.ended
    names = list(dict.fromkeys(seen.order))
    if pending:
        names += [n for n in PENDING_HANDSHAKE if n not in seen.derived]
    names = [n for n in names if spec_of(n, facts) is not None]
    head, history = names[:HEAD_SIZE], names[HEAD_SIZE:]
    pages = max(1, -(-len(history) // PAGE_SIZE))
    page = min(max(0, page), pages - 1)
    end = len(history) - page * PAGE_SIZE
    shown = head + history[max(0, end - PAGE_SIZE) : end]
    specs = {name: spec for name in shown if (spec := spec_of(name, facts)) is not None}
    # Inputs not shown themselves. While the handshake is under way they are what it derives
    # next, and its whole (small) schedule is drawn. Otherwise each is a leaf: its own inputs
    # are on another page or no longer retained, and are not reconstructed one by one.
    missing = [s for spec in specs.values() for s in spec.inputs]
    while missing:
        source = missing.pop()
        if source in specs or (found := spec_of(source, facts)) is None:
            continue
        if pending:
            missing.extend(found.inputs)
        elif found.inputs:
            note = "; its inputs are not drawn here (another page, or no longer retained)"
            found = replace(found, operation=found.operation + note, inputs=())
        specs[source] = found
    nodes = {name: _node(name, spec, seen, facts, pending=pending) for name, spec in specs.items()}
    return replace(_layout(nodes), pages=pages, page=page)


# -- layout --------------------------------------------------------------------------------------


def _depths(nodes: dict[str, KeyNode]) -> dict[str, int]:
    """Each node's column: one more than its deepest input's.

    A rekey's KEM outputs have no inputs from earlier epochs, so they are placed just before
    the chaining secret they feed rather than at the far left; transcript hashes just before
    their first consumer.
    """
    depth: dict[str, int] = {}

    def floating(node: KeyNode) -> bool:
        return node.kind == "hash" or (node.kind == "kem" and node.epoch > 0)

    consumers = _consumers(nodes)
    remaining = {name for name, node in nodes.items() if not floating(node)}
    while remaining:
        ready = [
            name
            for name in remaining
            if all(s in depth or floating(nodes[s]) for s in nodes[name].inputs)
        ]
        if not ready:
            msg = "cyclic key schedule"
            raise ValueError(msg)
        for name in ready:
            depth[name] = 1 + max(
                (depth[s] for s in nodes[name].inputs if not floating(nodes[s])), default=-1
            )
        remaining.difference_update(ready)
    remaining = {name for name, node in nodes.items() if floating(node)}
    while remaining:
        ready = [name for name in remaining if all(t in depth for t in consumers.get(name, []))]
        if not ready:
            msg = "cyclic key schedule"
            raise ValueError(msg)
        for name in ready:
            depth[name] = max(0, min((depth[t] for t in consumers.get(name, [])), default=1) - 1)
        remaining.difference_update(ready)
    return depth


def _consumers(nodes: dict[str, KeyNode]) -> dict[str, list[str]]:
    consumers: dict[str, list[str]] = {}
    for name, node in nodes.items():
        for source in node.inputs:
            consumers.setdefault(source, []).append(name)
    return consumers


def _layout(nodes: dict[str, KeyNode]) -> KeyGraph:
    """Columns by derivation depth, a band of rows per epoch, rows in order of appearance."""
    depth = _depths(nodes)
    placed: list[KeyNode] = []
    top = 0
    for epoch in sorted({n.epoch for n in nodes.values()}):
        used: dict[int, int] = {}
        for node in (n for n in nodes.values() if n.epoch == epoch):
            column = depth[node.key]
            placed.append(replace(node, column=column, row=top + used.get(column, 0)))
            used[column] = used.get(column, 0) + 1
        top += max(used.values(), default=0)
    edges = tuple(
        KeyEdge(f"{source}>{node.key}", source, node.key)
        for node in placed
        for source in node.inputs
        if source in nodes
    )
    columns = 1 + max((n.column for n in placed), default=-1)
    return KeyGraph(tuple(placed), edges, columns, top)
