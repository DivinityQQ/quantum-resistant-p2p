"""The "Why is this secure?" panel: a session's facts with their evidence and assumptions.

UI_DESIGN §7.5: each entry states what holds for *this* session, what it rests on, and which
event shows it. Signature verification by the engine is separated from a person comparing
safety numbers. There is no score: a successful session demonstrates its own facts, not every
adversarial property.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from qrp2p.core.trace import (
    Direction,
    KeysSwitched,
    RecordTraced,
    RekeyStep,
    SessionClosed,
    StateChanged,
)
from qrp2p.ui.inspect.model import ProfileFacts, SessionFacts, TraceItem


@dataclass(frozen=True, slots=True)
class Fact:
    """One entry of the panel."""

    key: str
    title: str
    value: str
    status: str
    """``ok``, ``info``, ``warn`` or ``fail``: never the only signal, the text says it too."""
    evidence: str
    """What shows it, in words."""
    assumption: str
    """What it rests on."""
    ordinal: int
    """The event that shows it; -1 if none."""
    section: str


ASSUMPTIONS: Final[dict[str, str]] = {
    "HYBRID-1": "Confidentiality holds if ML-KEM-768 or X25519 is unbroken, with SHA3-256 as "
    "X-Wing's combiner. Authentication needs both Ed25519 and ML-DSA-65 signatures to verify, so "
    "forging one needs both broken.",
    "PQ-CNSA-1": "Confidentiality rests on ML-KEM-1024 alone and authentication on ML-DSA-87 "
    "alone: the parameter sets of NSA's CNSA 2.0, with no classical fallback.",
    "LAB-CLASSICAL": "Classical only: X25519 and Ed25519. A quantum computer would break both. "
    "This profile exists in the solo lab, to compare.",
}

CLOSE_MEANINGS: Final[dict[str, str]] = {
    "normal": "An orderly close.",
    "decrypt_failed": "A record or handshake message did not authenticate: changed, replayed, "
    "reordered, or sealed under other keys.",
    "unexpected_message": "A message arrived that the protocol does not allow in that state.",
    "oversize": "A frame exceeded its size limit.",
    "schema_error": "A message did not have its exact layout or schema.",
    "signature_invalid": "A signature did not verify.",
    "finished_invalid": "A Finished MAC did not match the transcript.",
    "pin_mismatch": "The responder proved another identity than the pinned one.",
    "policy": "Refused by policy (a profile or an admission decision).",
    "timeout": "A deadline passed, or nothing arrived for too long.",
    "replaced": "A newer session with the same peer replaced this one.",
    "rate_limited": "A limit was reached.",
    "internal": "An internal error closed the session.",
    "locked": "The app was locked.",
    "kem_failure": "The KEM operation failed (a malformed key or ciphertext).",
    "reflection": "Our own identity or key came back to us.",
    "invalid_kem_key": "The KEM public key was not valid.",
}


def _algorithms(profile: ProfileFacts) -> str:
    return f"{profile.kem}; {profile.signature}; {profile.aead}; {profile.hash}"


def build(items: Iterable[TraceItem], facts: SessionFacts) -> tuple[Fact, ...]:  # noqa: C901
    """The facts of a session's retained trace."""
    established = -1
    closed: tuple[int, SessionClosed] | None = None
    first_in_record = -1
    key_updates = {"out": 0, "in": 0}
    rekeys = 0
    last_change = -1
    for item in items:
        match item.event:
            case StateChanged(state="established"):
                established = item.ordinal
            case SessionClosed():
                closed = (item.ordinal, item.event)
            case RecordTraced(direction=Direction.IN) if first_in_record < 0:
                first_in_record = item.ordinal
            case KeysSwitched(direction=direction, cause="key_update"):
                key_updates[direction.value] += 1
                last_change = item.ordinal
            case RekeyStep(step="done"):
                rekeys += 1
                last_change = item.ordinal
            case _:
                pass
    out: list[Fact] = []
    profile = facts.profile
    if profile is not None:
        out.append(
            Fact(
                "profile",
                "Profile",
                f"{profile.name}: {_algorithms(profile)}",
                "warn" if profile.lab_only else "info",
                "Offered in Hello and bound into the transcript (downgrade resistance, P5).",
                ASSUMPTIONS.get(profile.name, ""),
                -1,
                "4",
            )
        )
    out.append(_identity(facts, established))
    out.append(_verification(facts))
    out.append(_exposure(facts))
    out.append(_completion(facts, established, first_in_record))
    if established >= 0:
        updates = key_updates["out"] + key_updates["in"]
        out.append(
            Fact(
                "keys",
                "Key changes",
                f"{updates} KeyUpdate{'s' if updates != 1 else ''} "
                f"({key_updates['out']} sent, {key_updates['in']} received), "
                f"{rekeys} PQ rekey{'s' if rekeys != 1 else ''} completed",
                "info",
                "Each KeyUpdate moves one direction to a new generation; each signed PQ rekey "
                "injects fresh KEM secrets into a new epoch.",
                "KeyUpdate gives forward secrecy within an epoch. A signed PQ rekey locks out an "
                "attacker who learned the current keys, while the identity keys are safe (P9).",
                last_change,
                "8.4",
            )
        )
    if closed is not None:
        out.append(_closed_fact(*closed))
    elif facts.ended:
        out.append(
            Fact(
                "closed",
                "Connection lost",
                "The connection ended without a close record",
                "warn",
                "No authenticated close reason was received.",
                "",
                -1,
                "8.5",
            )
        )
    return tuple(out)


def _identity(facts: SessionFacts, established: int) -> Fact:
    name = facts.peer_name or "the peer"
    if not facts.peer_short_id:
        return Fact(
            "identity",
            "Peer identity",
            "Not authenticated",
            "info",
            "The handshake did not get far enough to prove an identity.",
            "",
            -1,
            "7.5",
        )
    if facts.initiator and facts.pinned_before:
        value = f"{name} ({facts.peer_short_id}) proved the pinned identity"
        evidence = (
            "Reply's signature and Finished verified against the pinned bundle before this side "
            "revealed its own identity in Confirm."
        )
    elif facts.initiator:
        value = f"First contact: {name} ({facts.peer_short_id}) is pinned now"
        evidence = (
            "Reply's signature verified, but there was no earlier pin to compare with: a "
            "machine in the middle would have been accepted just the same."
        )
    else:
        value = f"{name} ({facts.peer_short_id}) proved its identity in Confirm"
        evidence = "Confirm's signature and Finished verified; then admission decided."
    status = "ok" if facts.pinned_before or not facts.initiator else "warn"
    return Fact(
        "identity",
        "Peer identity",
        value,
        status,
        evidence,
        "Signatures prove possession of the bundle's private keys. Whether the bundle belongs "
        "to the person you think is a separate question: see verification.",
        established,
        "7.5",
    )


def _verification(facts: SessionFacts) -> Fact:
    if facts.lab:
        value, status = "Lab identities: nothing to verify", "info"
        evidence = "Both identities were generated for this lab and exist only here."
    elif facts.trust == "verified":
        value, status = "Safety number compared", "ok"
        evidence = "You marked this contact verified after comparing the 60-digit safety number."
    elif facts.trust:
        value, status = "Safety number not compared", "warn"
        evidence = "The contact is pinned but not verified."
    else:
        value, status = "Not a contact", "info"
        evidence = "No pinned identity is stored for this peer."
    return Fact(
        "verification",
        "Out-of-band verification",
        value,
        status,
        evidence,
        "Only a comparison over another channel (in person, a call) rules out a machine in "
        "the middle of the first contact.",
        -1,
        "5.2",
    )


def _exposure(facts: SessionFacts) -> Fact:
    if facts.lab:
        return Fact(
            "exposure",
            "Exposure",
            "Solo lab: every value is shown",
            "info",
            "Simulated nodes in this app, with throwaway identities; nothing touches the network.",
            "",
            -1,
            "11.1",
        )
    if facts.glass_box:
        return Fact(
            "exposure",
            "Exposure",
            "Glass-box: this session's keys and messages are visible",
            "warn",
            "Both users agreed after authentication; the request and the decision are in the "
            "transcript. Identity private keys are never shown.",
            "A glass-box session promises no secrecy from the two of you or from a saved recording.",
            -1,
            "11.3",
        )
    refused = " (a glass-box request was declined)" if facts.glass_box_requested else ""
    return Fact(
        "exposure",
        "Exposure",
        f"Public trace{refused}",
        "ok",
        "This session's provider has no path from secret values to the trace: the Inspector "
        "shows names and sizes only.",
        "",
        -1,
        "11.3",
    )


def _completion(facts: SessionFacts, established: int, first_in_record: int) -> Fact:
    if established < 0:
        state = "ended before completion" if facts.ended else "in progress"
        return Fact(
            "completion",
            "Handshake",
            state.capitalize(),
            "fail" if facts.ended else "info",
            "No Established state was observed.",
            "",
            -1,
            "7.5",
        )
    if facts.initiator:
        return Fact(
            "completion",
            "Handshake",
            "Complete: Admit verified",
            "ok",
            "FinA covered the whole transcript, including the admission decision.",
            "",
            established,
            "7.5",
        )
    if first_in_record >= 0:
        return Fact(
            "completion",
            "Handshake",
            "Complete: key confirmation received",
            "ok",
            "The first record from the initiator opened under ap_I, so both sides derived the "
            "same keys from the same transcript.",
            "",
            first_in_record,
            "7.5",
        )
    return Fact(
        "completion",
        "Handshake",
        "Admitted; waiting for key confirmation",
        "info",
        "The responder has no fifth message: the first record it opens confirms the keys.",
        "",
        established,
        "7.5",
    )


def _closed_fact(ordinal: int, event: SessionClosed) -> Fact:
    reason = event.reason.label
    admit = event.admit_reason.label if event.admit_reason is not None else ""
    quiet = reason in {"normal", "locked", "replaced"} or bool(admit)
    origin = "reported by the peer" if event.by_peer else "closed by this side"
    return Fact(
        "closed",
        "Authentication failed" if reason in {"decrypt_failed", "signature_invalid",
                                              "finished_invalid"} else "Closed",
        f"{reason}{f' ({admit})' if admit else ''}, {origin}",
        "info" if quiet else "fail",
        CLOSE_MEANINGS.get(reason, ""),
        "A reason names what failed, not who caused it: the receiver cannot tell an attack "
        "from a fault.",
        ordinal,
        "Appendix B",
    )  # fmt: skip
