"""Generate our own known-answer files (kdf.json, identity.json).

Run only for a deliberate spec change: ``uv run python -m tests.vectors.generate --force``.
The tests cross-check these values against independent implementations, so a KAT produced by a
buggy build would fail there rather than freeze the bug.
"""

import hashlib
import json
import sys
from typing import Any

from qrp2p.core.crypto import kdf
from qrp2p.core.crypto.hybrid_sig import Role, ed25519_message
from qrp2p.core.crypto.identity import IdentityKeyPair, safety_number
from qrp2p.core.crypto.kdf import SHA256, SHA384, HashFunction
from qrp2p.core.crypto.secret import Secret
from tests.vectors import VECTORS


def _shake(label: str, n: int) -> bytes:
    return hashlib.shake_256(label.encode()).digest(n)


def _kdf_cases(h: HashFunction) -> dict[str, Any]:
    labels = [
        [h.length, "derived", h.digest(b"").hex()],
        [32, "key", ""],
        [12, "iv", ""],
        [h.length, "r hs traffic", _shake("th", h.length).hex()],
    ]
    label_cases = [
        {
            "length": n,
            "label": lab,
            "context": ctx,
            "out": kdf.hkdf_label(n, lab, bytes.fromhex(ctx)).hex(),
        }
        for n, lab, ctx in labels
    ]
    secret = Secret(_shake(f"{h.name} secret", h.length), "S")
    th = _shake(f"{h.name} th", h.length)
    expand_cases = [
        {
            "secret": secret.reveal().hex(),
            "label": label,
            "context": ctx.hex(),
            "length": n,
            "out": kdf.expand_label(h, secret, label, ctx, n).reveal().hex(),
        }
        for label, ctx, n in [
            ("finished", b"", h.length),
            ("traffic upd", b"", h.length),
            ("exporter", th, h.length),
            ("key", b"", 32),
        ]
    ]
    keys = kdf.traffic_keys(h, secret)

    # A miniature of the DESIGN §7.4 schedule, as a function of (ss, transcript hashes).
    ss = Secret(_shake(f"{h.name} ss", 32), "ss")
    th_hello = h.digest(b"hello transcript")
    th_final = h.digest(b"final transcript")
    zeros = bytes(h.length)
    hs = kdf.hkdf_extract(h, zeros, ss, name="hs")
    hs_r = kdf.derive_secret(h, hs, "r hs traffic", th_hello)
    fk_r = kdf.expand_label(h, hs_r, "finished", b"", h.length)
    derived = kdf.derive_secret(h, hs, "derived", h.digest(b""))
    cs_0 = kdf.hkdf_extract(h, derived, zeros, name="cs_0")
    ap_i = kdf.derive_secret(h, cs_0, "i ap traffic", th_final)
    ap_keys = kdf.traffic_keys(h, ap_i)
    return {
        "hkdf_label": label_cases,
        "expand_label": expand_cases,
        "derive_secret": {
            "secret": secret.reveal().hex(),
            "label": "r hs traffic",
            "th": th.hex(),
            "out": kdf.derive_secret(h, secret, "r hs traffic", th).reveal().hex(),
        },
        "traffic_keys": {
            "secret": secret.reveal().hex(),
            "key": keys.key.reveal().hex(),
            "iv": keys.iv.reveal().hex(),
        },
        "schedule": {
            "ss": ss.reveal().hex(),
            "th_hello": th_hello.hex(),
            "th_final": th_final.hex(),
            "hs": hs.reveal().hex(),
            "hs_R": hs_r.reveal().hex(),
            "fk_R": fk_r.reveal().hex(),
            "cs_0": cs_0.reveal().hex(),
            "ap_I": ap_i.reveal().hex(),
            "ap_I_key": ap_keys.key.reveal().hex(),
            "ap_I_iv": ap_keys.iv.reveal().hex(),
        },
    }


def _identity_case(label: str) -> dict[str, Any]:
    seeds = [_shake(f"{label} {part}", 32) for part in ("ed25519", "mldsa65", "mldsa87")]
    pair = IdentityKeyPair(*(Secret(s, "seed") for s in seeds))
    th = _shake(f"{label} th", 32)
    return {
        "seeds": [s.hex() for s in seeds],
        "bundle": pair.bundle.encode().hex(),
        "peer_id": pair.bundle.peer_id.hex(),
        "short_id": pair.bundle.short_id,
        "th": th.hex(),
        "ed25519_sig_responder": pair.ed25519.sign(ed25519_message(Role.RESPONDER, th)).hex(),
    }


def main() -> None:
    """Write the KAT files; refuses to overwrite without ``--force``."""
    kdf_path, identity_path = VECTORS / "kdf.json", VECTORS / "identity.json"
    if (kdf_path.exists() or identity_path.exists()) and "--force" not in sys.argv:
        sys.exit("KAT files exist; pass --force to regenerate them deliberately")
    kdf_path.write_text(
        json.dumps({"SHA-256": _kdf_cases(SHA256), "SHA-384": _kdf_cases(SHA384)}, indent=1) + "\n",
        encoding="utf-8",
    )
    alice, bob = _identity_case("alice"), _identity_case("bob")
    safety = safety_number(bytes.fromhex(alice["peer_id"]), bytes.fromhex(bob["peer_id"]))
    identity_path.write_text(
        json.dumps({"alice": alice, "bob": bob, "safety_number": list(safety)}, indent=1) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
