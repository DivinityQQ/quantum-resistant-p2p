"""Write ``tests/vectors/handshake.json`` from the reference (never from ``qrp2p``).

Run only for a deliberate spec change: ``uv run python -m tests.reference.generate --force``.
"""

import hashlib
import json
import sys
from typing import Any

from tests.reference import protocol
from tests.reference.protocol import Identity, Inputs, Profile
from tests.vectors import VECTORS

PATH = VECTORS / "handshake.json"


def shake(label: str, n: int) -> bytes:
    return hashlib.shake_256(label.encode()).digest(n)


def identity(name: str) -> Identity:
    return Identity(*(shake(f"{name} {part}", 32) for part in ("ed25519", "mldsa65", "mldsa87")))


def case(p: Profile, name: str, *, glass_box: bool) -> dict[str, Any]:
    seed_len = 32 if p.kem == "xwing" else 64
    inputs = Inputs(
        initiator=identity("alice"),
        responder=identity("bob"),
        kem_seed=shake(f"{name} kem seed", seed_len),
        nonce_i=shake(f"{name} nonce_I", 32),
        nonce_r=shake(f"{name} nonce_R", 32),
        coins=shake(f"{name} coins", 64),
        gb_request=glass_box,
        glass_box=glass_box,
        rekey_seed=shake(f"{name} rekey seed", seed_len),
        rekey_coins=shake(f"{name} rekey coins", 64),
    )
    result = protocol.handshake(p, inputs)
    return {
        "profile": p.id,
        "inputs": {
            "initiator_seeds": [s.hex() for s in inputs.initiator.seeds],
            "responder_seeds": [s.hex() for s in inputs.responder.seeds],
            "kem_seed": inputs.kem_seed.hex(),
            "nonce_I": inputs.nonce_i.hex(),
            "nonce_R": inputs.nonce_r.hex(),
            "coins": inputs.coins.hex(),
            "gb_request": inputs.gb_request,
            "glass_box": inputs.glass_box,
            "rekey_seed": inputs.rekey_seed.hex(),
            "rekey_coins": inputs.rekey_coins.hex(),
        },
        "outputs": {k: v.hex() for k, v in result.values.items()},
    }


def main() -> None:
    """Write the vectors; refuses to overwrite without ``--force``."""
    if PATH.exists() and "--force" not in sys.argv:
        sys.exit("handshake.json exists; pass --force to regenerate it deliberately")
    cases = {
        "HYBRID-1 glass-box": case(protocol.HYBRID_1, "hybrid", glass_box=True),
        "PQ-CNSA-1": case(protocol.PQ_CNSA_1, "cnsa", glass_box=False),
    }
    PATH.write_text(json.dumps(cases, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
