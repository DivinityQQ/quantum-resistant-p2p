"""Peer-supplied text made safe to display in the desktop app (DESIGN §14.3, threat A2).

QML renders every peer-supplied string as plain text. On top of that, control characters and
bidirectional overrides are replaced by U+FFFD before a string reaches Qt: an override inside a
file name could make ``invoice<RLO>fdp.exe`` read as ``invoiceexe.pdf``, and a peer's isolate or
embedding could reorder the sentence a name is shown in. Ordinary right-to-left text still works:
Qt applies the bidirectional algorithm itself.
"""

from typing import Final

from qrp2p.services.text import display_text

__all__ = ["NAME_LIMIT", "display_name", "display_text", "fingerprint", "isolate"]

NAME_LIMIT: Final = 80
"""Characters of a name shown before it is cut with an ellipsis."""


def display_name(text: str, *, limit: int | None = NAME_LIMIT) -> str:
    """A single-line name (contact, file, mDNS label): newlines and controls become U+FFFD."""
    return display_text(text.strip(), limit=limit)


def fingerprint(peer_id: bytes) -> str:
    """A peer ID as lowercase hex in groups of four, e.g. ``a1b2 c3d4 …``."""
    digits = peer_id.hex()
    return " ".join(digits[i : i + 4] for i in range(0, len(digits), 4))


def isolate(text: str) -> str:
    """``text`` wrapped in a first-strong isolate, for embedding a name in a sentence.

    A right-to-left name then cannot reorder the sentence around it. Names passed here are
    already display-safe, so they hold no isolate of their own that could unbalance this one.
    """
    return f"\u2068{text}\u2069"
