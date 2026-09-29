"""Make peer-supplied text safe to show as plain text (DESIGN §14.3, threat A2).

Peer text (chat, file names, mDNS instance names) is shown as plain text only. On a terminal,
"plain" also means no control characters: an escape sequence in a chat line could otherwise move
the cursor, rewrite earlier output or retitle the window, and bidirectional overrides can make a
file name read differently from what it is. :func:`display_text` removes both.
"""

import unicodedata
from typing import Final

BIDI_CONTROLS: Final = frozenset(
    "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
"""Arabic letter mark, LRM/RLM, the embeddings and overrides, and the isolates."""

_REPLACEMENT: Final = "\ufffd"


def is_unsafe_char(char: str) -> bool:
    """Whether ``char`` is a control character, a lone surrogate or a bidirectional control.

    That is Unicode categories ``Cc`` (C0, DEL, C1) and ``Cs``, plus :data:`BIDI_CONTROLS`.
    """
    return char in BIDI_CONTROLS or unicodedata.category(char) in {"Cc", "Cs"}


def display_text(text: str, *, keep_newlines: bool = False, limit: int | None = None) -> str:
    r"""Return ``text`` with every unsafe character replaced by U+FFFD.

    Args:
        text: Untrusted text.
        keep_newlines: Keep ``\n`` (multi-line chat); tabs become spaces either way.
        limit: Truncate to this many characters, ending with an ellipsis.
    """
    out: list[str] = []
    for char in text:
        if char == "\t":
            out.append(" ")
        elif char == "\n" and keep_newlines:
            out.append(char)
        elif is_unsafe_char(char):
            out.append(_REPLACEMENT)
        else:
            out.append(char)
    result = "".join(out)
    if limit is not None and len(result) > limit:
        result = result[: max(limit - 1, 0)] + "…"
    return result
