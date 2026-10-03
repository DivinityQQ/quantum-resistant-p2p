"""Links into the specification, so every explanation can name and open its source."""

import re
from typing import Final

SPEC_URL: Final = "https://github.com/DivinityQQ/quantum-resistant-p2p/blob/main/docs/v2/DESIGN.md"

SECTIONS: Final[dict[str, str]] = {
    "3.2": "Security properties",
    "3.5": "Honest limits",
    "4": "Cryptographic profiles",
    "4.2": "X-Wing",
    "4.3": "X25519-KEM (`LAB-CLASSICAL` only)",
    "4.4": "Hybrid signature",
    "5.1": "Identity bundle",
    "5.2": "Safety number",
    "5.3": "Trust states",
    "6.3": "Framing",
    "7.1": "Overview",
    "7.2": "Message layouts",
    "7.3": "Transcript",
    "7.4": "Key schedule",
    "7.5": "Processing rules",
    "7.6": "Admission policy (responder)",
    "7.7": "Profile selection",
    "8.1": "Records",
    "8.2": "Inner messages",
    "8.4": "Key evolution",
    "8.5": "Liveness, receipts, close",
    "9": "File transfer",
    "11.1": "Visibility tiers",
    "11.3": "Glass-box sessions",
    "11.4": "Values exposed in glass-box sessions",
    "Appendix B": "Codes",
}
"""The DESIGN sections the Inspector cites, by number, with their exact headings."""

_TOP: Final = {
    "4": "4. Cryptographic profiles",
    "9": "9. File transfer",
    "Appendix B": "Appendix B — Codes",
}


def anchor(section: str) -> str:
    """GitHub's anchor for a DESIGN heading (lowercase, punctuation dropped, spaces to dashes)."""
    heading = _TOP.get(section) or f"{section} {SECTIONS[section]}"
    slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
    return f"#{slug}"


def link(section: str) -> str:
    """The URL of a DESIGN section."""
    return SPEC_URL + anchor(section)


def cite(section: str) -> str:
    """How a citation reads: ``DESIGN §7.2`` or ``DESIGN Appendix B``."""
    return f"DESIGN {section}" if section.startswith("Appendix") else f"DESIGN §{section}"
