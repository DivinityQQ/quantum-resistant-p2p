"""The responder's admission policy (DESIGN §7.6) and the glass-box prompt limits.

| Initiator's bundle | ``gb_request`` | Outcome |
| --- | --- | --- |
| Blocked | any | reject ``declined``, no prompt |
| Unknown | 0 | contact-request prompt; accept pins the contact |
| Unknown | 1 | contact-request prompt; glass-box refused (``glass_box = 0``) |
| Pinned / Verified | any | reject ``profile_policy`` if the Hello profile is not the contact's |
| Pinned / Verified | 0 | accept automatically |
| Pinned / Verified | 1 | glass-box consent prompt; decline gives a normal session. While
  prompts for the contact are rate-limited or muted, a normal session without a prompt |

The session manager has already applied the ``busy`` rules (simultaneous open, live-session cap).
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from qrp2p.core.errors import AdmitReason
from qrp2p.services.models import Contact, TrustState

PROMPT_INTERVAL: Final = 60.0
"""At most one glass-box prompt per contact per minute."""
DECLINES_TO_MUTE: Final = 3
MUTE_SECONDS: Final = 3600.0
"""Glass-box prompts are muted for an hour after three declines in a row."""


class PromptKind(StrEnum):
    """What the responder's user is asked."""

    CONTACT_REQUEST = "contact_request"
    GLASS_BOX = "glass_box"


@dataclass(frozen=True, slots=True)
class Accept:
    """Admit without asking."""

    glass_box: bool = False


@dataclass(frozen=True, slots=True)
class Reject:
    """Reject without asking."""

    reason: AdmitReason


@dataclass(frozen=True, slots=True)
class Ask:
    """Ask the user. ``glass_box_refused``: an unknown peer asked for glass-box; say it is off."""

    kind: PromptKind
    glass_box_refused: bool = False


type Decision = Accept | Reject | Ask


def decide(
    contact: Contact | None, *, profile_id: int, gb_request: bool, may_prompt_glass_box: bool
) -> Decision:
    """Apply DESIGN §7.6 to an authenticated initiator.

    Args:
        contact: The contact whose pinned bundle the initiator proved, or ``None`` (unknown).
        profile_id: The Hello's profile.
        gb_request: The Hello's glass-box request.
        may_prompt_glass_box: The :class:`GlassBoxLimiter` allows a prompt for this contact now.
    """
    if contact is None:
        return Ask(PromptKind.CONTACT_REQUEST, glass_box_refused=gb_request)
    if contact.trust is TrustState.BLOCKED:
        return Reject(AdmitReason.DECLINED)
    if profile_id != contact.profile_id:
        return Reject(AdmitReason.PROFILE_POLICY)
    if gb_request and may_prompt_glass_box:
        return Ask(PromptKind.GLASS_BOX)
    return Accept(glass_box=False)


@dataclass(slots=True)
class _PeerPrompts:
    last_prompt: float = float("-inf")
    declines: int = 0
    muted_until: float = float("-inf")


@dataclass(slots=True)
class GlassBoxLimiter:
    """Rate limits for glass-box prompts, per peer (DESIGN §7.6). Kept in memory."""

    _peers: dict[bytes, _PeerPrompts] = field(default_factory=dict[bytes, _PeerPrompts])

    def allows(self, peer_id: bytes, now: float) -> bool:
        """Whether a glass-box prompt for ``peer_id`` may be shown at ``now``."""
        state = self._peers.get(peer_id)
        if state is None:
            return True
        return now >= state.muted_until and now - state.last_prompt >= PROMPT_INTERVAL

    def prompted(self, peer_id: bytes, now: float) -> None:
        """A prompt was shown."""
        self._peers.setdefault(peer_id, _PeerPrompts()).last_prompt = now

    def declined(self, peer_id: bytes, now: float) -> None:
        """The user declined; the third decline in a row mutes the peer for an hour."""
        state = self._peers.setdefault(peer_id, _PeerPrompts())
        state.declines += 1
        if state.declines >= DECLINES_TO_MUTE:
            state.declines = 0
            state.muted_until = now + MUTE_SECONDS

    def accepted(self, peer_id: bytes) -> None:
        """The user accepted; the decline count starts over."""
        state = self._peers.get(peer_id)
        if state is not None:
            state.declines = 0
