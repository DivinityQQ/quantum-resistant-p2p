"""Named failure codes (DESIGN Appendix B) and the one exception that carries them.

Every failure in the protocol has a named reason; there is no silent fallback. Messages attached
to :class:`ProtocolError` are fixed, developer-written strings and never contain peer data or key
material.
"""

from enum import IntEnum, unique
from typing import override


@unique
class CloseReason(IntEnum):
    """Why a session or handshake ended (``close.reason``, DESIGN Appendix B)."""

    NORMAL = 0
    DECRYPT_FAILED = 1
    UNEXPECTED_MESSAGE = 2
    OVERSIZE = 3
    SCHEMA_ERROR = 4
    SIGNATURE_INVALID = 5
    FINISHED_INVALID = 6
    PIN_MISMATCH = 7
    POLICY = 8
    TIMEOUT = 9
    REPLACED = 10
    RATE_LIMITED = 11
    INTERNAL = 12
    LOCKED = 13
    KEM_FAILURE = 14
    REFLECTION = 15
    INVALID_KEM_KEY = 16

    @property
    def label(self) -> str:
        """The name shown in the UI and the Inspector, e.g. ``decrypt_failed``."""
        return self.name.lower()


@unique
class AdmitReason(IntEnum):
    """Why the responder rejected an initiator (``AdmitBody.reason``, DESIGN §7.6)."""

    NONE = 0
    DECLINED = 1
    PROFILE_POLICY = 2
    TIMEOUT = 3
    BUSY = 4

    @property
    def label(self) -> str:
        """The name shown in the UI and the Inspector, e.g. ``profile_policy``."""
        return self.name.lower()


@unique
class FileCancelReason(IntEnum):
    """Why a file transfer was cancelled (``file_cancel.reason``, DESIGN §9)."""

    USER = 0
    SIZE_MISMATCH = 1
    HASH_MISMATCH = 2
    DISK_FULL = 3
    LIMIT = 4

    @property
    def label(self) -> str:
        """The name shown in the UI, e.g. ``hash_mismatch``."""
        return self.name.lower()


class ProtocolError(Exception):
    """A failure with a named :class:`CloseReason`.

    Args:
        reason: The close reason; decides what the peer and the UI are told.
        detail: A fixed, developer-written explanation for logs. Never peer data or secrets.
    """

    def __init__(self, reason: CloseReason, detail: str = "") -> None:
        super().__init__(reason, detail)
        self.reason = reason
        self.detail = detail

    @override
    def __str__(self) -> str:
        return f"{self.reason.label}: {self.detail}" if self.detail else self.reason.label
