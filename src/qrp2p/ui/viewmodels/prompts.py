"""Contact requests, glass-box requests and key mismatches, one at a time (UI_DESIGN §6.2, §6.4).

A request is a pending decision, not a reserved slot: accepting it can still end as *busy*, the
initiator can leave, and the deadline can pass. The dialog shows what actually happened, from the
node's answer, and every action names the exact request it answers (the bridge's generation rule
keeps an answer from reaching a request of a later unlock).
"""

import time
from collections.abc import Callable
from typing import Final

from PySide6.QtCore import QTimer, Signal, Slot

from qrp2p.ui import ops
from qrp2p.ui.bridge import Scope
from qrp2p.ui.snapshots import MismatchSnap, PromptSnap, Reply
from qrp2p.ui.text import isolate
from qrp2p.ui.viewmodels.qt import ViewModel, mapped, readonly

CONTACT_REQUEST: Final = "contact_request"
GLASS_BOX: Final = "glass_box"
MISMATCH: Final = "mismatch"


def outcome_text(outcome: str, kind: str, name: str) -> str:
    """What to tell the user after a request closed; empty when nothing needs saying."""
    who = isolate(name) if name else "they"
    match outcome:
        case "busy":
            refused = "QRP2P refused the session: it already has as many open as it allows."
            return f"The contact was saved. {refused}" if kind == CONTACT_REQUEST else refused
        case "gone":
            return f"The contact was saved, but {who} left before the session opened."
        case "expired":
            return "This request expired: nobody answered it within 60 seconds."
        case "withdrawn":
            return "They cancelled the request before you answered."
        case _:
            return ""


class Prompts(ViewModel):
    """The request or mismatch the user is asked about now, and how many wait behind it.

    Args:
        scope: Requests for this unlocked period.
        accepting_contact: Called when the user accepts a contact request, before the answer is
            sent: the node saves and reports the new contact before it answers, and the
            workspace opens that contact's conversation when it appears.
        verify: Called with a contact ID when the user wants to verify after a re-pin.
    """

    changed = Signal()
    tick = Signal()
    finished = Signal(str)
    """A request closed with nothing more to show; the text (may be empty) is for a toast."""

    kind = readonly(str, "_kind", changed)
    """``""``, ``contact_request``, ``glass_box`` or ``mismatch``."""
    stage = readonly(str, "_stage", changed)
    """``ask``, ``confirm`` (a re-pin's second step), ``working`` or ``result``."""
    resultText = readonly(str, "_result", changed)  # noqa: N815
    resultIsError = readonly(bool, "_result_error", changed)  # noqa: N815
    queued = readonly(int, "_queued", changed)
    secondsLeft = readonly(int, "_seconds_left", tick)  # noqa: N815
    promptId = mapped(int, "_fields", "prompt_id", changed)  # noqa: N815
    shortId = mapped(str, "_fields", "short_id", changed)  # noqa: N815
    name = mapped(str, "_fields", "name", changed)
    profile = mapped(str, "_fields", "profile", changed)
    glassBoxRefused = mapped(bool, "_fields", "glass_box_refused", changed)  # noqa: N815
    contactId = mapped(str, "_fields", "contact_id", changed)  # noqa: N815
    expectedShortId = mapped(str, "_fields", "expected_short_id", changed)  # noqa: N815
    actualShortId = mapped(str, "_fields", "actual_short_id", changed)  # noqa: N815
    expectedFingerprint = mapped(str, "_fields", "expected_fingerprint", changed)  # noqa: N815
    actualFingerprint = mapped(str, "_fields", "actual_fingerprint", changed)  # noqa: N815

    def __init__(
        self,
        scope: Scope,
        *,
        accepting_contact: Callable[[], None],
        verify: Callable[[str], None],
    ) -> None:
        super().__init__()
        self._scope = scope
        self._accepting_contact = accepting_contact
        self._verify = verify
        self._queue: list[PromptSnap | MismatchSnap] = []
        self._current: PromptSnap | MismatchSnap | None = None
        self._expires_at = 0.0
        self._kind = ""
        self._stage = ""
        self._result = ""
        self._result_error = False
        self._queued = 0
        self._seconds_left = 0
        self._fields: dict[str, object] = _fields(None)
        self._timer = QTimer(self)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self._count_down)

    # -- updates ---------------------------------------------------------------------------------

    def opened(self, prompt: PromptSnap) -> None:
        """A request waits for an answer."""
        self._queue.append(prompt)
        self._advance()

    def mismatch(self, mismatch: MismatchSnap) -> None:
        """A key mismatch waits for Cancel or Re-pin."""
        self._queue.append(mismatch)
        self._advance()

    def closed(self, prompt_id: int, outcome: str) -> None:
        """A request closed: answered here, expired, or withdrawn by the initiator."""
        current = self._current
        if isinstance(current, PromptSnap) and current.prompt_id == prompt_id:
            if self._stage == "working":
                return  # our own answer: its reply says what happened
            text = outcome_text(outcome, current.kind, current.name)
            self._show_result(text or "This request is no longer waiting.", error=False)
            return
        self._queue = [
            p for p in self._queue if not (isinstance(p, PromptSnap) and p.prompt_id == prompt_id)
        ]
        self._update_queued()

    def pending_mismatch(self, contact_id: str) -> bool:
        """Whether a mismatch for this contact is shown or waiting."""
        items = [self._current, *self._queue]
        return any(isinstance(m, MismatchSnap) and m.contact_id == contact_id for m in items)

    # -- slots -----------------------------------------------------------------------------------

    @Slot(str)
    def accept(self, name: str) -> None:
        """Accept the request (a contact request pins the contact under ``name``)."""
        current = self._current
        if not isinstance(current, PromptSnap) or self._stage != "ask":
            return
        self._answer(current, accept=True, name=name)

    @Slot()
    def decline(self) -> None:
        """Refuse a contact request, or choose a normal session over glass-box."""
        current = self._current
        if not isinstance(current, PromptSnap) or self._stage != "ask":
            return
        self._answer(current, accept=False, name="")

    @Slot()
    def startRepin(self) -> None:  # noqa: N802
        """First step of a re-pin: show its consequences before doing it."""
        if isinstance(self._current, MismatchSnap) and self._stage == "ask":
            self._stage = "confirm"
            self.changed.emit()

    @Slot()
    def back(self) -> None:
        """Leave the re-pin confirmation."""
        if self._stage == "confirm":
            self._stage = "ask"
            self.changed.emit()

    @Slot()
    def repin(self) -> None:
        """Re-pin the contact to the identity that answered (Pinned, never Verified)."""
        current = self._current
        if not isinstance(current, MismatchSnap) or self._stage != "confirm":
            return

        def done(reply: Reply) -> None:
            if reply.error is not None:
                self._show_result(f"Could not re-pin: {reply.error.message}", error=True)
                return
            self._show_result(
                f"{isolate(current.name)} now uses the new identity and is not verified. "
                "Compare safety numbers before you trust it.",
                error=False,
            )

        self._work(ops.resolve_mismatch(current.mismatch_id, repin=True), done)

    @Slot()
    def keep(self) -> None:
        """Cancel after a mismatch: keep the saved identity (the safe default)."""
        current = self._current
        if not isinstance(current, MismatchSnap) or self._stage not in {"ask", "confirm"}:
            return
        self._work(ops.resolve_mismatch(current.mismatch_id, repin=False), lambda _: self._next())

    @Slot()
    def verifyNow(self) -> None:  # noqa: N802
        """After a re-pin: open the safety-number comparison."""
        current = self._current
        if isinstance(current, MismatchSnap):
            self._next()
            self._verify(current.contact_id)

    @Slot()
    def close(self) -> None:
        """Dismiss a result."""
        if self._stage == "result":
            self._next()

    # -- internals -------------------------------------------------------------------------------

    def _answer(self, prompt: PromptSnap, *, accept: bool, name: str) -> None:
        def done(reply: Reply) -> None:
            if reply.error is not None:
                message = reply.error.message
                self._show_result(message[:1].upper() + message[1:], error=True)
                return
            outcome = str(reply.value)
            text = outcome_text(outcome, prompt.kind, name or prompt.name)
            if text:
                self._show_result(text, error=outcome == "busy")
            else:
                self._next(_toast(outcome, prompt, name))

        if accept and prompt.kind == CONTACT_REQUEST:
            self._accepting_contact()  # before the request: the contact appears before its reply
        self._work(ops.answer_prompt(prompt.prompt_id, accept=accept, name=name), done)

    def _work(self, op: ops.Op, done: Callable[[Reply], None]) -> bool:
        if not self._scope.request(op, done):
            return False
        self._stage = "working"
        self._timer.stop()
        self.changed.emit()
        return True

    def _show_result(self, text: str, *, error: bool) -> None:
        self._stage = "result"
        self._result = text
        self._result_error = error
        self._timer.stop()
        self.changed.emit()

    def _next(self, toast: str = "") -> None:
        self._current = None
        self._advance()
        self.finished.emit(toast)

    def _advance(self) -> None:
        if self._current is None and self._queue:
            self._current = self._queue.pop(0)
            current = self._current
            self._kind = MISMATCH if isinstance(current, MismatchSnap) else current.kind
            self._stage = "ask"
            self._result = ""
            self._result_error = False
            self._fields = _fields(current)
            if isinstance(current, PromptSnap):
                self._expires_at = time.monotonic() + current.expires_in
                self._count_down()
                self._timer.start()
            else:
                self._timer.stop()
        elif self._current is None:
            self._kind = ""
            self._stage = ""
            self._fields = _fields(None)
            self._timer.stop()
        self._update_queued(emit=False)
        self.changed.emit()

    def _update_queued(self, *, emit: bool = True) -> None:
        self._queued = len(self._queue)
        if emit:
            self.changed.emit()

    def _count_down(self) -> None:
        left = max(round(self._expires_at - time.monotonic()), 0)
        if left != self._seconds_left:
            self._seconds_left = left
            self.tick.emit()


def _toast(outcome: str, prompt: PromptSnap, name: str) -> str:
    match outcome:
        case "accepted":
            return (
                f"Added {isolate(name or prompt.short_id)}. Compare safety numbers to verify them."
            )
        case "glass_box":
            return "Glass-box session admitted: both of you can see its keys and messages."
        case _:
            return ""


def _fields(item: PromptSnap | MismatchSnap | None) -> dict[str, object]:
    fields: dict[str, object] = {
        "prompt_id": 0,
        "short_id": "",
        "name": "",
        "profile": "",
        "glass_box_refused": False,
        "contact_id": "",
        "expected_short_id": "",
        "actual_short_id": "",
        "expected_fingerprint": "",
        "actual_fingerprint": "",
    }
    match item:
        case PromptSnap():
            fields |= {
                "prompt_id": item.prompt_id,
                "short_id": item.short_id,
                "name": item.name,
                "profile": item.profile,
                "glass_box_refused": item.glass_box_refused,
                "contact_id": item.contact_id,
            }
        case MismatchSnap():
            fields |= {
                "name": item.name,
                "contact_id": item.contact_id,
                "expected_short_id": item.expected_short_id,
                "actual_short_id": item.actual_short_id,
                "expected_fingerprint": item.expected_fingerprint,
                "actual_fingerprint": item.actual_fingerprint,
            }
        case None:
            pass
    return fields
