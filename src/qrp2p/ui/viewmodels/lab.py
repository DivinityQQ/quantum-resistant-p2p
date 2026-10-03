"""The solo lab of one unlocked period, as QML sees it (UI_DESIGN §8, §3.4).

The lab itself runs on the services thread (:mod:`qrp2p.ui.labhost`); every request returns a
fresh :class:`~qrp2p.ui.labhost.LabSnap`, which replaces what is shown. One request at a time:
a step is executed once, and Step, Run and the actions are unavailable while one is under way.
The lab's own Inspector shows Alice's or Bob's view of the run; when a reset or a fork replaces
the run, it reopens on the new run's views.
"""

from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal, Slot

from qrp2p.ui import ops
from qrp2p.ui.bridge import Scope
from qrp2p.ui.host import Op
from qrp2p.ui.labhost import DEFAULT_PROFILE, INACTIVE, PROFILES, LabSnap
from qrp2p.ui.snapshots import Reply
from qrp2p.ui.viewmodels.inspector import Inspector
from qrp2p.ui.viewmodels.listmodel import RowModel
from qrp2p.ui.viewmodels.qt import ViewModel, constant, mapped, readonly

SIDES = ("alice", "bob")


@dataclass(frozen=True, slots=True)
class StepRow:
    """A step taken, in the lab's history."""

    key: str
    number: int
    actor: str
    kind: str
    text: str


def _view(snap: LabSnap) -> dict[str, object]:
    return {
        "active": snap.active,
        "profile": snap.profile,
        "phase": snap.phase,
        "note": snap.note,
        "next_step": snap.next_step,
        "in_flight": list(snap.in_flight),
        "alice_open": snap.alice_open,
        "bob_open": snap.bob_open,
        "can_rekey": snap.can_rekey,
        "deciding": snap.deciding,
        "alice_received": list(snap.alice_received),
        "bob_received": list(snap.bob_received),
        "lab_time": snap.lab_time,
        "step_count": len(snap.steps),
    }


class Lab(ViewModel):
    """The solo lab's state and actions.

    Args:
        scope: Requests and updates of this unlocked period.
    """

    changed = Signal()
    busyChanged = Signal()  # noqa: N815
    failed = Signal(str)
    """A request failed; the message says why."""

    steps = constant(QObject, "_steps")
    inspector = constant(QObject, "_inspector")
    profiles = constant(list, "_profiles")
    busy = readonly(bool, "_busy", busyChanged)

    def __init__(self, scope: Scope, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._scope = scope
        self._snap = INACTIVE
        self._view = _view(INACTIVE)
        self._busy = False
        self._profiles = list(PROFILES)
        self._steps: RowModel[StepRow] = RowModel(StepRow, lambda r: r.key, self)
        self._inspector = Inspector(
            scope, preferred=lambda: self._snap.alice_session, parent=self, source="lab"
        )

    # -- properties (all from the last snapshot) -----------------------------------------------

    active = mapped(bool, "_view", "active", changed)
    profile = mapped(str, "_view", "profile", changed)
    phase = mapped(str, "_view", "phase", changed)
    """``ready``, ``running``, ``idle``, ``ended`` or ``diverged``."""
    note = mapped(str, "_view", "note", changed)
    nextStep = mapped(str, "_view", "next_step", changed)  # noqa: N815
    inFlight = mapped(list, "_view", "in_flight", changed)  # noqa: N815
    aliceOpen = mapped(bool, "_view", "alice_open", changed)  # noqa: N815
    bobOpen = mapped(bool, "_view", "bob_open", changed)  # noqa: N815
    canRekey = mapped(bool, "_view", "can_rekey", changed)  # noqa: N815
    deciding = mapped(bool, "_view", "deciding", changed)
    aliceReceived = mapped(list, "_view", "alice_received", changed)  # noqa: N815
    bobReceived = mapped(list, "_view", "bob_received", changed)  # noqa: N815
    labTime = mapped(float, "_view", "lab_time", changed)  # noqa: N815
    stepCount = mapped(int, "_view", "step_count", changed)  # noqa: N815

    @property
    def snapshot(self) -> LabSnap:
        """What is shown (tests read it)."""
        return self._snap

    @property
    def inspector_model(self) -> Inspector:
        """The lab's Inspector (Python side; QML reads ``inspector``)."""
        return self._inspector

    # -- slots ----------------------------------------------------------------------------------

    @Slot()
    def enter(self) -> None:
        """The lab screen opened: show the run, starting one if there is none."""
        if self._snap.active:
            self._inspector.setOpen(True)
            self._request(ops.lab_state())
        else:
            self._request(ops.lab_new(DEFAULT_PROFILE))

    @Slot()
    def leave(self) -> None:
        """The lab screen closed; the run stays until Reset or the lock."""
        self._inspector.setOpen(False)

    @Slot(str)
    def reset(self, profile: str) -> None:
        """A fresh experiment (new identities) with ``profile``."""
        self._request(ops.lab_new(profile))

    @Slot()
    def step(self) -> None:
        """Take the default step."""
        self._request(ops.lab_step())

    @Slot()
    def run(self) -> None:
        """Take default steps until nothing is in flight or waiting."""
        self._request(ops.lab_run())

    @Slot()
    def wait(self) -> None:
        """Let 30 seconds pass on the lab clock."""
        self._take("wait", "alice")

    @Slot(str, str, result=bool)
    def chat(self, side: str, text: str) -> bool:
        """Send a chat from ``side``; ``False`` (keep the text) if not possible now."""
        if not text.strip() or self._busy or side not in SIDES:
            return False
        return self._take("chat", side, text)

    @Slot(str)
    def keyUpdate(self, side: str) -> None:  # noqa: N802
        """``side`` moves its sending direction to new keys."""
        self._take("key_update", side)

    @Slot()
    def rekey(self) -> None:
        """Alice starts a PQ rekey."""
        self._take("rekey", "alice")

    @Slot(str)
    def closeSession(self, side: str) -> None:  # noqa: N802
        """``side`` closes the session."""
        self._take("close", side)

    @Slot(bool)
    def decide(self, admit: bool) -> None:  # noqa: FBT001
        """Bob admits or declines Alice."""
        self._take("admit" if admit else "decline", "bob")

    @Slot(int)
    def fork(self, number: int) -> None:
        """Replace the run with a fork after step ``number``: replayed to there, then live."""
        self._request(ops.lab_fork(number))

    # -- internals -----------------------------------------------------------------------------

    def _take(self, kind: str, side: str, text: str = "") -> bool:
        if side not in SIDES:
            return False
        return self._request(ops.lab_take(kind, side, text))

    def _request(self, op: Op) -> bool:
        if self._busy:
            return False

        def done(reply: Reply) -> None:
            self._set("_busy", value=False, signal=self.busyChanged)
            if reply.error is not None:
                self.failed.emit(reply.error.message)
            elif isinstance(reply.value, LabSnap):
                self._show(reply.value)

        if not self._scope.request(op, done):
            return False
        self._set("_busy", value=True, signal=self.busyChanged)
        return True

    def _show(self, snap: LabSnap) -> None:
        replaced = (snap.alice_session, snap.bob_session) != (
            self._snap.alice_session,
            self._snap.bob_session,
        )
        self._snap = snap
        self._view = _view(snap)
        self._steps.sync(
            [StepRow(str(s.number), s.number, s.actor, s.kind, s.text) for s in snap.steps]
        )
        self.changed.emit()
        if replaced and snap.active:  # a new run: its views replace the old ones
            self._inspector.setOpen(False)
            self._inspector.setOpen(True)
