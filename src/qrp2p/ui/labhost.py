"""The services-thread side of the solo lab: the current run, its trace bus and its tap.

The lab runs where the node runs, on the services thread; the Qt side only ever sees
:class:`LabSnap` values and the lab Inspector's trace updates. A reset, a fork or a loaded
recording replaces the run: the bus is cleared and the new run's two views get new session IDs,
so nothing of the old run can be mistaken for the new one. A lock ends the lab like everything
else of the unlocked period: its run, identities and revealed values are dropped.
"""

import itertools
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from qrp2p.lab.classical import LAB_PROFILES, lab_profile_named
from qrp2p.lab.solo import Kind, LabError, Side, SoloLab, Step
from qrp2p.services.trace_bus import SessionInfo, TraceBus
from qrp2p.ui.inspect.model import SessionFacts
from qrp2p.ui.tap import TraceTap, profile_facts

DEFAULT_PROFILE: Final = "HYBRID-1"
PROFILES: Final = tuple(p.name for p in LAB_PROFILES)
"""The profiles the lab offers, ``LAB-CLASSICAL`` last."""


@dataclass(frozen=True, slots=True)
class LabStepSnap:
    """A step taken: its number (from 1), who acted, and what it did."""

    number: int
    actor: str
    """``alice`` or ``bob`` (for a delivery: the receiver)."""
    kind: str
    text: str


@dataclass(frozen=True, slots=True)
class LabSnap:
    """The lab as the Qt side shows it."""

    active: bool
    profile: str
    phase: str
    """``ready``, ``running``, ``idle``, ``ended`` or ``diverged`` (see :class:`Phase`)."""
    note: str
    steps: tuple[LabStepSnap, ...]
    in_flight: tuple[str, ...]
    """``Hello · Alice → Bob``, oldest first."""
    next_step: str
    """What Step does now; empty if nothing."""
    alice_session: int
    bob_session: int
    alice_open: bool
    bob_open: bool
    can_rekey: bool
    deciding: bool
    """Bob must admit or decline Alice."""
    alice_received: tuple[str, ...]
    bob_received: tuple[str, ...]
    lab_time: float


INACTIVE: Final = LabSnap(
    active=False,
    profile=DEFAULT_PROFILE,
    phase="ready",
    note="",
    steps=(),
    in_flight=(),
    next_step="",
    alice_session=-1,
    bob_session=-1,
    alice_open=False,
    bob_open=False,
    can_rekey=False,
    deciding=False,
    alice_received=(),
    bob_received=(),
    lab_time=0.0,
)


class LabHost:
    """The solo lab of one unlocked period (services thread).

    Args:
        wake: Asks the host to flush soon (the lab tap's updates are pending).
        random_source: Fresh randomness for new runs and forks.
    """

    def __init__(
        self, wake: Callable[[], None], random_source: Callable[[int], bytes] = os.urandom
    ) -> None:
        self._bus = TraceBus()
        self._tap = TraceTap(self._bus, self._describe, wake, source="lab")
        self._random = random_source
        self._ids = itertools.count(1)
        self._lab: SoloLab | None = None

    @property
    def tap(self) -> TraceTap:
        """The lab Inspector's tap."""
        return self._tap

    def snapshot(self) -> LabSnap:
        """Where the lab is now."""
        lab = self._lab
        if lab is None:
            return INACTIVE
        steps = tuple(
            LabStepSnap(n, step.side.value, step.kind.value, note)
            for n, (step, note) in enumerate(zip(lab.steps, lab.notes, strict=True), start=1)
        )
        flight = tuple(
            f"{f.label} · {f.sender.person} → {f.sender.other.person}" for f in lab.in_flight
        )
        upcoming = lab.next_step()
        alice, bob = lab.session_ids
        return LabSnap(
            active=True,
            profile=lab.profile.name,
            phase=lab.phase.value,
            note=lab.note,
            steps=steps,
            in_flight=flight,
            next_step=lab.describe(upcoming) if upcoming is not None else "",
            alice_session=alice,
            bob_session=bob,
            alice_open=lab.is_open(Side.ALICE),
            bob_open=lab.is_open(Side.BOB),
            can_rekey=lab.can_rekey(),
            deciding=upcoming is not None and upcoming.kind is Kind.ADMIT,
            alice_received=lab.received(Side.ALICE),
            bob_received=lab.received(Side.BOB),
            lab_time=lab.now,
        )

    # -- requests ----------------------------------------------------------------------------

    def new(self, profile_name: str) -> LabSnap:
        """A fresh experiment with new identities (also Reset).

        Raises:
            LabError: No such lab profile.
        """
        profile = lab_profile_named(profile_name)
        if profile is None:
            msg = f"no lab profile named {profile_name!r}"
            raise LabError(msg)
        self._replace(lambda ids: SoloLab.fresh(profile, self._bus, ids, self._random))
        return self.snapshot()

    def step(self) -> LabSnap:
        """Take the default step (deliver the oldest frame, admit, or start).

        Raises:
            LabError: Nothing to do, or no run.
        """
        lab = self._current()
        upcoming = lab.next_step()
        if upcoming is None:
            msg = "nothing is in flight: choose what happens next"
            raise LabError(msg)
        lab.take(upcoming)
        return self.snapshot()

    def run(self) -> LabSnap:
        """Take default steps until nothing is in flight or waiting for a decision."""
        self._current().run()
        return self.snapshot()

    def take(self, kind: str, side: str, text: str = "") -> LabSnap:
        """Take a chosen step.

        Raises:
            LabError: The step cannot be taken now, or no run.
            ValueError: ``kind`` or ``side`` is not one the lab knows.
        """
        self._current().take(Step(Kind(kind), Side(side), text))
        return self.snapshot()

    def fork(self, upto: int) -> LabSnap:
        """Replace the run with a fork after step ``upto``: replayed to there, then live.

        Raises:
            LabError: No run, or ``upto`` is not a step of it.
        """
        record = self._current().run_record()
        if not 0 <= upto <= len(record.steps):
            msg = "there is no such step to fork at"
            raise LabError(msg)
        self._replace(
            lambda ids: SoloLab.replayed(
                record, self._bus, ids, upto=upto, random_source=self._random
            )
        )
        return self.snapshot()

    def close(self) -> None:
        """End the lab: drop the run, its bus and what the tap holds (a lock, the app closing)."""
        self._lab = None
        self._tap.close()
        self._bus.clear()

    # -- internals -----------------------------------------------------------------------------

    def _current(self) -> SoloLab:
        if self._lab is None:
            msg = "the lab has no run: start one"
            raise LabError(msg)
        return self._lab

    def _replace(self, make: Callable[[tuple[int, int]], SoloLab]) -> None:
        self._tap.pause()
        self._bus.clear()
        self._lab = make((next(self._ids), next(self._ids)))

    def _describe(self, info: SessionInfo) -> SessionFacts:
        local, peer = ("Alice", "Bob") if info.initiator else ("Bob", "Alice")
        return SessionFacts(
            session_id=info.session_id,
            initiator=info.initiator,
            address=info.address,
            profile=profile_facts(info.profile) if info.profile else None,
            local_name=local,
            peer_name=peer,
            peer_short_id=info.peer_short_id,
            contact_id="",
            trust="",
            pinned_before=info.pinned,
            glass_box_requested=False,
            glass_box=False,
            exposed=True,
            lab=True,
            established=info.established,
            ended=info.ended,
            end_reason=info.end_reason,
            admit_reason=info.admit_reason,
            by_peer=info.by_peer,
        )
