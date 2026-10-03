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
from dataclasses import dataclass, replace
from typing import Final

from qrp2p.lab.classical import LAB_PROFILES, lab_profile_named
from qrp2p.lab.recording import LabRecording
from qrp2p.lab.solo import Kind, LabError, Side, SoloLab, Step
from qrp2p.services.node import Node
from qrp2p.services.recordings import RecordingInfo, restored
from qrp2p.services.trace_bus import SessionInfo, TraceBus
from qrp2p.ui.inspect.model import SessionFacts
from qrp2p.ui.tap import TraceTap, session_facts

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
    recording: str = ""
    """While a glass-box recording is shown (view only): its title; empty for a lab run."""


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
        self,
        wake: Callable[[], None],
        random_source: Callable[[int], bytes] = os.urandom,
        node: Node | None = None,
    ) -> None:
        self._bus = TraceBus()
        self._tap = TraceTap(self._bus, self._describe, wake, source="lab")
        self._random = random_source
        self._node = node
        self._ids = itertools.count(1)
        self._lab: SoloLab | None = None
        self._viewing: tuple[str, str, int] | None = None
        """A glass-box recording on show: its title, profile and bus session ID."""

    @property
    def tap(self) -> TraceTap:
        """The lab Inspector's tap."""
        return self._tap

    def snapshot(self) -> LabSnap:
        """Where the lab is now."""
        if self._viewing is not None:
            title, profile, session_id = self._viewing
            return replace(
                INACTIVE,
                active=True,
                profile=profile,
                phase="recording",
                note="A glass-box recording: view only. It cannot be replayed, because the "
                "peer's randomness and keys were never this side's.",
                alice_session=session_id,
                recording=title,
            )
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

    async def save(self, title: str) -> RecordingInfo:
        """Save the current run as a recording (an explicit action, never automatic).

        Raises:
            LabError: No run (a recording on show is saved already).
            RecordingError: Beyond a bound.
        """
        if self._viewing is not None:
            msg = "this recording is saved already"
            raise LabError(msg)
        return await self._recordings().save_lab_recording(title, self._current().run_record())

    async def open(self, file_id: str) -> LabSnap:
        """Open a saved recording: a lab run replays, then continues live.

        A glass-box recording is shown instead, view only.

        Raises:
            RecordingError: No such recording, or it does not decode.
            VaultError: It does not open with this vault.
        """
        recording = await self._recordings().open_recording(file_id)
        if isinstance(recording, LabRecording):
            run = recording.run
            self._replace(
                lambda ids: SoloLab.replayed(run, self._bus, ids, random_source=self._random)
            )
        else:
            self._tap.pause()
            self._bus.clear()
            self._lab = None
            session_id = next(self._ids)
            info, records = restored(recording, session_id)
            self._bus.restore(info, records)
            self._viewing = (recording.meta.title, recording.meta.profile, session_id)
        return self.snapshot()

    def close(self) -> None:
        """End the lab: drop the run, its bus and what the tap holds (a lock, the app closing)."""
        self._lab = None
        self._viewing = None
        self._tap.close()
        self._bus.clear()

    # -- internals -----------------------------------------------------------------------------

    def _recordings(self) -> Node:
        if self._node is None:
            msg = "recordings need the node"
            raise LabError(msg)
        return self._node

    def _current(self) -> SoloLab:
        if self._lab is None:
            msg = "the lab has no run: start one"
            raise LabError(msg)
        return self._lab

    def _replace(self, make: Callable[[tuple[int, int]], SoloLab]) -> None:
        self._tap.pause()
        self._bus.clear()
        self._viewing = None
        self._lab = make((next(self._ids), next(self._ids)))

    def _describe(self, info: SessionInfo) -> SessionFacts:
        if self._viewing is not None and info.session_id == self._viewing[2]:
            # A glass-box recording: our side of it, every value revealed (EXPOSED).
            peer = info.peer_short_id or "Peer"
            return session_facts(
                info, local_name="You", peer_name=peer, exposed=True, recorded=True
            )
        local, peer = ("Alice", "Bob") if info.initiator else ("Bob", "Alice")
        return session_facts(info, local_name=local, peer_name=peer, exposed=True, lab=True)
