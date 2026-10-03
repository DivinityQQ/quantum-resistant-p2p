"""The protocol timeline: a session's trace as rows of a sequence diagram (UI_DESIGN §7.2).

Each row is one observation of the local node, in ordinal order:

- a **frame** row for each handshake frame sent or received;
- a **record** row for each record (its frame and its counters merged); a run of ordinary
  records (chat, files, receipts, pings) collapses into one **group** row whose records can be
  listed; control records (KeyUpdate, the rekey steps, close) always stand on their own;
- a **schedule** row for each run of key-schedule events (secrets derived, transcript hashes,
  references released), which the Keys view shows in full;
- **local** rows for state changes, key switches and rekey steps; a **closed** row for the end;
- a **gap** row wherever events were evicted: "Earlier events no longer retained".

Times are relative to the first retained event and come from this node's monotonic clock: the
peer's lane shows what this node sent and received, not anything measured on the peer.

The builder is incremental, because a file transfer appends hundreds of records a second: only
the newest row changes when events arrive.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Final

from qrp2p.core.trace import (
    FrameTraced,
    KeysSwitched,
    RecordTraced,
    RekeyStep,
    SecretDerived,
    SecretsReleased,
    SessionClosed,
    StateChanged,
    TranscriptHashed,
)
from qrp2p.core.wire import FrameType
from qrp2p.ui.inspect.fields import HEADER_LEN, frame_name
from qrp2p.ui.inspect.model import TraceItem

CONTROL_KINDS: Final = frozenset(
    {"key_update", "rekey_offer", "rekey_answer", "rekey_finish", "rekey_switch", "close"}
)
"""Records that change keys or end the session: never collapsed into a group."""

QUIET_CLOSES: Final = frozenset({"normal", "locked", "replaced"})
"""Close reasons that are not a failure."""


@dataclass(frozen=True, slots=True)
class TimelineRow:
    """One row of the sequence diagram."""

    key: str
    kind: str
    """``frame``, ``record``, ``group``, ``schedule``, ``local``, ``closed`` or ``gap``."""
    first: int
    """The first ordinal the row stands for."""
    last: int
    """The last ordinal the row stands for."""
    time: float
    """Seconds since the first retained event."""
    direction: str
    """``out`` or ``in`` for frames and records (and groups going one way); else empty."""
    title: str
    detail: str
    tone: str
    """Empty, ``danger`` for a failure, ``accent`` for a key change."""
    count: int
    """Records in a group; events in a schedule run; evicted events in a gap; else 1."""
    frame: int
    """The ordinal of the row's frame event, for the Messages view; -1 if it has none."""
    member: bool = False
    """A record listed under its expanded group."""


@dataclass(slots=True)
class _Run:
    """The group or schedule row at the end, still growing."""

    kind: str
    kinds: list[str] = field(default_factory=list[str])
    out: int = 0
    total: int = 0
    derived: int = 0
    hashed: int = 0
    released: int = 0


def _size(n: int) -> str:
    return f"{n:,} B"


class Timeline:
    """Builds :class:`TimelineRow` values from trace items as they arrive."""

    __slots__ = ("_members", "_next", "_origin", "_pending", "_rows", "_run")

    def __init__(self) -> None:
        self._rows: list[TimelineRow] = []
        self._members: dict[str, list[TimelineRow]] = {}
        self._run: _Run | None = None
        self._origin: float | None = None
        self._next = 0
        """The ordinal expected next; a larger one means events were evicted."""
        self._pending: tuple[TraceItem, FrameTraced] | None = None
        """A received or sent record frame waiting for its counters."""

    @property
    def origin(self) -> float | None:
        """The monotonic time of the first retained event: the clock's zero."""
        return self._origin

    def rows(self, expanded: Iterable[str] = ()) -> tuple[TimelineRow, ...]:
        """Every row so far, with the records of the ``expanded`` groups after them."""
        opened = set(expanded)
        rows: list[TimelineRow] = []
        for row in self._rows:
            rows.append(row)
            if row.key in opened:
                rows.extend(self._members.get(row.key, ()))
        pending = self._pending_row()
        if pending is not None:
            rows.append(pending)
        return tuple(rows)

    def members(self, key: str) -> tuple[TimelineRow, ...]:
        """The records of a group row."""
        return tuple(self._members.get(key, ()))

    def extend(self, items: Iterable[TraceItem]) -> None:
        """Add items in ordinal order (items at or before the last seen ordinal are ignored)."""
        for item in items:
            if item.ordinal < self._next:
                continue
            if self._origin is None:
                self._origin = item.time
            if item.ordinal > self._next:
                self._flush_pending()
                self._gap(item, item.ordinal - self._next)
            self._next = item.ordinal + 1
            self._add(item)

    # -- internals -------------------------------------------------------------------------------

    def _time(self, item: TraceItem) -> float:
        assert self._origin is not None  # noqa: S101  # set by the first item
        return item.time - self._origin

    def _append(self, row: TimelineRow, run: _Run | None = None) -> None:
        self._rows.append(row)
        self._run = run

    def _gap(self, item: TraceItem, missing: int) -> None:
        self._append(
            TimelineRow(
                key=f"gap:{item.ordinal}",
                kind="gap",
                first=item.ordinal - missing,
                last=item.ordinal - 1,
                time=self._time(item),
                direction="",
                title="Earlier events no longer retained",
                detail=f"{missing:,} events evicted from the ring",
                tone="",
                count=missing,
                frame=-1,
            )
        )

    def _add(self, item: TraceItem) -> None:
        event = item.event
        if isinstance(event, FrameTraced) and event.frame.type is FrameType.RECORD:
            self._flush_pending()
            self._pending = (item, event)
            return
        if isinstance(event, RecordTraced):
            self._record(item, event)
            return
        if not isinstance(
            event,
            FrameTraced
            | SecretDerived
            | TranscriptHashed
            | SecretsReleased
            | StateChanged
            | KeysSwitched
            | RekeyStep
            | SessionClosed,
        ):
            return  # revealed values: shown where they belong, in the Keys and Messages views
        self._flush_pending()
        match event:
            case FrameTraced():
                self._frame(item, event)
            case SecretDerived() | TranscriptHashed() | SecretsReleased():
                self._schedule(item, event)
            case StateChanged(machine=machine, state=state):
                title = f"{machine.capitalize()}: {state.replace('_', ' ')}"
                self._local(item, title, "Handshake state machine")
            case KeysSwitched(direction=direction, epoch=epoch, generation=generation):
                which = "Send" if direction.value == "out" else "Receive"
                cause = "KeyUpdate" if event.cause == "key_update" else "PQ rekey"
                detail = f"epoch {epoch}, generation {generation} ({cause})"
                self._local(item, f"{which} keys switched", detail, tone="accent")
            case RekeyStep(step=step, epoch=epoch):
                self._local(item, f"PQ rekey: {step}", f"epoch {epoch}", tone="accent")
            case SessionClosed():
                self._closed(item, event)

    def _frame(self, item: TraceItem, event: FrameTraced) -> None:
        self._append(
            TimelineRow(
                key=f"e:{item.ordinal}",
                kind="frame",
                first=item.ordinal,
                last=item.ordinal,
                time=self._time(item),
                direction=event.direction.value,
                title=frame_name(event),
                detail=_size(len(event.frame.body) + HEADER_LEN),
                tone="",
                count=1,
                frame=item.ordinal,
            )
        )

    def _record(self, item: TraceItem, record: RecordTraced) -> None:
        pending, self._pending = self._pending, None
        start = pending[0] if pending is not None else item
        frame = pending[0].ordinal if pending is not None else -1
        control = record.kind in CONTROL_KINDS
        row = TimelineRow(
            key=f"e:{start.ordinal}",
            kind="record",
            first=start.ordinal,
            last=item.ordinal,
            time=self._time(start),
            direction=record.direction.value,
            title=f"Record · {record.kind}",
            detail=f"seq {record.seq} · epoch {record.epoch}, generation {record.generation} · "
            f"{_size(record.length + HEADER_LEN)}",
            tone="accent" if control else "",
            count=1,
            frame=frame,
        )
        if control:
            self._append(row)
        else:
            self._group(row, record.kind)

    def _group(self, row: TimelineRow, kind: str) -> None:
        run = self._run
        last = self._rows[-1] if self._rows else None
        if last is not None and run is not None and run.kind == "group":
            self._members[last.key].append(replace(row, member=True))
            self._rows[-1] = self._grown(last, run, row, kind)
            return
        if last is not None and last.kind == "record" and not last.tone:
            # A second ordinary record in a row: the two become a group.
            key = f"g:{last.first}"
            run = _Run("group")
            self._members[key] = [replace(last, member=True), replace(row, member=True)]
            group = TimelineRow(
                key=key,
                kind="group",
                first=last.first,
                last=last.last,
                time=last.time,
                direction=last.direction,
                title="",
                detail="",
                tone="",
                count=0,
                frame=-1,
            )
            group = self._grown(group, run, last, _record_kind(last))
            self._rows[-1] = self._grown(group, run, row, kind)
            self._run = run
            return
        self._append(row)

    @staticmethod
    def _grown(group: TimelineRow, run: _Run, row: TimelineRow, kind: str) -> TimelineRow:
        if kind not in run.kinds:
            run.kinds.append(kind)
        run.total += 1
        run.out += row.direction == "out"
        return replace(
            group,
            last=row.last,
            count=run.total,
            direction=group.direction if group.direction == row.direction else "",
            title="Records · " + ", ".join(run.kinds),
            detail=f"{run.total:,} records · {run.out:,} out, {run.total - run.out:,} in",
        )

    def _schedule(
        self, item: TraceItem, event: SecretDerived | TranscriptHashed | SecretsReleased
    ) -> None:
        run = self._run
        last = self._rows[-1] if self._rows else None
        growing = last is not None and run is not None and run.kind == "schedule"
        if not growing or run is None:
            run = _Run("schedule")
        match event:
            case SecretDerived():
                run.derived += 1
            case TranscriptHashed():
                run.hashed += 1
            case SecretsReleased(labels=labels):
                run.released += len(labels)
        detail = _schedule_detail(run)
        if growing and last is not None:
            self._rows[-1] = replace(last, last=item.ordinal, count=last.count + 1, detail=detail)
            return
        self._append(
            TimelineRow(
                key=f"s:{item.ordinal}",
                kind="schedule",
                first=item.ordinal,
                last=item.ordinal,
                time=self._time(item),
                direction="",
                title="Key schedule",
                detail=detail,
                tone="",
                count=1,
                frame=-1,
            ),
            run,
        )

    def _local(self, item: TraceItem, title: str, detail: str, *, tone: str = "") -> None:
        self._append(
            TimelineRow(
                key=f"e:{item.ordinal}",
                kind="local",
                first=item.ordinal,
                last=item.ordinal,
                time=self._time(item),
                direction="",
                title=title,
                detail=detail,
                tone=tone,
                count=1,
                frame=-1,
            )
        )

    def _closed(self, item: TraceItem, event: SessionClosed) -> None:
        reason = event.reason.label
        admit = f" ({event.admit_reason.label})" if event.admit_reason is not None else ""
        origin = "Reported by the peer" if event.by_peer else "Closed by this side"
        quiet = reason in QUIET_CLOSES or event.admit_reason is not None
        self._append(
            TimelineRow(
                key=f"e:{item.ordinal}",
                kind="closed",
                first=item.ordinal,
                last=item.ordinal,
                time=self._time(item),
                direction="",
                title=f"Closed: {reason}{admit}",
                detail=origin,
                tone="" if quiet else "danger",
                count=1,
                frame=-1,
            )
        )

    def _pending_row(self) -> TimelineRow | None:
        """A record frame whose counters have not arrived (one that failed to open, say)."""
        if self._pending is None:
            return None
        item, event = self._pending
        incoming = event.direction.value == "in"
        return TimelineRow(
            key=f"e:{item.ordinal}",
            kind="frame",
            first=item.ordinal,
            last=item.ordinal,
            time=self._time(item),
            direction=event.direction.value,
            title="Record (not opened)" if incoming else "Record",
            detail=_size(len(event.frame.body) + HEADER_LEN),
            tone="",
            count=1,
            frame=item.ordinal,
        )

    def _flush_pending(self) -> None:
        row = self._pending_row()
        self._pending = None
        if row is not None:
            self._append(row)


def _record_kind(row: TimelineRow) -> str:
    return row.title.removeprefix("Record · ")


def _schedule_detail(run: _Run) -> str:
    parts: list[str] = []
    if run.derived:
        parts.append(f"{run.derived} derived")
    if run.hashed:
        parts.append(f"{run.hashed} transcript {'hash' if run.hashed == 1 else 'hashes'}")
    if run.released:
        parts.append(f"{run.released} released")
    return " · ".join(parts)
