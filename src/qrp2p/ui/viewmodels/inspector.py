"""The Inspector of one unlocked period: which session, its trace, and one shared selection.

UI_DESIGN §7: Timeline, Messages, Keys and Security show one session and share a selection (an
event, a frame, a field, a key). The data comes from the services thread's trace tap
(:mod:`qrp2p.ui.tap`) through the bridge, so a lock ends it like everything else of the period.

- **Opening** asks for the session's retained events; its new ones then arrive with each batch.
- **Pause following** stops the forwarding and freezes the views; networking is untouched.
  **Follow live** asks for everything after the last ordinal seen and shows a gap if the ring
  evicted some meanwhile. Nothing queues while paused.
- The Qt side keeps what it was sent, up to :data:`ITEM_CAP` events; beyond that it takes a fresh
  snapshot of what the bus retains (its handshake and its bounded tail).
- The timeline and frame list grow incrementally; the key graph and security facts are rebuilt
  from the few schedule and control events, and only while their view is shown.

Every string here comes from a trace event, a revealed value of an exposed session, or the
specification. A normal session has no revealed values, so no view-model string can hold one.
"""

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Final

from PySide6.QtCore import QObject, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices, QGuiApplication

from qrp2p.core.trace import (
    Direction,
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
from qrp2p.ui import ops
from qrp2p.ui.bridge import Scope
from qrp2p.ui.inspect import fields, keygraph, security
from qrp2p.ui.inspect.fields import FieldRow
from qrp2p.ui.inspect.keygraph import KeyGraph
from qrp2p.ui.inspect.model import RecordOpened, Revealed, SessionFacts, TraceItem, item_bytes
from qrp2p.ui.inspect.security import Fact
from qrp2p.ui.inspect.spec import SECTIONS, cite, link
from qrp2p.ui.inspect.timeline import Timeline, TimelineRow
from qrp2p.ui.snapshots import Reply, Update
from qrp2p.ui.tap import (
    BUFFER_BYTES,
    InspectSnap,
    SessionDescribed,
    SessionRemoved,
    TraceAppended,
    TraceOverflow,
)
from qrp2p.ui.viewmodels.hexmodel import HexModel
from qrp2p.ui.viewmodels.listmodel import RowModel
from qrp2p.ui.viewmodels.qt import ViewModel, constant, items, readonly

ITEM_CAP: Final = 30_000
"""Events kept on the Qt side; beyond it, a fresh snapshot of what the bus retains."""

VIEWS: Final = ("timeline", "messages", "keys", "security")


@dataclass(frozen=True, slots=True)
class SessionRow:
    """A retained session in the Inspector's chooser."""

    key: str
    session_id: int
    title: str
    subtitle: str
    state: str
    """``handshake``, ``open``, ``ended`` or ``failed``."""
    exposure: str
    """``public`` or ``glass_box``."""


@dataclass(frozen=True, slots=True)
class EventRow:
    """A timeline row, as QML shows it."""

    key: str
    kind: str
    first: int
    last: int
    time: str
    direction: str
    title: str
    detail: str
    tone: str
    count: int
    frame: int
    member: bool
    expanded: bool


@dataclass(frozen=True, slots=True)
class FrameRow:
    """A captured frame in the Messages list."""

    key: str
    ordinal: int
    time: str
    direction: str
    name: str
    size: str


@dataclass(frozen=True, slots=True)
class NodeRow:
    """A key-graph node, as QML shows it."""

    key: str
    kind: str
    epoch: int
    column: int
    row: int
    operation: str
    inputs: str
    """The inputs' names, comma-separated (for the dependency list)."""
    outputs: str
    section: str
    """The DESIGN section that defines it (``openSpec`` opens it)."""
    cite: str
    size: int
    state: str
    released: str
    value: str
    ordinal: int


@dataclass(frozen=True, slots=True)
class EdgeRow:
    """A key-graph edge with its ends' grid positions."""

    key: str
    source: str
    target: str
    from_column: int
    from_row: int
    to_column: int
    to_row: int


@dataclass(frozen=True, slots=True)
class FactRow:
    """A security fact, as QML shows it."""

    key: str
    title: str
    value: str
    status: str
    evidence: str
    assumption: str
    ordinal: int
    section: str
    cite: str


def _time(seconds: float) -> str:
    return f"+{seconds:.3f} s"


def _session_row(facts: SessionFacts) -> SessionRow:
    who = facts.peer_name or (facts.address if facts.initiator else f"from {facts.address}")
    role = "Outgoing" if facts.initiator else "Incoming"
    if facts.lab:  # both ends are ours: name the view, and its role in the handshake
        who = f"{facts.local_name}'s view"
        role = "Initiator" if facts.initiator else "Responder"
    profile = facts.profile.name if facts.profile is not None else ""
    if facts.ended:
        failed = bool(facts.end_reason) and facts.end_reason not in {"normal", "locked", "replaced"}
        state = "failed" if failed and not facts.established else "ended"
        reason = facts.admit_reason or facts.end_reason or "connection lost"
        status = f"ended: {reason}"
    else:
        state = "open" if facts.established else "handshake"
        status = "open" if facts.established else "handshake"
    parts = [p for p in (role, profile, status) if p]
    return SessionRow(
        key=str(facts.session_id),
        session_id=facts.session_id,
        title=who or role,
        subtitle=" · ".join(parts),
        state=state,
        exposure="glass_box" if facts.glass_box else "public",
    )


def _event_row(row: TimelineRow, expanded: set[str]) -> EventRow:
    return EventRow(
        key=row.key,
        kind=row.kind,
        first=row.first,
        last=row.last,
        time=_time(row.time),
        direction=row.direction,
        title=row.title,
        detail=row.detail,
        tone=row.tone,
        count=row.count,
        frame=row.frame,
        member=row.member,
        expanded=row.key in expanded,
    )


def _graph_rows(graph: KeyGraph) -> tuple[list[NodeRow], list[EdgeRow]]:
    outputs: dict[str, list[str]] = {}
    for edge in graph.edges:
        outputs.setdefault(edge.source, []).append(edge.target)
    where = {n.key: (n.column, n.row) for n in graph.nodes}
    nodes = [
        NodeRow(
            key=n.key,
            kind=n.kind,
            epoch=n.epoch,
            column=n.column,
            row=n.row,
            operation=n.operation,
            inputs=", ".join(n.inputs),
            outputs=", ".join(outputs.get(n.key, ())),
            section=n.section,
            cite=cite(n.section),
            size=n.size,
            state=n.state,
            released=n.released,
            value=n.value,
            ordinal=n.ordinal,
        )
        for n in graph.nodes
    ]
    edges = [
        EdgeRow(e.key, e.source, e.target, *where[e.source], *where[e.target]) for e in graph.edges
    ]
    return nodes, edges


def _fact_row(fact: Fact) -> FactRow:
    return FactRow(
        key=fact.key,
        title=fact.title,
        value=fact.value,
        status=fact.status,
        evidence=fact.evidence,
        assumption=fact.assumption,
        ordinal=fact.ordinal,
        section=fact.section,
        cite=cite(fact.section),
    )


_SCHEDULE = SecretDerived | TranscriptHashed | SecretsReleased | Revealed
_CONTROL = StateChanged | KeysSwitched | RekeyStep | SessionClosed


class Inspector(ViewModel):
    """The Inspector's state for one unlocked period.

    Args:
        scope: Requests and updates of this unlocked period.
        preferred: The session to open first: the selected conversation's, or -1.
        source: Whose sessions: ``node`` (the messenger's) or ``lab`` (the solo lab's).
    """

    openChanged = Signal()  # noqa: N815
    sessionChanged = Signal()  # noqa: N815
    followingChanged = Signal()  # noqa: N815
    selectionChanged = Signal()  # noqa: N815
    frameChanged = Signal()  # noqa: N815
    graphChanged = Signal()  # noqa: N815
    viewChanged = Signal()  # noqa: N815
    recordingSaved = Signal(str)  # noqa: N815
    """A save finished: what to tell the user."""

    sessions = constant(QObject, "_sessions")
    timeline = constant(QObject, "_timeline_model")
    frames = constant(QObject, "_frames")
    fields = constant(QObject, "_fields")
    hex = constant(QObject, "_hex")
    plaintext = constant(QObject, "_plaintext")
    keyNodes = constant(QObject, "_nodes")  # noqa: N815
    keyEdges = constant(QObject, "_edges")  # noqa: N815
    facts = constant(QObject, "_facts")
    isOpen = readonly(bool, "_open", openChanged)  # noqa: N815
    sessionId = readonly(int, "_session_id", sessionChanged)  # noqa: N815
    title = readonly(str, "_title", sessionChanged)
    localName = readonly(str, "_local_name", sessionChanged)  # noqa: N815
    peerName = readonly(str, "_peer_name", sessionChanged)  # noqa: N815
    """The peer as the timeline's lane names it: its contact name, short ID or address."""
    initiator = readonly(bool, "_initiator", sessionChanged)
    """The local side opened the connection (it is the left, initiator, lane)."""
    subtitle = readonly(str, "_subtitle", sessionChanged)
    exposure = readonly(str, "_exposure", sessionChanged)
    """``public``, ``glass_box`` or ``lab`` (empty with no session)."""
    loading = readonly(bool, "_loading", sessionChanged)
    error = readonly(str, "_error", sessionChanged)
    following = readonly(bool, "_following", followingChanged)
    view = readonly(str, "_view", viewChanged)
    selectedRow = readonly(str, "_selected_row", selectionChanged)  # noqa: N815
    selectedFrame = readonly(int, "_selected_frame", selectionChanged)  # noqa: N815
    selectedField = readonly(str, "_selected_field", selectionChanged)  # noqa: N815
    selectedNode = readonly(str, "_selected_node", selectionChanged)  # noqa: N815
    frameTitle = readonly(str, "_frame_title", frameChanged)  # noqa: N815
    frameDetail = readonly(str, "_frame_detail", frameChanged)  # noqa: N815
    keyColumns = readonly(int, "_key_columns", graphChanged)  # noqa: N815
    keyRows = readonly(int, "_key_rows", graphChanged)  # noqa: N815
    keyPage = readonly(int, "_key_page", graphChanged)  # noqa: N815
    keyPages = readonly(int, "_key_pages", graphChanged)  # noqa: N815

    def __init__(
        self,
        scope: Scope,
        preferred: Callable[[], int],
        parent: QObject | None = None,
        *,
        source: str = "node",
    ) -> None:
        super().__init__(parent)
        self._scope = scope
        self._preferred = preferred
        self._source = source
        self._sessions: RowModel[SessionRow] = RowModel(SessionRow, lambda r: r.key, self)
        self._timeline_model: RowModel[EventRow] = RowModel(EventRow, lambda r: r.key, self)
        self._frames: RowModel[FrameRow] = RowModel(FrameRow, lambda r: r.key, self)
        self._fields: RowModel[FieldRow] = RowModel(FieldRow, lambda r: r.key, self)
        self._hex = HexModel(self)
        self._plaintext = HexModel(self)
        self._nodes: RowModel[NodeRow] = RowModel(NodeRow, lambda r: r.key, self)
        self._edges: RowModel[EdgeRow] = RowModel(EdgeRow, lambda r: r.key, self)
        self._facts: RowModel[FactRow] = RowModel(FactRow, lambda r: r.key, self)
        self._known: dict[int, SessionFacts] = {}
        self._open = False
        self._session_id = -1
        self._facts_now: SessionFacts | None = None
        self._title = ""
        self._local_name = ""
        self._peer_name = ""
        self._initiator = True
        self._subtitle = ""
        self._exposure = ""
        self._loading = False
        self._error = ""
        self._following = True
        self._view = "timeline"
        self._selected_row = ""
        self._selected_frame = -1
        self._selected_field = ""
        self._selected_node = ""
        self._frame_title = ""
        self._frame_detail = ""
        self._key_columns = 0
        self._key_rows = 0
        self._key_page = 0
        self._key_pages = 1
        self._expanded: set[str] = set()
        self._reset_trace()
        scope.updates.connect(self.apply)

    # -- state of the inspected trace --------------------------------------------------------------

    def _reset_trace(self) -> None:
        self._key_page = 0
        self._key_pages = 1
        self._items: list[TraceItem] = []
        self._item_bytes = 0
        self._by_ordinal: dict[int, TraceItem] = {}
        self._schedule: list[TraceItem] = []
        self._control: list[TraceItem] = []
        self._record_of: dict[int, RecordTraced] = {}
        """Record frame ordinal to its counters."""
        self._pending_frames: dict[Direction, int] = {}
        self._opened: dict[tuple[str, int], RecordOpened] = {}
        self._first_in_record: TraceItem | None = None
        self._last = -1
        self._timeline = Timeline()
        self._graph_dirty = True
        self._facts_dirty = True

    @property
    def trace_items(self) -> tuple[TraceItem, ...]:
        """What the Qt side holds of the inspected session (tests read it)."""
        return tuple(self._items)

    # -- slots -------------------------------------------------------------------------------------

    @Slot(bool)
    def setOpen(self, is_open: bool) -> None:  # noqa: FBT001, N802
        """The Inspector pane opened or closed."""
        if is_open == self._open:
            return
        self._open = is_open
        self.openChanged.emit()
        if is_open:
            self._scope.request(ops.inspect_sessions(self._source), self._sessions_listed)
        else:
            self._scope.request(ops.inspect_close(self._source))
            self._clear_session()

    @Slot(int)
    def chooseSession(self, session_id: int) -> None:  # noqa: N802
        """Inspect another retained session."""
        if session_id == self._session_id and not self._error:
            return
        self._following = True
        self.followingChanged.emit()
        self._inspect(session_id, reset=True)

    @Slot(str)
    def setView(self, view: str) -> None:  # noqa: N802
        """The visible tab: the key graph and facts are built only while shown."""
        if view in VIEWS and view != self._view:
            self._view = view
            self.viewChanged.emit()
            self._refresh_derived()

    @Slot()
    def pause(self) -> None:
        """Freeze the display; the session and networking carry on."""
        if self._following and self._session_id >= 0:
            self._following = False
            self.followingChanged.emit()
            self._scope.request(ops.inspect_pause(self._source))

    @Slot()
    def followLive(self) -> None:  # noqa: N802
        """Resume: catch up from the last event seen, then follow."""
        if not self._following and self._session_id >= 0:
            self._following = True
            self.followingChanged.emit()
            self._inspect(self._session_id, reset=False)

    @Slot(str)
    def selectRow(self, key: str) -> None:  # noqa: N802
        """Select a timeline row; a row with a frame selects it in Messages too."""
        row = next((r for r in self._timeline_model.rows() if r.key == key), None)
        if row is None:
            return
        self._selected_row = key
        if row.frame >= 0:
            self._select_frame(row.frame)
        self.selectionChanged.emit()

    @Slot(str)
    def toggleGroup(self, key: str) -> None:  # noqa: N802
        """List a group's records, or collapse them."""
        if key in self._expanded:
            self._expanded.discard(key)
        else:
            self._expanded.add(key)
        self._sync_timeline()
        if self._timeline_model.indexOf(self._selected_row) < 0:  # a record of the folded group
            self._selected_row = key
            self.selectionChanged.emit()

    @Slot(int)
    def selectFrame(self, ordinal: int) -> None:  # noqa: N802
        """Select a captured frame (Messages)."""
        if ordinal in self._by_ordinal:
            self._select_frame(ordinal)
            row = next((r for r in self._timeline_model.rows() if r.frame == ordinal), None)
            if row is not None:
                self._selected_row = row.key
            self.selectionChanged.emit()

    @Slot(str)
    def selectField(self, key: str) -> None:  # noqa: N802
        """Select a field: its bytes are highlighted in the hex view it belongs to."""
        row = next((r for r in self._fields.rows() if r.key == key), None)
        if row is None:
            return
        self._selected_field = key
        target, other = (self._hex, self._plaintext)
        if row.source == "plaintext":
            target, other = other, target
        target.highlight(row.start, row.length)
        other.highlight(0, 0)
        self.selectionChanged.emit()

    @Slot(str, int)
    def selectByte(self, source: str, offset: int) -> None:  # noqa: N802
        """A byte was clicked: select the innermost field that holds it."""
        holding = [
            r
            for r in self._fields.rows()
            if r.source == source and r.length and r.start <= offset < r.start + r.length
        ]
        if holding:
            self.selectField(max(holding, key=lambda r: (r.depth, -r.length)).key)

    @Slot(str)
    def selectNode(self, key: str) -> None:  # noqa: N802
        """Select a key-graph node (or clear the selection with an empty key)."""
        if key != self._selected_node:
            self._selected_node = key
            self.selectionChanged.emit()

    @Slot(int)
    def setKeyPage(self, page: int) -> None:  # noqa: N802
        """Browse a bounded page of the retained key history, newest first."""
        if 0 <= page < self._key_pages and page != self._key_page:
            self._key_page = page
            self.selectNode("")
            self._graph_dirty = True
            self._refresh_derived()

    @Slot(int)
    def showOrdinal(self, ordinal: int) -> None:  # noqa: N802
        """Go to the timeline row holding an event (a fact's evidence, a node's event)."""
        row = next((r for r in self._timeline_model.rows() if r.first <= ordinal <= r.last), None)
        if row is not None:
            self.selectRow(row.key)
            self.setView("timeline")

    @Slot(str)
    def copyField(self, key: str) -> None:  # noqa: N802
        """Copy a field's bytes as hex: an explicit action, never automatic (UI_DESIGN §10)."""
        row = next((r for r in self._fields.rows() if r.key == key), None)
        if row is None or not row.length:
            return
        source = self._plaintext.bytes if row.source == "plaintext" else self._hex.bytes
        _copy(source[row.start : row.start + row.length].hex())

    @Slot(str)
    def copyNodeValue(self, key: str) -> None:  # noqa: N802
        """Copy a revealed value or a transcript hash as hex (only what is shown can be copied)."""
        row = next((r for r in self._nodes.rows() if r.key == key), None)
        if row is not None and row.value:
            _copy(row.value)

    @Slot(str)
    def saveRecording(self, title: str) -> None:  # noqa: N802
        """Save the inspected glass-box session as a recording (an explicit action only)."""
        if self._exposure != "glass_box" or self._session_id < 0:
            return

        def done(reply: Reply) -> None:
            if reply.error is not None:
                self.recordingSaved.emit(f"Not saved: {reply.error.message}")
            else:
                self.recordingSaved.emit("Saved. It is in Learn → Recordings, marked EXPOSED.")

        self._scope.request(ops.save_session_recording(self._session_id, title), done)

    @Slot(str, result=str)
    def cite(self, section: str) -> str:
        """How a section is cited (``DESIGN §7.2``); empty for an unknown one."""
        return cite(section) if section in SECTIONS else ""

    @Slot(str)
    def openSpec(self, section: str) -> None:  # noqa: N802
        """Open a DESIGN section in the browser: only the specification's own URL, by section."""
        if section in SECTIONS:
            QDesktopServices.openUrl(QUrl(link(section)))

    # -- updates -----------------------------------------------------------------------------------

    def apply(self, updates: tuple[Update, ...]) -> None:
        """Take the Inspector's updates from a batch."""
        for update in updates:
            tapped = isinstance(
                update, SessionDescribed | SessionRemoved | TraceAppended | TraceOverflow
            )
            if tapped and update.source != self._source:
                continue  # the other Inspector's
            match update:
                case SessionDescribed(facts=facts):
                    self._described(facts)
                case SessionRemoved(session_id=session_id):
                    self._known.pop(session_id, None)
                    if session_id == self._session_id:
                        retained = self._known.copy()
                        self._clear_session()
                        self._known = retained
                        self._error = (
                            "The selected session is no longer retained. Choose another session."
                        )
                        self.sessionChanged.emit()
                    self._sync_sessions()
                case TraceAppended(session_id=session_id, items=new):
                    if session_id == self._session_id and self._following and not self._loading:
                        self._ingest(new)
                case TraceOverflow(session_id=session_id):
                    if session_id == self._session_id and self._following and not self._loading:
                        self._inspect(session_id, reset=False)
                case _:
                    pass

    def refresh_contact(self, contact_id: str, name: str, trust: str) -> None:
        """A contact changed: its sessions' names and trust in the Inspector follow."""
        changed = False
        for session_id, facts in list(self._known.items()):
            if facts.contact_id == contact_id and (facts.peer_name, facts.trust) != (name, trust):
                self._known[session_id] = replace(facts, peer_name=name, trust=trust)
                changed = True
        if changed:
            self._sync_sessions()
            current = self._known.get(self._session_id)
            if current is not None:
                self._set_facts(current)

    # -- internals ---------------------------------------------------------------------------------

    def _sessions_listed(self, reply: Reply) -> None:
        if not self._open:
            return
        listed = items(reply.value, SessionFacts)
        self._known = {f.session_id: f for f in listed}
        self._sync_sessions()
        preferred = self._preferred()
        if preferred in self._known:
            self._inspect(preferred, reset=True)
        elif listed:
            self._inspect(listed[-1].session_id, reset=True)

    def _described(self, facts: SessionFacts) -> None:
        if not self._open:
            return
        self._known[facts.session_id] = facts
        self._sync_sessions()
        if facts.session_id == self._session_id:
            self._set_facts(facts)

    def _sync_sessions(self) -> None:
        ordered = sorted(self._known.values(), key=lambda f: -f.session_id)
        self._sessions.sync([_session_row(f) for f in ordered])

    def _inspect(self, session_id: int, *, reset: bool) -> None:
        after = -1 if reset else self._last

        def done(reply: Reply) -> None:
            if session_id != self._session_id or not self._open:
                return
            self._loading = False
            if reply.error is not None and reply.error.kind == "trace_overflow":
                self._inspect(session_id, reset=True)
                return
            if reply.error is not None or not isinstance(reply.value, InspectSnap):
                self._error = reply.error.message if reply.error else "Not available."
                self.sessionChanged.emit()
                return
            snap = reply.value
            self._error = ""
            if reset:
                self._reset_trace()
                self._expanded.clear()
                self._frames.clear()
                self._clear_selection()
            # Events evicted while paused show as a gap: the timeline sees the ordinals jump.
            self._set_facts(snap.facts)
            self._ingest(snap.items, snapshot=True)

        if reset:
            self._session_id = session_id
        self._loading = True
        self._error = ""
        self.sessionChanged.emit()
        if not self._scope.request(ops.inspect(session_id, after, self._source), done):
            self._loading = False
            self.sessionChanged.emit()

    def _set_facts(self, facts: SessionFacts) -> None:
        self._facts_now = facts
        self._known[facts.session_id] = facts
        row = _session_row(facts)
        self._title = row.title
        self._local_name = facts.local_name
        self._peer_name = facts.peer_name or facts.address or "Peer"
        self._initiator = facts.initiator
        self._subtitle = row.subtitle
        self._exposure = "lab" if facts.lab else ("glass_box" if facts.exposed else "public")
        self._facts_dirty = self._graph_dirty = True
        self.sessionChanged.emit()
        self._refresh_derived()

    def _clear_session(self) -> None:
        self._session_id = -1
        self._facts_now = None
        self._known.clear()
        self._sessions.clear()
        self._reset_trace()
        self._expanded.clear()
        self._timeline_model.clear()
        self._frames.clear()
        self._nodes.clear()
        self._edges.clear()
        self._facts.clear()
        self._clear_selection()
        self._title = self._subtitle = self._exposure = self._error = ""
        self._local_name = self._peer_name = ""
        self._loading = False
        self._following = True
        self.sessionChanged.emit()
        self.followingChanged.emit()

    def _clear_selection(self) -> None:
        self._selected_row = ""
        self._selected_frame = -1
        self._selected_field = ""
        self._selected_node = ""
        self._fields.clear()
        self._hex.show(b"")
        self._plaintext.show(b"")
        self._frame_title = self._frame_detail = ""
        self.frameChanged.emit()
        self.selectionChanged.emit()

    def _ingest(self, new: tuple[TraceItem, ...], *, snapshot: bool = False) -> None:
        """Add events; live ones beyond :data:`ITEM_CAP` trigger a fresh snapshot instead.

        A snapshot is what the bus retains, which is bounded: it is always taken whole.
        """
        fresh = [i for i in new if i.ordinal > self._last]
        if not fresh:
            return
        cost = sum(item_bytes(i) for i in fresh)
        if (
            (not snapshot or self._items) and len(self._items) + len(fresh) > ITEM_CAP
        ) or self._item_bytes + cost > BUFFER_BYTES:
            self._inspect(self._session_id, reset=True)  # what the bus retains, afresh
            return
        self._item_bytes += cost
        self._timeline.extend(fresh)  # first: it fixes the clock origin the frame rows use
        frames: dict[int, FrameRow] = {}
        for item in fresh:
            self._items.append(item)
            self._by_ordinal[item.ordinal] = item
            self._index(item, frames)
        self._last = fresh[-1].ordinal
        self._sync_timeline()
        self._frames.append(list(frames.values()))
        self._refresh_derived()

    def _index(self, item: TraceItem, frames: dict[int, FrameRow]) -> None:
        """Index one event; ``frames`` collects this batch's new frame rows by ordinal."""
        event = item.event
        match event:
            case FrameTraced():
                if event.frame.type is FrameType.RECORD:
                    self._pending_frames[event.direction] = item.ordinal
                frames[item.ordinal] = self._frame_row(item, event)
            case RecordTraced():
                frame = self._pending_frames.pop(event.direction, None)
                if frame is not None:
                    self._record_of[frame] = event
                    self._name_record(frame, event, frames)
                if event.direction is Direction.IN and self._first_in_record is None:
                    self._first_in_record = item
                    self._facts_dirty = True
            case RecordOpened():
                self._opened[(event.key, event.seq)] = event
            case _ if isinstance(event, _SCHEDULE):
                self._schedule.append(item)
                self._graph_dirty = True
            case _ if isinstance(event, _CONTROL):
                self._control.append(item)
                self._facts_dirty = True
            case _:
                pass

    def _name_record(self, frame: int, record: RecordTraced, frames: dict[int, FrameRow]) -> None:
        """A record frame is named by its kind once its counters arrive (just after it)."""
        row = frames.get(frame)
        if row is not None:
            frames[frame] = replace(row, name=f"Record · {record.kind}")
        else:  # the frame came in an earlier batch
            match = self._frames.indexOf(str(frame))
            if match >= 0:
                old = self._frames.rows()[match]
                self._frames.update(replace(old, name=f"Record · {record.kind}"))

    def _frame_row(self, item: TraceItem, event: FrameTraced) -> FrameRow:
        origin = self._timeline.origin if self._timeline.origin is not None else item.time
        return FrameRow(
            key=str(item.ordinal),
            ordinal=item.ordinal,
            time=_time(item.time - origin),
            direction=event.direction.value,
            name=fields.frame_name(event),
            size=f"{len(event.frame.body) + fields.HEADER_LEN:,} B",
        )

    def _sync_timeline(self) -> None:
        """Update the rows; the selected row's detail follows when its row changed."""
        old = self._row(self._selected_row)
        rows = self._timeline.rows(self._expanded)
        self._timeline_model.sync([_event_row(r, self._expanded) for r in rows])
        if old is not None and self._row(self._selected_row) != old:
            self.selectionChanged.emit()

    def _node(self, key: str) -> NodeRow | None:
        index = self._nodes.indexOf(key) if key else -1
        return self._nodes.rows()[index] if index >= 0 else None

    def _row(self, key: str) -> EventRow | None:
        index = self._timeline_model.indexOf(key) if key else -1
        return self._timeline_model.rows()[index] if index >= 0 else None

    def _refresh_derived(self) -> None:
        facts = self._facts_now
        if facts is None:
            return
        if self._view == "keys" and self._graph_dirty:
            self._graph_dirty = False
            graph = keygraph.build(self._schedule, facts, page=self._key_page)
            nodes, edges = _graph_rows(graph)
            old = self._node(self._selected_node)
            self._nodes.sync(nodes)
            self._edges.sync(edges)
            self._key_columns, self._key_rows = graph.columns, graph.rows
            self._key_pages, self._key_page = graph.pages, graph.page
            self.graphChanged.emit()
            if old is not None and self._node(self._selected_node) != old:
                self.selectionChanged.emit()
        if self._view == "security" and self._facts_dirty:
            self._facts_dirty = False
            control = list(self._control)
            if self._first_in_record is not None:
                control.append(self._first_in_record)
            control.sort(key=lambda i: i.ordinal)
            self._facts.sync([_fact_row(f) for f in security.build(control, facts)])

    def _select_frame(self, ordinal: int) -> None:
        item = self._by_ordinal.get(ordinal)
        if item is None or not isinstance(item.event, FrameTraced):
            return
        event = item.event
        self._selected_frame = ordinal
        self._selected_field = ""
        rows = fields.frame_fields(event)
        opened = self._opened_for(ordinal, event)
        facts = self._facts_now
        if opened is not None:
            profile = facts.profile if facts is not None else None
            rows += fields.plaintext_fields(event.frame.type, opened, profile)
        self._fields.reset(rows)
        self._hex.show(event.frame.encode())
        self._plaintext.show(opened.plaintext if opened is not None else b"")
        record = self._record_of.get(ordinal)
        name = fields.frame_name(event)
        if record is not None:
            name = f"Record · {record.kind}"
        arrow = "sent" if event.direction is Direction.OUT else "received"
        self._frame_title = name
        detail = [f"{arrow}, {len(event.frame.body) + fields.HEADER_LEN:,} bytes"]
        if record is not None:
            detail.append(
                f"seq {record.seq}, epoch {record.epoch}, generation {record.generation} "
                "(local counters: never sent)"
            )
        if opened is not None:
            detail.append("decrypted with this session's revealed keys")
        elif self._exposure == "public" and event.frame.type is not FrameType.HELLO:
            detail.append("sealed: a public trace never holds plaintext")
        self._frame_detail = " · ".join(detail)
        self.frameChanged.emit()

    def _opened_for(self, ordinal: int, event: FrameTraced) -> RecordOpened | None:
        if self._facts_now is None or not self._facts_now.exposed:
            return None
        key = fields.HANDSHAKE_KEYS.get(event.frame.type)
        if key is not None:
            return self._opened.get(key)
        record = self._record_of.get(ordinal)
        if record is None:
            return None
        label = fields.record_key(record, initiator=self._facts_now.initiator)
        return self._opened.get((label, record.seq))


def _copy(text: str) -> None:
    QGuiApplication.clipboard().setText(text)
