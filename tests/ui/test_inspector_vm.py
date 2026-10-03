"""The Inspector's view model against a fake services side (UI_DESIGN §7, §11.3, §13.2).

Opening picks the selected conversation's session; events append in order and only once; a
paused display ignores what arrives and catches up on resume; a gap is shown, never hidden;
selection is shared between rows, frames, fields and bytes; the key graph and facts are built
only while their view is shown; a normal session's view-model strings hold no secret.
"""

from collections.abc import Iterator
from dataclasses import replace

import pytest
from PySide6.QtCore import QCoreApplication

from qrp2p.core.crypto.provider import Revealed as RevealedValue
from qrp2p.core.trace import Direction, FrameTraced
from qrp2p.core.wire import Frame, FrameType
from qrp2p.ui.inspect.model import Revealed, SessionFacts, TraceItem, item_bytes
from qrp2p.ui.inspect.spec import SPEC_URL
from qrp2p.ui.inspect.timeline import Timeline
from qrp2p.ui.snapshots import ContactChanged, ErrorInfo
from qrp2p.ui.tap import InspectSnap, SessionDescribed, SessionRemoved, TraceAppended, TraceOverflow
from qrp2p.ui.viewmodels.application import AppController
from qrp2p.ui.viewmodels.inspector import ITEM_CAP, Inspector
from qrp2p.ui.viewmodels.workspace import Workspace
from tests.ui.fakes import FakeBackend, contact, online, settle
from tests.ui.inspect_support import scripted, secret_hexes, session_facts
from tests.ui.test_viewmodels import unlock

BOB = contact("Bob", created=1000.0)


@pytest.fixture
def backend(qapp: QCoreApplication) -> FakeBackend:  # noqa: ARG001
    return FakeBackend()


@pytest.fixture
def app(backend: FakeBackend) -> Iterator[AppController]:
    controller = AppController(backend.bridge, data_dir="/data")
    yield controller
    controller.deleteLater()
    settle()


def facts(**changes: object) -> SessionFacts:
    values: dict[str, object] = {"session_id": 7, "contact_id": BOB.contact_id, "peer_name": "Bob"}
    return session_facts(**(values | changes))


def opened(
    backend: FakeBackend, app: AppController, items: list[TraceItem], **changes: object
) -> Inspector:
    ws = unlock(backend, app, online(BOB))
    backend.reply(backend.one("history"), ())
    inspector = ws.inspector_model
    inspector.setOpen(True)
    backend.reply(backend.one("inspect_sessions"), (facts(**changes),))
    request = backend.one("inspect")
    assert request.args == {"session_id": 7, "after": -1}  # the selected conversation's session
    backend.reply(request, InspectSnap(facts(**changes), tuple(items), missing=False))
    return inspector


def keys(inspector: Inspector) -> list[str]:
    return [r.key for r in inspector._timeline_model.rows()]


def test_opening_shows_the_selected_conversations_session(
    backend: FakeBackend, app: AppController
) -> None:
    items = scripted().i.items
    inspector = opened(backend, app, items)
    assert inspector.property("sessionId") == 7
    assert inspector.property("title") == "Bob"
    assert inspector.property("exposure") == "public"
    assert inspector.property("following")
    assert inspector._sessions.rows()[0].subtitle == "Outgoing · HYBRID-1 · open"
    titles = [r.title for r in inspector._timeline_model.rows()]
    assert titles[1:5] == ["Hello", "Initiator: wait reply", "Reply", "Key schedule"]
    assert inspector._frames.rows()[0].name == "Hello"
    assert [i.ordinal for i in inspector.trace_items] == list(range(len(items)))


def test_live_events_append_once_in_order(backend: FakeBackend, app: AppController) -> None:
    items = scripted().i.items
    inspector = opened(backend, app, items[:50])
    backend.updates(TraceAppended(7, tuple(items[40:80])))  # overlaps what was already seen
    backend.updates(TraceAppended(99, tuple(items[80:])))  # another session: ignored
    backend.updates(TraceAppended(7, tuple(items[80:])))
    assert [i.ordinal for i in inspector.trace_items] == list(range(len(items)))
    whole = Timeline()  # the same rows as building from all items at once
    whole.extend(items)
    assert keys(inspector) == [r.key for r in whole.rows()]


def test_pausing_freezes_the_display_and_resuming_catches_up(
    backend: FakeBackend, app: AppController
) -> None:
    items = scripted().i.items
    inspector = opened(backend, app, items[:50])
    inspector.pause()
    backend.one("inspect_pause")
    assert not inspector.property("following")
    backend.updates(TraceAppended(7, tuple(items[50:60])))  # already in flight: ignored
    assert len(inspector.trace_items) == 50
    inspector.followLive()
    request = backend.one("inspect")
    assert request.args == {"session_id": 7, "after": 49}
    backend.reply(request, InspectSnap(facts(), tuple(items[70:]), missing=True))
    rows = inspector._timeline_model.rows()
    gap = next(r for r in rows if r.kind == "gap")
    assert (gap.first, gap.last, gap.count) == (50, 69, 20)
    assert inspector.property("following")


def test_an_overflow_catches_up_from_the_last_ordinal(
    backend: FakeBackend, app: AppController
) -> None:
    items = scripted().i.items
    inspector = opened(backend, app, items[:30])
    backend.updates(TraceOverflow(7))
    assert backend.one("inspect").args == {"session_id": 7, "after": 29}
    assert inspector.property("loading")


def test_too_many_events_take_a_fresh_snapshot(
    backend: FakeBackend, app: AppController, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("qrp2p.ui.viewmodels.inspector.ITEM_CAP", 60)
    assert ITEM_CAP > 60
    items = scripted().i.items
    inspector = opened(backend, app, items[:50])
    backend.updates(TraceAppended(7, tuple(items[50:70])))
    request = backend.one("inspect")
    assert request.args == {"session_id": 7, "after": -1}
    backend.reply(request, InspectSnap(facts(), tuple(items[:5] + items[40:]), missing=False))
    assert [i.ordinal for i in inspector.trace_items][:6] == [0, 1, 2, 3, 4, 40]
    assert any(r.kind == "gap" for r in inspector._timeline_model.rows())


def test_a_frame_selection_drives_fields_and_bytes(
    backend: FakeBackend, app: AppController
) -> None:
    items = scripted().i.items
    inspector = opened(backend, app, items)
    reply = next(
        i
        for i in items
        if isinstance(i.event, FrameTraced) and i.event.frame.type is FrameType.REPLY
    )
    row = next(r for r in inspector._timeline_model.rows() if r.frame == reply.ordinal)
    inspector.selectRow(row.key)
    assert inspector.property("selectedFrame") == reply.ordinal
    assert inspector.property("frameTitle") == "Reply"
    assert "sealed" in inspector.property("frameDetail")
    assert inspector._hex.bytes == reply.event.frame.encode()  # type: ignore[union-attr]
    inspector.selectField("b:ct/ctX")
    assert (
        inspector._hex.property("highlightStart"),
        inspector._hex.property("highlightLength"),
    ) == (
        5 + 32 + 1088,
        32,
    )
    inspector.selectByte("frame", 5 + 32 + 10)  # inside ctM, inside ct: the innermost wins
    assert inspector.property("selectedField") == "b:ct/ctM"
    inspector.selectByte("frame", 2)  # the header's length field
    assert inspector.property("selectedField") == "h:length"
    assert inspector._plaintext.bytes == b""  # a public trace has no plaintext


def test_an_exposed_frame_shows_its_plaintext(backend: FakeBackend, app: AppController) -> None:
    items = scripted(exposed=True).i.items
    inspector = opened(backend, app, items, glass_box=True, exposed=True)
    assert inspector.property("exposure") == "glass_box"
    admit = next(
        i
        for i in items
        if isinstance(i.event, FrameTraced) and i.event.frame.type is FrameType.ADMIT
    )
    inspector.selectFrame(admit.ordinal)
    assert "decrypted" in inspector.property("frameDetail")
    names = [r.name for r in inspector._fields.rows() if r.source == "plaintext"]
    assert names == ["nonce", "decision", "admit flags", "reason", "FinA"]
    inspector.selectField("p:FinA")
    assert inspector._plaintext.property("highlightStart") == 3
    assert inspector._hex.property("highlightLength") == 0


def test_the_key_graph_and_facts_are_built_only_while_shown(
    backend: FakeBackend, app: AppController
) -> None:
    inspector = opened(backend, app, scripted().i.items)
    assert inspector._nodes.rows() == ()
    assert inspector._facts.rows() == ()
    inspector.setView("keys")
    nodes = {n.key: n for n in inspector._nodes.rows()}
    assert nodes["hs_R"].inputs == "hs, th_hello"
    assert "fk_R" in nodes["hs_R"].outputs
    assert nodes["hs_R"].cite == "DESIGN §7.4"
    assert nodes["hs_R"].value == ""
    assert inspector.property("keyColumns") > 5
    edge = next(e for e in inspector._edges.rows() if e.key == "hs>hs_R")
    assert (edge.from_column, edge.to_column) == (nodes["hs"].column, nodes["hs_R"].column)
    inspector.setView("security")
    found = {f.key: f for f in inspector._facts.rows()}
    assert found["completion"].value == "Complete: Admit verified"
    assert found["identity"].cite == "DESIGN §7.5"
    inspector.setView("nonsense")
    assert inspector.property("view") == "security"


def test_a_fact_leads_to_its_evidence(backend: FakeBackend, app: AppController) -> None:
    inspector = opened(backend, app, scripted().i.items)
    inspector.setView("security")
    completion = next(f for f in inspector._facts.rows() if f.key == "completion")
    inspector.showOrdinal(completion.ordinal)
    assert inspector.property("view") == "timeline"
    row = next(
        r for r in inspector._timeline_model.rows() if r.key == inspector.property("selectedRow")
    )
    assert row.first <= completion.ordinal <= row.last


def test_descriptors_and_contacts_update_the_session(
    backend: FakeBackend, app: AppController
) -> None:
    inspector = opened(backend, app, scripted().i.items)
    backend.updates(SessionDescribed(facts(ended=True, end_reason="normal")))
    assert inspector._sessions.rows()[0].subtitle.endswith("ended: normal")
    backend.updates(ContactChanged(replace(online(BOB), name="Robert", trust="verified")))
    assert inspector.property("title") == "Robert"
    inspector.setView("security")
    assert next(f for f in inspector._facts.rows() if f.key == "verification").status == "ok"


def test_a_session_that_is_gone_says_so(backend: FakeBackend, app: AppController) -> None:
    inspector = opened(backend, app, scripted().i.items)
    inspector.chooseSession(3)
    backend.reply(
        backend.one("inspect"), error=ErrorInfo("node", "that session is no longer retained")
    )
    assert inspector.property("error") == "that session is no longer retained"
    assert not inspector.property("loading")


def test_closing_forgets_everything(backend: FakeBackend, app: AppController) -> None:
    inspector = opened(backend, app, scripted().i.items)
    inspector.setOpen(False)
    backend.one("inspect_close")
    assert inspector.trace_items == ()
    assert inspector._sessions.rows() == ()
    assert inspector.property("sessionId") == -1
    backend.updates(TraceAppended(7, tuple(scripted().i.items[:3])))
    assert inspector.trace_items == ()


def test_a_lock_ends_the_inspection(backend: FakeBackend, app: AppController) -> None:
    inspector = opened(backend, app, scripted().i.items[:20])
    app.lock()
    backend.updates(TraceAppended(7, tuple(scripted().i.items[20:30])))
    assert len(inspector.trace_items) == 20  # the bridge stopped accepting at the lock


def strings_of(inspector: Inspector) -> str:
    models = [
        inspector._timeline_model,
        inspector._frames,
        inspector._fields,
        inspector._nodes,
        inspector._edges,
        inspector._facts,
        inspector._sessions,
    ]
    texts = [str(row) for model in models for row in model.rows()]
    hexes = [
        "".join(inspector._hex.data(inspector._hex.index(r, 0), role) or "" for role in (257, 259))
        for r in range(inspector._hex.rowCount())
    ]
    return "\n".join([*texts, *hexes, str(inspector.property("frameDetail"))])


def test_view_model_strings_of_a_normal_session_hold_no_secret(
    backend: FakeBackend, app: AppController
) -> None:
    """The canary for the Inspector's own strings; the exposed run proves the search finds them."""
    handled: list[RevealedValue] = []
    normal = scripted(secrets=handled)  # the values this very session derived, kept aside
    secrets = secret_hexes(handled)
    assert len(secrets) > 40
    inspector = opened(backend, app, normal.i.items)
    for view in ("timeline", "keys", "security"):
        inspector.setView(view)
    for row in inspector._timeline_model.rows():
        inspector.selectRow(row.key)
        for field in inspector._fields.rows():
            inspector.selectField(field.key)
    text = strings_of(inspector).lower()
    assert not [s for s in secrets if s in text]
    # The search works: an exposed session's views do show its values.
    exposed = scripted(exposed=True)
    revealed = {i.event.value.hex() for i in exposed.i.items if isinstance(i.event, Revealed)}
    opened_again(backend, inspector, exposed.i.items)
    inspector.setView("keys")
    shown = strings_of(inspector).lower()
    assert revealed
    assert all(v in shown for v in revealed)


def opened_again(backend: FakeBackend, inspector: Inspector, items: list[TraceItem]) -> Inspector:
    inspector.chooseSession(8)
    request = backend.one("inspect", lambda r: r.args["session_id"] == 8)
    backend.reply(
        request,
        InspectSnap(facts(session_id=8, glass_box=True, exposed=True), tuple(items), missing=False),
    )
    return inspector


def test_the_workspace_owns_one_inspector(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, online(BOB))
    assert isinstance(ws, Workspace)
    assert isinstance(ws.property("inspector"), Inspector)


def test_the_lanes_name_both_sides_by_role(backend: FakeBackend, app: AppController) -> None:
    inspector = opened(backend, app, scripted().i.items)
    assert (inspector.property("localName"), inspector.property("peerName")) == ("You", "Bob")
    assert inspector.property("initiator")
    backend.updates(SessionDescribed(facts(initiator=False, peer_name="")))
    assert not inspector.property("initiator")
    assert inspector.property("peerName") == "10.0.0.2:47470"  # before authentication


def test_only_the_specifications_own_sections_open(
    backend: FakeBackend, app: AppController, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened_urls: list[str] = []
    monkeypatch.setattr(
        "qrp2p.ui.viewmodels.inspector.QDesktopServices.openUrl",
        lambda url: opened_urls.append(url.toString()),
    )
    inspector = opened(backend, app, scripted().i.items)
    inspector.openSpec("7.4")
    inspector.openSpec("https://example.org/")
    inspector.openSpec("")
    assert opened_urls == [SPEC_URL + "#74-key-schedule"]
    assert inspector.cite("Appendix B") == "DESIGN Appendix B"
    assert inspector.cite("8.4") == "DESIGN §8.4"
    assert inspector.cite("99") == ""


def test_frames_carry_their_time_and_record_kind(backend: FakeBackend, app: AppController) -> None:
    items = scripted().i.items
    record = next(
        n
        for n, i in enumerate(items)
        if isinstance(i.event, FrameTraced) and i.event.frame.type is FrameType.RECORD
    )
    inspector = opened(backend, app, items[: record + 1])  # its counters arrive in the next batch
    assert inspector._frames.rows()[-1].name == "Record"
    backend.updates(TraceAppended(7, tuple(items[record + 1 :])))
    frames = inspector._frames.rows()
    origin = items[0].time
    assert frames[0].time == f"+{items[frames[0].ordinal].time - origin:.3f} s"
    assert len({f.time for f in frames}) > len(frames) // 2  # each at its own time, not all +0
    assert frames[[f.ordinal for f in frames].index(items[record].ordinal)].name == "Record · chat"
    assert {f.name for f in frames} >= {"Hello", "Reply", "Record · key_update", "Record · close"}


def test_the_detail_follows_changes_to_the_selected_row(
    backend: FakeBackend, app: AppController
) -> None:
    inspector = opened(backend, app, scripted().i.items)
    announced: list[None] = []
    inspector.selectionChanged.connect(lambda: announced.append(None))
    group = next(r for r in inspector._timeline_model.rows() if r.kind == "group")
    inspector.selectRow(group.key)
    announced.clear()
    inspector.toggleGroup(group.key)  # the selected row now reads "expanded"
    assert announced
    member = next(r for r in inspector._timeline_model.rows() if r.member)
    inspector.selectRow(member.key)
    inspector.toggleGroup(group.key)  # folding hides the selected record: its group is selected
    assert inspector.property("selectedRow") == group.key


def test_a_rebuilt_key_node_announces_itself(backend: FakeBackend, app: AppController) -> None:
    items = scripted().i.items
    reply = next(
        n
        for n, i in enumerate(items)
        if isinstance(i.event, FrameTraced) and i.event.frame.type is FrameType.REPLY
    )
    inspector = opened(backend, app, items[:reply])
    inspector.setView("keys")
    inspector.selectNode("dk")  # the initiator's key pair: nothing uses it yet
    assert next(n for n in inspector._nodes.rows() if n.key == "dk").outputs == ""
    announced: list[None] = []
    inspector.selectionChanged.connect(lambda: announced.append(None))
    backend.updates(TraceAppended(7, tuple(items[reply:])))
    assert announced  # the detail shown for dk is refreshed
    dk = next(n for n in inspector._nodes.rows() if n.key == "dk")
    assert "ssM" in dk.outputs
    assert dk.released == "used"


def test_bytes_trigger_resnapshot_and_pause_keeps_a_bounded_frozen_view(
    backend: FakeBackend, app: AppController, monkeypatch: pytest.MonkeyPatch
) -> None:

    monkeypatch.setattr("qrp2p.ui.viewmodels.inspector.BUFFER_BYTES", 64_000)
    original = scripted().i.items[:1]
    inspector = opened(backend, app, original)
    frame = FrameTraced(Direction.OUT, Frame(FrameType.RECORD, bytes(16_000)), ())
    for n in range(1, 6):
        backend.updates(TraceAppended(7, (TraceItem(n, float(n), frame),)))
    request = backend.one("inspect")
    assert request.args["after"] == -1
    kept = (*original, TraceItem(4, 4.0, frame), TraceItem(5, 5.0, frame))
    backend.reply(request, InspectSnap(facts(), kept, missing=True))
    assert sum(item_bytes(i) for i in inspector.trace_items) <= 64_000
    assert any(row.kind == "gap" for row in inspector._timeline_model.rows())
    inspector.pause()
    frozen = inspector.trace_items
    for n in range(6, 50):
        backend.updates(TraceAppended(7, (TraceItem(n, float(n), frame),)))
    assert inspector.trace_items == frozen


def test_session_eviction_removes_picker_entries_and_invalidates_an_inflight_selection(
    backend: FakeBackend, app: AppController
) -> None:

    inspector = opened(backend, app, scripted().i.items)
    for session_id in range(8, 40):
        backend.updates(SessionDescribed(facts(session_id=session_id)))
    backend.updates(*(SessionRemoved(n) for n in range(7, 24)))
    assert set(inspector._known) == set(range(24, 40))
    assert inspector.property("sessionId") == -1
    assert "no longer retained" in inspector.property("error")
    assert not inspector.trace_items


def test_a_dropped_snapshot_reply_requests_a_fresh_bounded_snapshot(
    backend: FakeBackend, app: AppController
) -> None:
    inspector = opened(backend, app, scripted().i.items[:20])
    backend.updates(TraceOverflow(7))
    request = backend.one("inspect")
    backend.reply(request, error=ErrorInfo("trace_overflow", "The trace display is catching up."))
    retry = backend.one("inspect")
    assert retry.args == {"session_id": 7, "after": -1}
    backend.reply(retry, InspectSnap(facts(), tuple(scripted().i.items), missing=False))
    assert not inspector.property("loading")
    assert inspector.trace_items
