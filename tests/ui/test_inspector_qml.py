"""The Inspector's QML against a scripted trace, driven by keyboard and mouse (UI_DESIGN §7, §12).

Ctrl+I opens it on the selected conversation's session with focus on its tab; the four views
render public and glass-box traces in both themes without a Qt warning; the keyboard reaches
every selection; pause and session choice send their requests; a value is shown only where the
session revealed it.
"""

from dataclasses import replace

import pytest
from PySide6.QtCore import QObject, QPointF, Qt
from PySide6.QtQuick import QQuickItem
from PySide6.QtTest import QTest

from qrp2p.core.crypto.provider import Revealed as RevealedValue
from qrp2p.core.trace import SecretDerived
from qrp2p.ui.inspect.model import Revealed, TraceItem
from qrp2p.ui.tap import InspectSnap
from qrp2p.ui.viewmodels.inspector import Inspector
from tests.ui.fakes import SETTINGS, contact, online
from tests.ui.inspect_support import scripted, secret_hexes, session_facts
from tests.ui.window import Ui, items, of_type

BOB = contact("Bob")
CTRL = Qt.KeyboardModifier.ControlModifier


def facts(**changes: object) -> object:
    values: dict[str, object] = {"session_id": 7, "contact_id": BOB.contact_id, "peer_name": "Bob"}
    return session_facts(**(values | changes))


def inspecting(
    ui: Ui, trace: list[TraceItem], *, settings: object = SETTINGS, **changes: object
) -> Inspector:
    """Unlock with Bob online, open the Inspector with Ctrl+I and answer its two requests."""
    ui.unlock(online(BOB), settings=settings)
    ui.backend.reply(ui.backend.one("history"), ())
    ui.key(Qt.Key.Key_I, CTRL)
    ui.backend.reply(ui.backend.one("inspect_sessions"), (facts(**changes),))
    request = ui.backend.one("inspect")
    assert request.args == {"session_id": 7, "after": -1}
    ui.backend.reply(request, InspectSnap(facts(**changes), tuple(trace), missing=False))  # type: ignore[arg-type]
    settled(ui)
    inspector = ui.app.property("workspace").inspector_model
    assert isinstance(inspector, Inspector)
    return inspector


def settled(ui: Ui) -> None:
    """Wait until the split has finished opening (a 200 ms transition)."""
    pane = ui.item("inspectorPane")
    widths: list[float] = []
    while len(widths) < 3 or len(set(widths[-3:])) > 1:
        ui.frame()
        QTest.qWait(30)
        widths.append(pane.width())


def texts(ui: Ui) -> list[str]:
    """Every visible text in the window."""
    ui.frame()
    return [
        str(i.property("text"))
        for i in items(ui.window)
        if i.isVisible() and i.metaObject().indexOfProperty("text") >= 0 and i.property("text")
    ]


def focused(ui: Ui) -> QQuickItem | None:
    return ui.window.activeFocusItem()


def test_a_normal_sessions_inspector_shows_none_of_its_secrets(ui: Ui) -> None:
    """End to end on the Qt side: every visible text, as the user walks frames, fields and keys."""
    handled: list[RevealedValue] = []
    trace = scripted(secrets=handled).i.items
    secrets = secret_hexes(handled)
    chats = {"hello 1", "hi 2", "after the rekey"}  # sent and received text, in readable form
    inspector = inspecting(ui, trace)
    seen: set[str] = set()
    for frame in inspector._frames.rows():
        inspector.selectFrame(frame.ordinal)
        fields = inspector._fields.rows()
        if fields:
            inspector.selectField(fields[-1].key)
        seen.update(texts(ui))
    inspector.setView("keys")
    for node in inspector._nodes.rows():
        inspector.selectNode(node.key)
        seen.update(texts(ui))
    inspector.setView("security")
    seen.update(texts(ui))
    shown = "\n".join(seen)
    assert len(secrets) > 40
    assert not [v for v in secrets if v in shown.lower()]
    assert not [c for c in chats if c in shown]


def test_ctrl_i_opens_the_selected_session_with_focus_on_its_tab(ui: Ui) -> None:
    inspecting(ui, scripted().i.items)
    assert ui.item("inspectorPane").isVisible()
    assert focused(ui) is ui.item("inspectorTab-timeline")
    assert ui.item("exposureTag").property("text") == "PUBLIC TRACE"
    assert (
        ui.item("exposureNote").property("text") == "Secret values are hidden in normal sessions."
    )
    ui.key(Qt.Key.Key_I, CTRL)
    ui.backend.one("inspect_close")
    assert ui.find("inspectorPane") is None
    assert focused(ui) is ui.item("composerInput")  # back where the user was


def test_tabs_follow_arrow_keys_home_and_end(ui: Ui) -> None:
    inspector = inspecting(ui, scripted().i.items)
    for key, view in [
        (Qt.Key.Key_Right, "messages"),
        (Qt.Key.Key_Right, "keys"),
        (Qt.Key.Key_End, "security"),
        (Qt.Key.Key_Home, "timeline"),
        (Qt.Key.Key_Left, "timeline"),
    ]:
        ui.key(key)
        assert inspector.property("view") == view
        assert focused(ui) is ui.item(f"inspectorTab-{view}")


@pytest.mark.parametrize("appearance", ["light", "dark"])
@pytest.mark.parametrize("exposed", [False, True])
def test_every_view_renders_a_trace(ui: Ui, appearance: str, *, exposed: bool) -> None:
    trace = scripted(exposed=exposed).i.items
    inspector = inspecting(
        ui,
        trace,
        settings=replace(SETTINGS, appearance=appearance),
        exposed=exposed,
        glass_box=exposed,
    )
    reply = next(r for r in inspector._timeline_model.rows() if r.title == "Reply")
    inspector.selectRow(reply.key)
    inspector.selectField(next(f.key for f in inspector._fields.rows() if f.name == "ct"))
    for view in ("timeline", "messages", "keys", "security"):
        inspector.setView(view)
        ui.frame()
    inspector.selectNode("hs_R")
    inspector.setView("keys")
    shown = texts(ui)
    revealed = {i.event.label: i.event.value.hex() for i in trace if isinstance(i.event, Revealed)}
    if exposed:
        assert ui.item("nodeValue").property("text") == revealed["hs_R"]
        assert "GLASS-BOX" in shown
    else:
        assert not revealed
        assert ui.find("nodeValue") is None or not ui.item("nodeValue").isVisible()
        assert "PUBLIC TRACE" in shown


def test_the_keyboard_reaches_rows_fields_and_bytes(ui: Ui) -> None:
    inspector = inspecting(ui, scripted().i.items)
    timeline = ui.item("timelineList")
    timeline.forceActiveFocus()
    ui.key(Qt.Key.Key_Home)
    for _ in range(10):
        if inspector.property("frameTitle") == "Reply":
            break
        ui.key(Qt.Key.Key_Down)
    assert inspector.property("frameTitle") == "Reply"
    assert ui.item("frameTitle").property("text") == "Reply"
    table = ui.item("fieldTable")
    table.forceActiveFocus()
    ui.key(Qt.Key.Key_Down)
    ui.key(Qt.Key.Key_Down)
    ui.key(Qt.Key.Key_Down)
    nonce = next(r for r in inspector._fields.rows() if r.name == "nonce_R")
    assert inspector.property("selectedField") == nonce.key
    assert (
        inspector._hex.property("highlightStart"),
        inspector._hex.property("highlightLength"),
    ) == (
        nonce.start,
        32,
    )


def test_a_group_of_records_opens_and_folds_from_the_keyboard(ui: Ui) -> None:
    inspector = inspecting(ui, scripted().i.items)
    group = next(r for r in inspector._timeline_model.rows() if r.kind == "group")
    inspector.selectRow(group.key)
    ui.item("timelineList").forceActiveFocus()
    ui.key(Qt.Key.Key_Return)
    assert any(r.member for r in inspector._timeline_model.rows())
    ui.key(Qt.Key.Key_Space)
    assert not any(r.member for r in inspector._timeline_model.rows())


def test_the_key_graph_walks_inputs_and_outputs(ui: Ui) -> None:
    inspector = inspecting(ui, scripted().i.items)
    ui.key(Qt.Key.Key_Right)  # focus starts on the Timeline tab
    ui.key(Qt.Key.Key_Right)
    assert inspector.property("view") == "keys"
    ui.item("keyGraph").forceActiveFocus()
    ui.key(Qt.Key.Key_Down)
    assert inspector.property("selectedNode") == "dk"
    ui.key(Qt.Key.Key_Right)  # dk is used by ssM first
    assert inspector.property("selectedNode") == "ssM"
    ui.key(Qt.Key.Key_Left)
    assert inspector.property("selectedNode") == "dk"
    ui.key(Qt.Key.Key_Escape)
    assert inspector.property("selectedNode") == ""


def test_pausing_and_following_send_their_requests(ui: Ui) -> None:
    inspector = inspecting(ui, scripted().i.items)
    last = inspector.trace_items[-1].ordinal
    ui.click("followButton")
    ui.backend.one("inspect_pause")
    assert ui.item("pausedTag").isVisible()
    ui.click("followButton")
    assert ui.backend.one("inspect").args == {"session_id": 7, "after": last}
    assert ui.find("pausedTag") is None or not ui.item("pausedTag").isVisible()


def test_another_retained_session_is_chosen_from_the_picker(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    ui.key(Qt.Key.Key_I, CTRL)
    ended = facts(session_id=3, established=False, ended=True, end_reason="decrypt_failed")
    ui.backend.reply(ui.backend.one("inspect_sessions"), (ended, facts()))
    ui.backend.reply(ui.backend.one("inspect"), InspectSnap(facts(), (), missing=False))  # type: ignore[arg-type]
    settled(ui)
    ui.click("sessionPicker")
    popup = ui.window.findChild(QObject, "sessionPopup")
    assert popup is not None
    assert popup.property("visible")
    assert "decrypt_failed" in " ".join(texts_of(ui.item("session-3")))
    ui.click("session-3")
    assert ui.backend.one("inspect").args == {"session_id": 3, "after": -1}
    assert not popup.property("visible")


def texts_of(item: QQuickItem) -> list[str]:
    found: list[str] = []
    pending = [item]
    while pending:
        current = pending.pop()
        if current.metaObject().indexOfProperty("text") >= 0 and current.property("text"):
            found.append(str(current.property("text")))
        pending.extend(current.childItems())
    return found


def test_expand_hides_the_chat_and_restore_brings_it_back(ui: Ui) -> None:
    inspecting(ui, scripted().i.items)
    ui.window.resize(1400, 860)
    settled(ui)
    messenger = ui.item("messenger")
    expand = next(i for i in of_type(ui, "IconButton") if i.property("label") == "Expand Inspector")
    ui.click_item(expand)
    assert messenger.property("inspectorExpanded")
    restore = next(i for i in of_type(ui, "IconButton") if i.property("label") == "Restore split")
    ui.click_item(restore)
    assert not messenger.property("inspectorExpanded")


@pytest.mark.parametrize(("width", "height", "scale"), [(720, 540, 150), (1000, 700, 100)])
def test_the_inspector_holds_at_small_windows_and_large_text(
    ui: Ui, width: int, height: int, scale: int
) -> None:
    inspector = inspecting(
        ui,
        scripted(exposed=True).i.items,
        settings=replace(SETTINGS, text_scale=scale),
        exposed=True,
    )
    ui.window.resize(width, height)
    reply = next(r for r in inspector._timeline_model.rows() if r.title == "Reply")
    inspector.selectRow(reply.key)
    for view in ("timeline", "messages", "keys", "security"):
        inspector.setView(view)
        ui.frame()
    settled(ui)
    right = ui.item("inspectorPane").mapToScene(QPointF(ui.item("inspectorPane").width(), 0)).x()
    for name in ("sessionPicker", "followButton", "inspectorTab-security"):
        item = ui.item(name)
        edge = item.mapToScene(QPointF(item.width(), 0)).x()
        assert edge <= right + 0.5, name  # the header fits: nothing is pushed out of the pane


def test_long_key_histories_have_bounded_keyboard_accessible_pages(ui: Ui) -> None:

    trace = scripted().i.items
    start = trace[-1].ordinal + 1
    trace += [
        TraceItem(start + n, 1000.0 + n, SecretDerived(f"ap_I[0]+{n + 1}", 32)) for n in range(1000)
    ]
    inspector = inspecting(ui, trace)
    inspector.setView("keys")
    ui.frame()
    assert inspector.property("keyPages") > 1
    assert len(inspector._nodes.rows()) <= 576
    older = ui.item("keyOlder")
    older.forceActiveFocus()
    ui.key(Qt.Key.Key_Space)
    ui.frame()
    assert inspector.property("keyPage") == 1
    assert len(inspector._nodes.rows()) <= 576
    assert any("page 2" in text for text in texts(ui))
    ui.item("keyNewer").forceActiveFocus()
    ui.key(Qt.Key.Key_Space)
    ui.frame()
    assert inspector.property("keyPage") == 0
