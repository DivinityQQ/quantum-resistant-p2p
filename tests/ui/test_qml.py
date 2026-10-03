"""The real QML window, offscreen, driven by keyboard and mouse against a fake services side.

Any Qt warning (a QML error, a binding loop, a broken anchor) fails these tests (see
conftest.py), so they also guard every screen they open against regressions.
"""

import re
from dataclasses import replace

import pytest
from PySide6.QtCore import (
    QCoreApplication,
    QMimeData,
    QObject,
    QPoint,
    QPointF,
    QRectF,
    QSize,
    Qt,
    QUrl,
)
from PySide6.QtGui import QColor, QContextMenuEvent, QGuiApplication, QImage
from PySide6.QtQml import QQmlApplicationEngine, QQmlComponent, QQmlEngine, QQmlExpression
from PySide6.QtQuick import QQuickItem, QQuickWindow
from PySide6.QtTest import QTest

from qrp2p.ui.app import QML
from qrp2p.ui.icons import IconProvider, render
from qrp2p.ui.snapshots import (
    ContactChanged,
    ErrorInfo,
    MessageChanged,
    MismatchOpened,
    MismatchSnap,
    NoticePosted,
    PromptOpened,
    PromptSnap,
)
from tests.ui.fakes import SETTINGS, chat, contact, online, settle
from tests.ui.window import Ui, flush_deletes, items, named, of_type

BOB = contact("Bob")


def text_formats(engine: QQmlApplicationEngine, window: QQuickWindow) -> list[tuple[str, int]]:
    """Every item in the window with a textFormat, and its value (read through QML: the enum's
    type is private to Qt, so Python cannot convert it)."""
    found: list[tuple[str, int]] = []
    for item in items(window):
        if item.metaObject().indexOfProperty("textFormat") < 0:
            continue
        context = QQmlEngine.contextForObject(item) or engine.rootContext()
        value, failed = QQmlExpression(context, item, "textFormat").evaluate()
        assert not failed
        found.append((item.metaObject().className(), int(value)))
    return found


def scene_rect(item: QQuickItem) -> QRectF:
    return QRectF(
        item.mapToScene(QPointF(0, 0)),
        QPointF(item.mapToScene(QPointF(item.width(), item.height()))),
    )


def hover(ui: Ui, item: QQuickItem) -> None:
    center = item.mapToScene(QPointF(item.width() / 2, item.height() / 2)).toPoint()
    QTest.mouseMove(ui.window, center + QPoint(1, 0))  # a move, so hover changes
    QTest.mouseMove(ui.window, center)
    settle()


def context_menu(ui: Ui, item: QQuickItem) -> QObject:
    """Ask ``item`` for its context menu (right click or the menu key) and return it, open."""
    point = item.mapToScene(QPointF(min(20, item.width() / 2), item.height() - 10)).toPoint()
    event = QContextMenuEvent(QContextMenuEvent.Reason.Mouse, point, ui.window.mapToGlobal(point))
    QGuiApplication.sendEvent(ui.window, event)
    settle()
    menus = [  # from the item: list delegates have no QObject parent the window could search
        o
        for o in item.findChildren(QObject)
        if o.metaObject().className().startswith("TextEditMenu") and o.property("visible")
    ]
    assert len(menus) == 1
    return menus[0]


def menu_entry(menu: QObject, name: str) -> QQuickItem:
    entry = menu.findChild(QQuickItem, name)
    assert entry is not None, name
    return entry


# -- files and rules ---------------------------------------------------------------------------------


def test_every_qml_file_compiles(qapp: QCoreApplication) -> None:  # noqa: ARG001
    engine = QQmlApplicationEngine()
    engine.addImportPath(str(QML))
    engine.addImageProvider("icon", IconProvider())
    files = sorted(QML.rglob("*.qml"))
    assert len(files) > 40
    for path in files:
        component = QQmlComponent(engine, QUrl.fromLocalFile(str(path)))
        assert component.status() == QQmlComponent.Status.Ready, (
            path.name,
            component.errorString(),
        )


def test_icons_render_only_bundled_names_and_hex_colours() -> None:
    size = QSize(24, 24)
    drawn = render("send-horizontal", "242628", size)
    assert any(drawn.pixelColor(x, y).alpha() > 0 for x in range(24) for y in range(24))
    tinted = render("check", "ccff0000", size)  # alpha first, as Qt names colours
    painted = [tinted.pixelColor(x, y) for x in range(24) for y in range(24)]
    strongest = max(painted, key=lambda c: c.alpha())
    assert strongest.red() > 200
    assert strongest.green() < 40
    assert 150 < strongest.alpha() < 230
    for name, color in [("../app-icon", "242628"), ("no-such-icon", "242628"), ("check", "red")]:
        blank = render(name, color, size)
        assert all(blank.pixelColor(x, y).alpha() == 0 for x in range(24) for y in range(24))


# -- screens -----------------------------------------------------------------------------------------


def test_create_the_vault_from_the_keyboard(ui: Ui) -> None:
    ui.backend.lifecycle("no_vault")
    ui.item("createName").forceActiveFocus()
    ui.type("Alice")
    ui.key(Qt.Key.Key_Tab)
    ui.type("correct horse")
    ui.key(Qt.Key.Key_Tab)
    ui.type("correct horse")
    ui.key(Qt.Key.Key_Return)
    request = ui.backend.one("create_vault")
    assert request.args == {"password": "correct horse", "display_name": "Alice"}


def test_unlock_and_wrong_password(ui: Ui) -> None:
    ui.backend.lifecycle("locked")
    ui.backend.reply(ui.backend.one("device_unlock_available"), False)
    ui.item("unlockPassword").forceActiveFocus()
    ui.type("guess")
    ui.key(Qt.Key.Key_Return)
    ui.backend.reply(ui.backend.one("unlock"), error=ErrorInfo("wrong_password", "Wrong password."))
    assert ui.app.property("error") == "Wrong password."
    ui.unlock(BOB)
    assert ui.find("messenger") is not None


def test_every_text_is_plain_and_peer_markup_stays_literal(ui: Ui) -> None:
    ui.unlock(online(BOB))
    hostile = '<b>bold</b> <img src="file:///etc/passwd"> <a href="x">link</a>'
    ui.backend.reply(ui.backend.one("history"), (chat(hostile), chat("plain")))
    ui.frame()
    bubbles = named(ui.window, "bubbleText")
    assert hostile in [b.property("text") for b in bubbles]
    formats = text_formats(ui.engine, ui.window)
    assert len(formats) > 30
    assert all(value == 0 for _, value in formats), [f for f in formats if f[1] != 0]  # PlainText


def test_enter_sends_and_shift_enter_starts_a_line(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    composer = ui.item("composerInput")
    composer.forceActiveFocus()
    ui.type("hello")
    ui.key(Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)
    ui.type("world")
    assert composer.property("text") == "hello\nworld"
    ui.key(Qt.Key.Key_Return)
    assert ui.backend.one("send_chat").args["text"] == "hello\nworld"
    assert composer.property("text") == ""


def test_an_offline_contact_keeps_the_draft(ui: Ui) -> None:
    ui.unlock(BOB)
    ui.backend.reply(ui.backend.one("history"), ())
    ui.item("composerInput").forceActiveFocus()
    ui.type("later")
    ui.key(Qt.Key.Key_Return)
    assert ui.backend.pending("send_chat") == []
    assert ui.item("composerInput").property("text") == "later"
    assert not ui.item("sendButton").isEnabled()


def test_lock_removes_every_view_of_the_conversation(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), (chat("secret plans"),))
    ui.item("composerInput").forceActiveFocus()
    ui.type("unsent draft")
    ui.key(Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
    flush_deletes()
    assert ui.find("messenger") is None
    assert ui.find("composerInput") is None
    texts = [
        str(o.property("text"))
        for o in ui.window.findChildren(QObject)
        if o.metaObject().indexOfProperty("text") >= 0
    ]
    assert not [t for t in texts if "secret plans" in t or "unsent draft" in t]
    assert ui.app.property("phase") == "locking"


def test_settings_show_what_the_vault_holds(ui: Ui) -> None:
    ui.unlock(BOB, settings=replace(SETTINGS, auto_lock_minutes=15))
    dialog = ui.window.findChild(QObject, "settingsDialog")
    assert dialog is not None
    dialog.setProperty("visible", True)
    settle()
    combo = ui.item("autoLockCombo")
    assert combo.property("displayText") == "15 minutes"


def test_settings_outside_the_presets_show_their_stored_value(ui: Ui) -> None:
    ui.unlock(BOB, settings=replace(SETTINGS, auto_lock_minutes=120, max_file_size=2_500_000_000))
    dialog = ui.window.findChild(QObject, "settingsDialog")
    assert dialog is not None
    dialog.setProperty("visible", True)
    settle()
    assert ui.item("autoLockCombo").property("displayText") == "120 minutes"
    assert ui.item("maxFileCombo").property("displayText") in {"2.5 GB", "2,5 GB"}


def test_notices_do_not_outlive_the_lock(ui: Ui) -> None:
    ui.unlock(BOB)
    ui.backend.updates(NoticePosted("Added Bob. Compare safety numbers to verify them."))
    ui.until(lambda: "Added Bob" in str(ui.item("toasts").property("current")))
    ui.key(Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
    flush_deletes()
    assert ui.find("toasts") is None
    texts = [
        str(item.property("text"))
        for item in items(ui.window)
        if item.metaObject().indexOfProperty("text") >= 0
    ]
    assert not [t for t in texts if "Bob" in t]


def test_a_contact_request_is_answered_from_its_dialog(ui: Ui) -> None:
    ui.unlock(BOB)
    prompt = PromptSnap(
        prompt_id=4,
        kind="contact_request",
        short_id="CARL-0000",
        contact_id="",
        name="",
        profile="HYBRID-1",
        glass_box_refused=True,
        expires_in=60.0,
    )
    ui.backend.updates(PromptOpened(prompt))
    dialog = ui.window.findChild(QObject, "promptDialog")
    assert dialog is not None
    assert dialog.property("visible")

    def name_field_has_focus() -> bool:
        focused = ui.window.activeFocusItem()
        return focused is not None and focused.metaObject().indexOfProperty("echoMode") >= 0

    ui.until(name_field_has_focus)
    ui.type("Carol")
    ui.click("acceptContact")
    request = ui.backend.one("answer_prompt")
    assert request.args == {"prompt_id": 4, "accept": True, "name": "Carol"}


def test_a_key_mismatch_defaults_to_cancel(ui: Ui) -> None:
    ui.unlock(BOB)
    mismatch = MismatchSnap(
        mismatch_id=2,
        contact_id=BOB.contact_id,
        name="Bob",
        expected_short_id="BOBX-0000",
        actual_short_id="EVIL-0000",
        expected_fingerprint="aaaa bbbb",
        actual_fingerprint="cccc dddd",
    )
    ui.backend.updates(MismatchOpened(mismatch))

    def cancel_has_focus() -> bool:
        focused = ui.window.activeFocusItem()
        return focused is not None and focused.objectName() == "keepIdentity"

    ui.until(cancel_has_focus)
    ui.click("startRepin")
    assert ui.backend.pending("resolve_mismatch") == []  # a re-pin needs its second step
    assert not ui.item("startRepin").isVisible()


def test_glass_box_is_asked_for_from_the_conversation_menu(ui: Ui) -> None:
    ui.unlock(BOB)
    ui.backend.reply(ui.backend.one("history"), ())
    more = next(
        i for i in of_type(ui, "IconButton") if str(i.property("label")).startswith("More actions")
    )
    ui.click_item(more)
    (menu,) = [
        o for o in more.findChildren(QObject) if o.metaObject().className().startswith("AppMenu_")
    ]
    assert menu.property("visible")
    entry = menu_entry(menu, "connectGlassBoxItem")
    ui.click_item(entry)

    def cancel_has_focus() -> bool:
        focused = ui.window.activeFocusItem()
        return focused is not None and focused.objectName() == "cancelGlassBox"

    ui.until(cancel_has_focus)  # the safe choice is the default
    assert ui.backend.pending("connect_contact") == []
    ui.click("askGlassBox")
    assert ui.backend.one("connect_contact").args["glass_box"] is True
    assert not entry.property("enabled")  # one request at a time


def test_a_busy_button_does_not_submit_twice_but_lets_focus_move(ui: Ui) -> None:
    ui.unlock(BOB)
    dialog = ui.window.findChild(QObject, "connectDialog")
    assert dialog is not None
    dialog.setProperty("visible", True)
    ui.until(lambda: ui.window.activeFocusItem() is ui.item("connectHost"))
    ui.type("10.0.0.9")
    ui.key(Qt.Key.Key_Return)
    assert len(ui.backend.pending("connect_address")) == 1
    button = ui.item("connectButton")
    button.forceActiveFocus()
    ui.key(Qt.Key.Key_Space)  # busy: no second connection attempt
    assert len(ui.backend.pending("connect_address")) == 1
    ui.key(Qt.Key.Key_Tab)
    assert ui.window.activeFocusItem() is not button


def test_the_theme_changes_in_place(ui: Ui) -> None:
    ui.unlock(BOB)
    messenger = ui.find("messenger")
    assert ui.window.color() == QColor("#FAF9F6")
    ui.backend.updates(ContactChanged(BOB))  # any update; then the settings reply
    ws = ui.app.property("workspace")
    ws.settings_model.apply(replace(SETTINGS, appearance="dark"))
    ui.app._sync_appearance()
    settle()
    assert ui.window.color() == QColor("#151718")
    assert ui.find("messenger") is messenger  # nothing was rebuilt


@pytest.mark.parametrize(("width", "height", "scale"), [(720, 540, 150), (1600, 1000, 100)])
def test_layouts_hold_at_small_windows_and_large_text(
    ui: Ui, width: int, height: int, scale: int
) -> None:
    ui.unlock(online(BOB), contact("Carol"), settings=replace(SETTINGS, text_scale=scale))
    ui.backend.reply(
        ui.backend.one("history"), tuple(chat(f"message {i} " * 20) for i in range(30))
    )
    ui.window.resize(width, height)
    messenger = ui.item("messenger")
    messenger.setProperty("inspectorOpen", True)
    settle()
    messenger.setProperty("inspectorOpen", False)
    settle()
    for name in ("chooser", "settingsDialog", "connectDialog", "detailsDialog", "verifyDialog"):
        popup = ui.window.findChild(QObject, name)
        assert popup is not None
        popup.setProperty("visible", True)
        settle()
        popup.setProperty("visible", False)
        settle()
    ui.backend.updates(MessageChanged(BOB.contact_id, chat("one more"), added=True))
    assert ui.find("composerInput") is not None


def test_qml_sources_follow_the_rules() -> None:
    """Static rules: plain text only, no literal colours, nothing opens peer data."""
    sources = {p: p.read_text(encoding="utf-8") for p in QML.rglob("*.qml")}
    for path, text in sources.items():
        name = path.name
        for banned in (
            "RichText",
            "StyledText",
            "MarkdownText",
            "AutoText",
            "Label {",
            "openUrlExternally",
            "Qt.labs.platform",
            "LocalStorage",
        ):
            assert banned not in text, (name, banned)
        if name != "Theme.qml":
            assert not re.search(r'"#[0-9A-Fa-f]{6,8}"', text), (name, "literal colour")
        for block in ("Text {", "TextEdit {", "T.TextArea {"):
            for at in [i for i in range(len(text)) if text.startswith(block, i)]:
                if text[max(0, at - 3) : at] == "App":
                    continue  # AppText {
                body = text[at : text.find("}", at)]
                assert "textFormat:" in body, (name, block)
                assert "PlainText" in body, (name, block)


# -- controls -----------------------------------------------------------------------------------------


def test_the_composer_grows_with_its_lines_then_scrolls(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    area = ui.item("composerInput")
    area.forceActiveFocus()
    flick = area.parentItem().parentItem()
    ui.type("one")
    for line in ("two", "three"):
        ui.key(Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)
        ui.type(line)
    ui.frame()
    assert flick.height() >= area.property("contentHeight")  # all three lines show
    for line in range(10):
        ui.key(Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)
        ui.type(f"more {line}")
    ui.frame()
    assert flick.height() < area.height()  # capped: it scrolls now
    assert flick.property("contentY") + flick.height() >= area.height() - 1  # to the cursor


def test_tooltips_never_cover_their_control(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    buttons = sorted(of_type(ui, "IconButton"), key=lambda b: scene_rect(b).top())
    for button in (buttons[0], buttons[-1]):  # one at the top of the window, one at the bottom
        hover(ui, button)
        tips = [
            t
            for t in button.findChildren(QObject)
            if t.metaObject().className().startswith("AppToolTip")
        ]
        assert len(tips) == 1
        ui.until(lambda tip=tips[0]: bool(tip.property("opened")))
        box = scene_rect(tips[0].property("background"))
        assert not box.intersects(scene_rect(button)), button.property("label")
        assert box.top() >= 0
        assert box.bottom() <= ui.window.height()


def test_buttons_show_the_busy_cursor_only_while_busy(ui: Ui) -> None:
    ui.unlock(BOB)
    dialog = ui.window.findChild(QObject, "connectDialog")
    assert dialog is not None
    dialog.setProperty("visible", True)
    ui.until(lambda: ui.window.activeFocusItem() is ui.item("connectHost"))
    ui.type("10.0.0.9")
    button = ui.item("connectButton")
    hover(ui, button)
    assert ui.window.cursor().shape() != Qt.CursorShape.BusyCursor
    ui.key(Qt.Key.Key_Return)
    hover(ui, button)
    assert ui.window.cursor().shape() == Qt.CursorShape.BusyCursor


def test_the_password_toggle_leaves_the_field_border_visible(ui: Ui) -> None:
    ui.backend.lifecycle("no_vault")
    field = ui.item("createPassword")
    (toggle,) = [b for b in of_type(ui, "IconButton") if field.isAncestorOf(b)]
    inner = scene_rect(field).adjusted(2, 2, -2, -2)  # inside the focused (2 px) border
    assert inner.contains(scene_rect(toggle))


def test_scroll_bars_never_cover_wrapping_content(ui: Ui) -> None:
    ui.unlock(BOB)
    ui.window.resize(720, 420)
    dialog = ui.window.findChild(QObject, "settingsDialog")
    assert dialog is not None
    dialog.setProperty("visible", True)
    ui.frame()
    flick = dialog.property("contentItem")
    (bar,) = [b for b in of_type(ui, "AppScrollBar") if b.parentItem() is flick]
    (body,) = flick.property("contentItem").childItems()
    assert scene_rect(body).right() <= scene_rect(bar).left()


def test_text_has_a_context_menu(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), (chat("copy me"),))
    area = ui.item("composerInput")
    area.forceActiveFocus()
    ui.type("draft")
    menu = context_menu(ui, area)
    assert menu_entry(menu, "menuPaste").isVisible()
    menu.setProperty("visible", False)
    settle()

    bubble = ui.item("bubbleText")
    menu = context_menu(ui, bubble)
    assert not menu_entry(menu, "menuPaste").isVisible()  # read-only
    copy = menu_entry(menu, "menuCopy")
    assert copy.isEnabled()  # nothing selected: copies the whole message
    QGuiApplication.clipboard().clear()
    ui.click_item(copy)
    assert QGuiApplication.clipboard().text() == "copy me"
    assert bubble.property("selectedText") == ""


def test_a_masked_password_cannot_be_copied_out(ui: Ui) -> None:
    ui.backend.lifecycle("locked")
    field = ui.item("unlockPassword")
    field.forceActiveFocus()
    ui.type("hunter2")
    ui.key(Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
    menu = context_menu(ui, field)
    assert not menu_entry(menu, "menuCopy").isEnabled()
    assert menu_entry(menu, "menuPaste").isVisible()


def test_pasting_files_or_an_image_offers_them(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    area = ui.item("composerInput")
    area.forceActiveFocus()
    clipboard = QGuiApplication.clipboard()

    picture = QImage(8, 8, QImage.Format.Format_RGB32)
    picture.fill(QColor("teal"))
    clipboard.setImage(picture)
    ui.key(Qt.Key.Key_V, Qt.KeyboardModifier.ControlModifier)
    offer = ui.backend.one("send_file_data")
    assert str(offer.args["name"]).startswith("Pasted image ")
    assert bytes(offer.args["data"]).startswith(b"\x89PNG")  # type: ignore[arg-type]
    assert area.property("text") == ""

    files = QMimeData()
    files.setUrls([QUrl.fromLocalFile("/data/report.pdf")])
    clipboard.setMimeData(files)
    menu = context_menu(ui, area)
    paste = menu_entry(menu, "menuPaste")
    assert paste.isEnabled()  # no text on the clipboard, but files to offer
    ui.click_item(paste)
    assert ui.backend.one("send_file").args["path"] == "/data/report.pdf"

    clipboard.setText("just text")
    ui.key(Qt.Key.Key_V, Qt.KeyboardModifier.ControlModifier)
    assert area.property("text") == "just text"
    assert len(ui.backend.pending("send_file_data")) == 1
    assert len(ui.backend.pending("send_file")) == 1


def test_the_title_counts_unread_messages_while_unlocked(ui: Ui) -> None:
    carol = contact("Carol")
    ui.unlock(online(BOB), online(carol))
    other = next(c for c in (BOB, carol) if c.contact_id != ui.app.workspace.property("selectedId"))  # type: ignore[attr-defined]
    ui.backend.updates(MessageChanged(other.contact_id, chat("psst"), added=True))
    assert ui.window.title() == "QRP2P (1)"
    ui.key(Qt.Key.Key_L, Qt.KeyboardModifier.ControlModifier)
    assert ui.window.title() == "QRP2P"
