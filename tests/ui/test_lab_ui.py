"""The solo lab's view model and screens, served by a real lab host (UI_DESIGN §8, §3.4).

Entering the lab starts a run and opens its Inspector on Alice's view; one request runs at a
time; a failure is reported, never swallowed; a fork or reset reopens the Inspector on the new
run's views; the screens drive all of it from the keyboard and the mouse, in both layouts.
"""

from collections.abc import Iterator
from dataclasses import replace

import pytest
from PySide6.QtCore import QCoreApplication, QObject, Qt
from PySide6.QtQuick import QQuickItem

from qrp2p.ui.labhost import LabHost
from qrp2p.ui.tap import InspectSnap
from qrp2p.ui.viewmodels.application import AppController
from qrp2p.ui.viewmodels.lab import Lab
from tests.ui.fakes import SETTINGS, FakeBackend, contact, online, settle
from tests.ui.inspect_support import session_facts
from tests.ui.lab_support import Recordings, lab_host, serve
from tests.ui.test_inspector_qml import settled
from tests.ui.test_labhost import glass_box_recording
from tests.ui.test_viewmodels import unlock
from tests.ui.window import Ui, of_type

BOB = contact("Bob")


@pytest.fixture
def backend(qapp: QCoreApplication) -> FakeBackend:  # noqa: ARG001
    return FakeBackend()


@pytest.fixture
def app(backend: FakeBackend) -> Iterator[AppController]:
    controller = AppController(backend.bridge, data_dir="/data")
    yield controller
    controller.deleteLater()
    settle()


def entered(backend: FakeBackend, app: AppController) -> tuple[Lab, object]:
    ws = unlock(backend, app, online(BOB))
    backend.reply(backend.one("history"), ())
    host = lab_host()
    lab = ws.lab_model
    lab.enter()
    serve(backend, host)
    return lab, host


# -- the view model ---------------------------------------------------------------------------


def test_entering_starts_a_run_and_inspects_alices_view(
    backend: FakeBackend, app: AppController
) -> None:
    lab, _ = entered(backend, app)
    assert lab.property("active")
    assert lab.property("phase") == "ready"
    assert lab.property("nextStep") == "Start the handshake"
    inspector = lab.inspector_model
    assert inspector.property("sessionId") == lab.snapshot.alice_session
    assert inspector.property("exposure") == "lab"
    assert inspector.property("title") == "Alice's view"


def test_steps_and_runs_update_the_lab_and_its_inspector(
    backend: FakeBackend, app: AppController
) -> None:
    lab, host = entered(backend, app)
    lab.step()
    assert lab.property("busy")
    lab.step()  # one request at a time: ignored
    serve(backend, host)  # type: ignore[arg-type]
    assert not lab.property("busy")
    assert lab.property("stepCount") == 1
    assert lab.property("inFlight") == ["Hello · Alice → Bob"]
    lab.run()
    serve(backend, host)  # type: ignore[arg-type]
    assert lab.property("phase") == "idle"
    assert lab.property("aliceOpen")
    titles = [r.title for r in lab.inspector_model._timeline_model.rows()]
    assert {"Hello", "Reply", "Confirm", "Admit"} <= set(titles)
    assert lab.chat("alice", "hello Bob")
    assert not lab.chat("alice", "   ")
    serve(backend, host)  # type: ignore[arg-type]
    lab.run()
    serve(backend, host)  # type: ignore[arg-type]
    assert lab.property("bobReceived") == ["hello Bob"]


def test_a_refused_step_is_reported(backend: FakeBackend, app: AppController) -> None:
    lab, host = entered(backend, app)
    failures: list[str] = []
    lab.failed.connect(failures.append)
    lab.closeSession("alice")
    serve(backend, host)  # type: ignore[arg-type]
    assert failures == ["Alice has no open session"]
    assert not lab.property("busy")


def test_a_fork_reopens_the_inspector_on_the_new_run(
    backend: FakeBackend, app: AppController
) -> None:
    lab, host = entered(backend, app)
    lab.run()
    serve(backend, host)  # type: ignore[arg-type]
    old = lab.snapshot.alice_session
    lab.fork(2)
    serve(backend, host)  # type: ignore[arg-type]
    assert lab.property("stepCount") == 2
    assert lab.snapshot.alice_session != old
    inspector = lab.inspector_model
    assert inspector.property("sessionId") == lab.snapshot.alice_session
    assert {r.session_id for r in inspector._sessions.rows()} == {
        lab.snapshot.alice_session,
        lab.snapshot.bob_session,
    }


def test_the_lab_inspector_ignores_the_messengers_trace(
    backend: FakeBackend, app: AppController
) -> None:
    lab, host = entered(backend, app)
    ws = app.property("workspace")
    messenger = ws.inspector_model
    lab.run()
    serve(backend, host)  # type: ignore[arg-type]
    assert messenger.trace_items == ()  # the messenger's Inspector never saw the lab's events
    assert lab.inspector_model.trace_items


# -- the screens ------------------------------------------------------------------------------


def lab_screen(ui: Ui, width: int = 1400, height: int = 860, scale: int = 100) -> object:
    ui.unlock(online(BOB), settings=replace(SETTINGS, text_scale=scale))
    ui.backend.reply(ui.backend.one("history"), ())
    ui.window.resize(width, height)
    host = lab_host()
    messenger = ui.item("messenger")
    messenger.setProperty("area", "learn")
    ui.until(
        lambda: (f := ui.window.activeFocusItem()) is not None and f.objectName() == "openSoloLab"
    )
    ui.key(Qt.Key.Key_Space)  # Learn focuses its first action: the keyboard path into the lab
    serve(ui.backend, host)
    ui.frame()
    return host


def test_learn_opens_from_the_menu_and_leads_to_the_lab(ui: Ui) -> None:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    menu_button = next(i for i in of_type(ui, "IconButton") if i.property("label") == "Menu")
    ui.click_item(menu_button)
    (menu,) = [
        o
        for o in menu_button.findChildren(QObject)
        if o.metaObject().className().startswith("AppMenu_")
    ]
    learn = menu.findChild(QQuickItem, "learnItem")
    assert learn is not None
    ui.click_item(learn)
    assert ui.item("learnScreen").isVisible()
    assert ui.find("inspectorButton") is None or not ui.item("inspectorButton").isVisible()
    host = lab_host()
    ui.click("openSoloLab")
    serve(ui.backend, host)
    assert ui.item("labScreen").isVisible()
    assert ui.item("labTag").property("text") == "LAB"


def test_the_lab_is_driven_from_its_screen(ui: Ui) -> None:
    host = lab_screen(ui)
    step = ui.item("labStep")
    assert step.property("text") == "Step: Start the handshake"
    for _ in range(4):
        ui.click("labStep")
        serve(ui.backend, host)  # type: ignore[arg-type]
    assert ui.item("labAdmit").isVisible()  # Bob decides
    ui.click("labAdmit")
    serve(ui.backend, host)  # type: ignore[arg-type]
    ui.click("labRun")
    serve(ui.backend, host)  # type: ignore[arg-type]
    assert step.property("text") == "Nothing in flight"
    assert not step.property("enabled")
    field = ui.item("labChat-alice")
    field.forceActiveFocus()
    ui.type("hello Bob")
    ui.key(Qt.Key.Key_Return)
    serve(ui.backend, host)  # type: ignore[arg-type]
    assert field.property("text") == ""
    ui.click("labRun")
    serve(ui.backend, host)  # type: ignore[arg-type]
    lab = ui.app.property("workspace").lab_model
    assert lab.property("bobReceived") == ["hello Bob"]


def test_a_step_is_chosen_and_forked_at(ui: Ui) -> None:
    host = lab_screen(ui)
    ui.click("labRun")
    serve(ui.backend, host)  # type: ignore[arg-type]
    steps = ui.item("labStepList")
    steps.forceActiveFocus()
    ui.key(Qt.Key.Key_Up)  # the last step
    ui.key(Qt.Key.Key_Up)
    fork = ui.item("labFork")
    assert fork.property("text") == "Fork after step 5"
    ui.click("labFork")
    serve(ui.backend, host)  # type: ignore[arg-type]
    lab = ui.app.property("workspace").lab_model
    assert lab.property("stepCount") == 5
    assert ui.item("labStep").property("text") == "Step: Deliver Admit to Alice"


@pytest.mark.parametrize(("width", "height", "scale"), [(720, 540, 150), (1000, 700, 100)])
def test_the_lab_holds_at_small_windows_and_large_text(
    ui: Ui, width: int, height: int, scale: int
) -> None:
    host = lab_screen(ui, width, height, scale)
    ui.click("labRun")
    serve(ui.backend, host)  # type: ignore[arg-type]
    assert ui.item("labScreen").isVisible()
    assert ui.item("labTag").isVisible()


# -- recordings -------------------------------------------------------------------------------


def learn(ui: Ui, store: Recordings) -> LabHost:
    ui.unlock(online(BOB))
    ui.backend.reply(ui.backend.one("history"), ())
    ui.window.resize(1400, 860)
    host = lab_host(store)
    ui.item("messenger").setProperty("area", "learn")
    serve(ui.backend, host)
    return host


def test_a_run_is_saved_listed_replayed_and_deleted(ui: Ui) -> None:
    store = Recordings()
    host = learn(ui, store)
    ui.until(
        lambda: (f := ui.window.activeFocusItem()) is not None and f.objectName() == "openSoloLab"
    )
    ui.key(Qt.Key.Key_Space)
    serve(ui.backend, host)
    ui.click("labRun")
    serve(ui.backend, host)
    ui.click("labSave")
    field = ui.item("promptField")
    assert field.property("text") == "Solo lab · HYBRID-1 · 6 steps"
    ui.until(lambda: ui.window.activeFocusItem() is field)
    ui.key(Qt.Key.Key_Return)  # takes the suggestion
    serve(ui.backend, host)
    dialog = ui.window.findChild(QObject, "labSaveDialog")
    assert dialog is not None
    ui.until(lambda: not dialog.property("visible"))  # its modal overlay is gone
    assert len(store.saved) == 1
    (file_id,) = store.saved
    lab = ui.app.property("workspace").lab_model
    lab.reset("PQ-CNSA-1")
    serve(ui.backend, host)
    ui.item("messenger").setProperty("area", "learn")
    serve(ui.backend, host)
    ui.click(f"openRecording-{file_id}")
    serve(ui.backend, host)
    assert ui.item("labScreen").isVisible()
    assert lab.property("profile") == "HYBRID-1"
    assert lab.property("stepCount") == 6
    ui.item("messenger").setProperty("area", "learn")
    serve(ui.backend, host)
    ui.click(f"deleteRecording-{file_id}")
    assert store.saved  # the first click only asks
    ui.click(f"deleteRecording-{file_id}")
    serve(ui.backend, host)
    assert store.saved == {}
    assert ui.find(f"recording-{file_id}") is None


def test_a_glass_box_recording_opens_view_only(ui: Ui) -> None:
    store = Recordings()
    info = store.add(glass_box_recording())
    host = learn(ui, store)
    view = ui.item(f"openRecording-{info.file_id}")
    assert view.property("text") == "View"
    ui.click_item(view)
    serve(ui.backend, host)
    assert ui.item("exposedTag").isVisible()
    assert ui.find("labStep") is None or not ui.item("labStep").isVisible()
    inspector = ui.app.property("workspace").lab_model.inspector_model
    assert inspector.property("exposure") == "glass_box"
    assert inspector.trace_items


def test_only_a_glass_box_session_offers_saving_from_the_inspector(ui: Ui) -> None:
    ui.unlock(online(BOB, glass_box=True))
    ui.backend.reply(ui.backend.one("history"), ())
    ui.key(Qt.Key.Key_I, Qt.KeyboardModifier.ControlModifier)
    exposed = session_facts(session_id=7, contact_id=BOB.contact_id, glass_box=True, exposed=True)
    ui.backend.reply(ui.backend.one("inspect_sessions"), (exposed,))
    ui.backend.reply(ui.backend.one("inspect"), InspectSnap(exposed, (), missing=False))
    settled(ui)
    ui.click("saveRecording")
    ui.until(
        lambda: (f := ui.window.activeFocusItem()) is not None and f.objectName() == "promptField"
    )
    ui.key(Qt.Key.Key_Return)
    assert ui.backend.one("save_session_recording").args == {
        "session_id": 7,
        "title": "Glass-box with Bob",
    }
