"""View models against a fake services side: lifecycle, lock, history races, delivery, prompts.

These are the contracts UI_DESIGN §13.1 asks to test before any screen is wired: immutable
snapshots, the generation filter, stale commands and prompts, lock with queued updates, admission
capacity, and the password-change outcomes.
"""

from collections.abc import Iterator
from dataclasses import replace

import pytest
from PySide6.QtCore import QCoreApplication

from qrp2p.ui.snapshots import (
    ActivitySnap,
    Batch,
    ConnectStage,
    ContactChanged,
    ContactRemoved,
    ErrorInfo,
    FileSnap,
    MessageChanged,
    MessageSnap,
    MismatchOpened,
    MismatchSnap,
    PromptClosed,
    PromptOpened,
    PromptSnap,
    SafetySnap,
    SessionEnded,
)
from qrp2p.ui.text import isolate
from qrp2p.ui.viewmodels.application import INTERRUPTED_CHANGE, AppController
from qrp2p.ui.viewmodels.conversation import Conversation
from qrp2p.ui.viewmodels.workspace import Workspace
from tests.ui.fakes import SETTINGS, FakeBackend, chat, contact, offline, online, settle, workspace

BOB = contact("Bob", created=1000.0)
CAROL = contact("Carol", created=2000.0)


@pytest.fixture
def backend(qapp: QCoreApplication) -> FakeBackend:  # noqa: ARG001
    return FakeBackend()


@pytest.fixture
def app(backend: FakeBackend) -> Iterator[AppController]:
    controller = AppController(backend.bridge, data_dir="/data")
    yield controller
    controller.deleteLater()
    settle()


def unlock(backend: FakeBackend, app: AppController, *contacts: object) -> Workspace:
    """Unlock with these contacts and finish loading; returns the workspace."""
    backend.lifecycle("unlocked", workspace(*contacts))  # type: ignore[arg-type]
    assert app.property("phase") == "opening"
    activity = backend.one("recent_activity")
    backend.reply(activity, ActivitySnap(tuple((c.contact_id, c.created) for c in contacts)))  # type: ignore[attr-defined]
    assert app.property("phase") == "unlocked"
    ws = app.property("workspace")
    assert isinstance(ws, Workspace)
    return ws


def selected(ws: Workspace) -> Conversation:
    conversation = ws.conversation_model
    assert conversation is not None
    return conversation


def load(backend: FakeBackend, *messages: object) -> None:
    backend.reply(backend.one("history"), tuple(messages))


def rows(conversation: Conversation) -> list[tuple[str, str]]:
    return [(r.text, r.status) for r in conversation.messages.rows()]


# -- application ------------------------------------------------------------------------------------


def test_phases_follow_the_node(backend: FakeBackend, app: AppController) -> None:
    assert app.property("phase") == "starting"
    backend.lifecycle("no_vault")
    assert app.property("phase") == "noVault"
    app.createVault("Me", "short", "short")
    assert app.property("error") == "Use at least 8 characters."
    app.createVault("Me", "long enough", "different!")
    assert app.property("error") == "The passwords differ."
    assert backend.requests == []
    app.createVault("Me", "long enough", "long enough")
    create = backend.one("create_vault")
    assert not create.scoped
    assert app.property("busy")
    ws = unlock(backend, app)
    assert ws.property("ready")
    assert app.property("busy") is False
    backend.reply(create)
    assert app.property("welcome")
    app.dismissWelcome()
    assert not app.property("welcome")


def test_a_lock_drops_the_workspace_before_queued_updates_arrive(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    conversation = selected(ws)
    load(backend, chat("before the lock"))
    assert rows(conversation) == [("before the lock", "received")]
    assert backend.post is not None
    # A message is on its way through the queue when the user locks.
    backend.post(
        Batch(backend.gen, (MessageChanged(BOB.contact_id, chat("in flight"), added=True),))
    )
    app.lock()
    assert app.property("workspace") is None
    assert app.property("phase") == "locking"
    settle()
    assert rows(conversation) == [("before the lock", "received")]  # nothing refilled it
    lock = backend.one("lock")
    assert not lock.scoped
    backend.lifecycle("locked")
    assert app.property("phase") == "locked"
    again = unlock(backend, app, BOB)
    assert again is not ws
    assert again.conversation_model is not conversation
    assert selected(again).messages.rows() == ()  # a new period loads its own history
    assert backend.pending("history")


def test_a_view_model_from_before_a_lock_cannot_answer_a_new_request(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    old_prompts = ws.prompts_model
    prompt = PromptSnap(
        prompt_id=1,
        kind="contact_request",
        short_id="EVEX-0000",
        contact_id="",
        name="",
        profile="HYBRID-1",
        glass_box_refused=False,
        expires_in=60.0,
    )
    backend.updates(PromptOpened(prompt))
    app.lock()
    backend.lifecycle("locked")
    new = unlock(backend, app, BOB)
    backend.updates(PromptOpened(prompt))  # the node numbers prompts afresh: the same ID again
    old_prompts.accept("Eve")  # a stale dialog's button
    assert backend.pending("answer_prompt") == []
    new.prompts_model.accept("Eve")
    assert backend.one("answer_prompt").args["prompt_id"] == 1


def test_device_unlock_is_tried_only_when_the_app_starts(
    backend: FakeBackend, app: AppController
) -> None:
    backend.lifecycle("locked")
    backend.reply(backend.one("device_unlock_available"), True)
    assert app.property("deviceUnlockAvailable")
    attempt = backend.one("unlock_with_device")
    assert app.property("busyText") == "Unlocking with this device…"
    unlock(backend, app, BOB)
    backend.reply(attempt)
    app.lock()
    backend.lifecycle("locked")
    backend.reply(backend.one("device_unlock_available"), True)
    assert backend.pending("unlock_with_device") == []  # the device key must not undo a lock


def test_failed_device_unlock_falls_back_to_the_password(
    backend: FakeBackend, app: AppController
) -> None:
    backend.lifecycle("locked")
    backend.reply(backend.one("device_unlock_available"), True)
    backend.reply(backend.one("unlock_with_device"), error=ErrorInfo("keychain", "No keychain."))
    assert app.property("busy") is False
    assert "Use your password" in app.property("error")
    app.unlock("pw")
    backend.reply(backend.one("unlock"), error=ErrorInfo("wrong_password", "Wrong password."))
    assert app.property("error") == "Wrong password."


@pytest.mark.parametrize(("state", "phase"), [("in_use", "inUse"), ("failed", "failed")])
def test_the_node_could_not_start(
    backend: FakeBackend, app: AppController, state: str, phase: str
) -> None:
    backend.lifecycle(state, error="disk on fire")
    assert app.property("phase") == phase


def test_password_change_outcomes(backend: FakeBackend, app: AppController) -> None:
    unlock(backend, app, BOB)
    results: list[tuple[bool, str]] = []
    app.passwordChangeFinished.connect(lambda ok, text: results.append((ok, text)))
    app.changePassword("old", "new password", "new password")
    backend.reply(backend.one("change_password"))
    app.changePassword("old", "new password", "new password")
    cleanup = "Password changed; vault cleanup failed. The new password is active."
    backend.reply(backend.one("change_password"), error=ErrorInfo("cleanup", cleanup))
    app.changePassword("bad", "new password", "new password")
    backend.reply(backend.one("change_password"), error=ErrorInfo("wrong_password", "x"))
    assert results == [
        (True, "Password changed; everything was re-encrypted."),
        (True, cleanup),
        (False, "The current password is wrong."),
    ]
    # An uncertain commit locks the node before its answer arrives; the answer still does.
    app.changePassword("old", "new password", "new password")
    request = backend.one("change_password")
    assert not request.scoped
    backend.lifecycle("locked")
    backend.reply(request, error=ErrorInfo("vault", "the commit outcome is unknown"))
    assert results[-1] == (False, INTERRUPTED_CHANGE)
    assert app.property("notice") == INTERRUPTED_CHANGE
    assert app.property("phase") == "locked"


def test_appearance_follows_the_settings(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    ws.settings_model.set("appearance", "dark")
    request = backend.one("update_setting")
    assert request.args == {"name": "appearance", "value": "dark"}
    assert app.property("appearance") == "system"  # shown once the vault holds it
    backend.reply(request, replace(SETTINGS, appearance="dark", text_scale=130))
    assert (app.property("appearance"), app.property("textScale")) == ("dark", 130)
    app.lock()
    assert app.property("appearance") == "dark"  # kept while locked


# -- conversations ----------------------------------------------------------------------------------


def test_history_and_updates_that_race_its_load(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, online(BOB))
    conversation = selected(ws)
    assert conversation.property("loading")
    sent = chat("hi", direction="out", status="sending")
    # While the load runs: the message is added, then its receipt arrives...
    backend.updates(
        MessageChanged(BOB.contact_id, sent, added=True),
        MessageChanged(BOB.contact_id, replace(sent, status="sent"), added=False),
        MessageChanged(BOB.contact_id, replace(sent, status="delivered"), added=False),
    )
    assert conversation.messages.rows() == ()
    # ...and the load read the entry between the second and third change.
    load(backend, chat("older"), replace(sent, status="sent"))
    assert rows(conversation) == [("older", "received"), ("hi", "delivered")]
    assert not conversation.property("loading")


def test_receipts_move_a_message_to_delivered(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, online(BOB))
    conversation = selected(ws)
    load(backend)
    assert conversation.send("hello")
    request = backend.one("send_chat")
    assert request.args == {"contact_id": BOB.contact_id, "text": "hello"}
    message = chat("hello", direction="out", status="sending")
    states: list[str] = []
    for status in ("sending", "sent", "delivered"):
        backend.updates(
            MessageChanged(
                BOB.contact_id, replace(message, status=status), added=status == "sending"
            )
        )
        states.append(conversation.messages.rows()[-1].status_text)
    assert states == ["Sending…", "Sent", "Delivered"]
    assert len(conversation.messages.rows()) == 1


def test_sending_needs_a_session_and_keeps_the_text_on_failure(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    conversation = selected(ws)
    load(backend)
    assert not conversation.send("hello")  # offline: the composer keeps the text
    assert backend.pending("send_chat") == []
    backend.updates(ContactChanged(online(BOB)))
    restored: list[str] = []
    failures: list[str] = []
    conversation.draftRestored.connect(restored.append)
    conversation.actionFailed.connect(failures.append)
    assert conversation.send("hello")
    backend.reply(backend.one("send_chat"), error=ErrorInfo("not_connected", "not connected"))
    assert restored == ["hello"]
    assert failures == ["Not sent: not connected"]


def test_a_failed_message_is_sent_again_only_on_request(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, online(BOB))
    conversation = selected(ws)
    failed = chat("lost", direction="out", status="failed")
    load(backend, failed)
    assert backend.pending("send_chat") == []
    conversation.retry(failed.entry_id)
    assert backend.one("send_chat").args["text"] == "lost"


def test_connecting_shows_each_stage(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    conversation = selected(ws)
    load(backend)
    conversation.connectSession()
    assert conversation.property("banner") == "connecting"
    assert ws.strip.rows()[0].presence == "connecting"  # type: ignore[attr-defined]
    backend.updates(ConnectStage(BOB.contact_id, "10.0.0.2:47470", "waiting_for_admission"))
    assert conversation.property("banner") == "waiting"
    backend.reply(
        backend.one("connect_contact"),
        error=ErrorInfo("node", "the peer rejected the session: declined"),
    )
    assert conversation.property("banner") == "error"
    assert (
        conversation.property("bannerText")
        == "Could not connect: the peer rejected the session: declined"
    )
    assert ws.strip.rows()[0].presence == "offline"  # type: ignore[attr-defined]
    conversation.connectSession()
    backend.updates(ContactChanged(online(BOB)))
    assert conversation.property("banner") == ""
    backend.reply(backend.one("connect_contact"))
    assert conversation.property("presence") == "online"


def test_a_key_mismatch_replaces_the_connection_error(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    conversation = selected(ws)
    load(backend)
    conversation.connectSession()
    mismatch = MismatchSnap(
        mismatch_id=7,
        contact_id=BOB.contact_id,
        name="Bob",
        expected_short_id="BOBX-0000",
        actual_short_id="EVIL-0000",
        expected_fingerprint="aaaa",
        actual_fingerprint="bbbb",
    )
    backend.updates(MismatchOpened(mismatch))  # the node reports it before the connect fails
    backend.reply(
        backend.one("connect_contact"),
        error=ErrorInfo("node", "the handshake failed: pin_mismatch"),
    )
    assert conversation.property("banner") == ""
    prompts = ws.prompts_model
    assert prompts.property("kind") == "mismatch"
    assert prompts.property("actualShortId") == "EVIL-0000"


def test_session_end_is_explained_unless_the_user_closed_it(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, online(BOB))
    conversation = selected(ws)
    load(backend)
    backend.updates(
        ContactChanged(offline(BOB)), SessionEnded(BOB.contact_id, "decrypt_failed", by_peer=False)
    )
    assert conversation.property("banner") == "ended"
    assert conversation.property("bannerText") == "Authentication failed (decrypt_failed)"
    conversation.dismissBanner()
    backend.updates(ContactChanged(online(BOB)))
    conversation.disconnectSession()
    backend.one("disconnect")
    backend.updates(
        ContactChanged(offline(BOB)), SessionEnded(BOB.contact_id, "normal", by_peer=False)
    )
    assert conversation.property("banner") == ""


# -- workspace --------------------------------------------------------------------------------------


def test_the_most_recent_conversation_opens(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB, CAROL)
    assert ws.property("selectedId") == CAROL.contact_id  # created later
    assert [r.name for r in ws.strip.rows()] == ["Carol", "Bob"]  # type: ignore[attr-defined]


def test_unread_counts(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, online(BOB), online(CAROL))
    selected(ws)
    attention: list[str] = []
    ws.incomingMessage.connect(attention.append)
    backend.updates(MessageChanged(BOB.contact_id, chat("psst"), added=True))
    assert {r.name: r.unread for r in ws.strip.rows()} == {"Bob": 1, "Carol": 0}  # type: ignore[attr-defined]
    assert attention == ["Bob"]
    ws.setStripLimit(1)  # only Bob fits now (most recent)...
    ws.select(CAROL.contact_id)  # ...until Carol is selected: she must stay visible
    assert [r.name for r in ws.strip.rows()] == ["Carol"]  # type: ignore[attr-defined]
    assert ws.property("hiddenUnread") == 1
    ws.select(BOB.contact_id)
    assert ws.property("hiddenUnread") == 0
    ws.setWindowActive(False)
    backend.updates(MessageChanged(BOB.contact_id, chat("again"), added=True))
    assert ws.strip.rows()[0].unread == 1  # type: ignore[attr-defined]
    ws.setWindowActive(True)
    assert ws.strip.rows()[0].unread == 0  # type: ignore[attr-defined]


def test_a_deleted_contact_moves_the_selection(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB, CAROL)
    assert ws.property("selectedId") == CAROL.contact_id
    backend.updates(ContactRemoved(CAROL.contact_id))
    assert ws.property("selectedId") == BOB.contact_id
    backend.updates(ContactRemoved(BOB.contact_id))
    assert ws.property("selectedId") == ""
    assert ws.conversation_model is None


def test_the_chooser_filters_by_name_and_short_id(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB, CAROL)
    ws.setSearch("car")
    assert [r.name for r in ws.contacts.rows()] == ["Carol"]  # type: ignore[attr-defined]
    ws.setSearch("bobx0")
    assert [r.name for r in ws.contacts.rows()] == ["Bob"]  # type: ignore[attr-defined]
    ws.setSearch("")
    assert ws.property("contactCount") == 2


def test_connect_by_address_reports_each_stage(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    connected: list[str] = []
    ws.addressConnected.connect(connected.append)
    ws.connectAddress("10.0.0.9", 47470, "Dave", "")
    assert ws.property("addressStage") == "connecting"
    backend.updates(ConnectStage("", "10.0.0.9:47470", "waiting_for_admission"))
    assert ws.property("addressStage") == "waiting"
    dave = contact("Dave")
    backend.updates(ContactChanged(online(dave)))
    backend.reply(backend.one("connect_address"), dave.contact_id)
    assert connected == [dave.contact_id]
    assert ws.property("selectedId") == dave.contact_id
    ws.connectAddress("10.0.0.10", 47470, "", "")
    backend.reply(
        backend.one("connect_address"), error=ErrorInfo("node", "could not reach the peer")
    )
    assert ws.property("addressError") == "Could not reach the peer"
    assert not ws.property("addressBusy")


# -- prompts ----------------------------------------------------------------------------------------


def request(prompt_id: int, kind: str = "contact_request", **changes: object) -> PromptSnap:
    snap = PromptSnap(
        prompt_id=prompt_id,
        kind=kind,
        short_id="CARL-0000",
        contact_id="",
        name="",
        profile="HYBRID-1",
        glass_box_refused=False,
        expires_in=60.0,
    )
    return replace(snap, **changes)


def test_an_accepted_contact_request_opens_the_new_conversation(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    prompts = ws.prompts_model
    backend.updates(PromptOpened(request(1)))
    assert (prompts.property("kind"), prompts.property("stage")) == ("contact_request", "ask")
    assert 0 < prompts.property("secondsLeft") <= 60
    notices: list[str] = []
    ws.noticePosted.connect(notices.append)
    prompts.accept("Carol")
    assert prompts.property("stage") == "working"
    # As the node does it: the contact is saved and reported before the answer's reply.
    backend.updates(ContactChanged(online(CAROL)), PromptClosed(1, "accepted"))
    backend.reply(backend.one("answer_prompt"), "accepted")
    assert prompts.property("kind") == ""
    assert ws.property("selectedId") == CAROL.contact_id
    assert notices == [f"Added {isolate('Carol')}. Compare safety numbers to verify them."]


def test_acceptance_can_end_busy(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    prompts = ws.prompts_model
    backend.updates(PromptOpened(request(1)))
    prompts.accept("Carol")
    backend.reply(backend.one("answer_prompt"), "busy")
    assert prompts.property("stage") == "result"
    assert prompts.property("resultIsError")
    assert prompts.property("resultText").startswith("The contact was saved. QRP2P refused")
    prompts.close()
    assert prompts.property("kind") == ""


def test_a_request_that_expires_while_shown(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    prompts = ws.prompts_model
    backend.updates(
        PromptOpened(request(1)),
        PromptOpened(request(2, kind="glass_box", contact_id=BOB.contact_id, name="Bob")),
    )
    assert prompts.property("queued") == 1
    backend.updates(PromptClosed(1, "expired"))
    assert prompts.property("stage") == "result"
    assert (
        prompts.property("resultText")
        == "This request expired: nobody answered it within 60 seconds."
    )
    prompts.accept("too late")
    assert backend.pending("answer_prompt") == []
    prompts.close()
    assert prompts.property("kind") == "glass_box"
    assert prompts.property("name") == "Bob"


def test_a_queued_request_that_ends_leaves_quietly(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    prompts = ws.prompts_model
    backend.updates(PromptOpened(request(1)), PromptOpened(request(2)))
    backend.updates(PromptClosed(2, "withdrawn"))
    assert (prompts.property("promptId"), prompts.property("queued")) == (1, 0)


def test_re_pinning_takes_two_explicit_steps(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    prompts = ws.prompts_model
    verify: list[str] = []
    ws.verifyRequested.connect(verify.append)
    mismatch = MismatchSnap(
        mismatch_id=3,
        contact_id=BOB.contact_id,
        name="Bob",
        expected_short_id="BOBX-0000",
        actual_short_id="EVIL-0000",
        expected_fingerprint="aaaa",
        actual_fingerprint="bbbb",
    )
    backend.updates(MismatchOpened(mismatch))
    prompts.repin()  # not without the confirmation step
    assert backend.pending("resolve_mismatch") == []
    prompts.startRepin()
    assert prompts.property("stage") == "confirm"
    prompts.back()
    assert prompts.property("stage") == "ask"
    prompts.startRepin()
    prompts.repin()
    request_ = backend.one("resolve_mismatch")
    assert request_.args["repin"] is True
    backend.reply(request_)
    assert prompts.property("stage") == "result"
    prompts.verifyNow()
    assert verify == [BOB.contact_id]
    assert prompts.property("kind") == ""


def test_cancel_keeps_the_saved_identity(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, BOB)
    prompts = ws.prompts_model
    mismatch = MismatchSnap(
        mismatch_id=4,
        contact_id=BOB.contact_id,
        name="Bob",
        expected_short_id="BOBX-0000",
        actual_short_id="EVIL-0000",
        expected_fingerprint="aaaa",
        actual_fingerprint="bbbb",
    )
    backend.updates(MismatchOpened(mismatch))
    prompts.keep()
    keep = backend.one("resolve_mismatch")
    assert keep.args["repin"] is False
    backend.reply(keep)
    assert prompts.property("kind") == ""


# -- review findings (2026-10-02) --------------------------------------------------------------------


def test_the_first_lock_after_creating_a_vault_stays_locked(
    backend: FakeBackend, app: AppController
) -> None:
    backend.lifecycle("no_vault")
    app.createVault("Me", "long enough", "long enough")
    unlock(backend, app, BOB)
    backend.reply(backend.one("create_vault"))
    # The user turns on "Remember on this device", then locks.
    app.lock()
    backend.lifecycle("locked")
    backend.reply(backend.one("device_unlock_available"), True)
    assert app.property("deviceUnlockAvailable")  # offered as a button...
    assert backend.pending("unlock_with_device") == []  # ...but never used by itself


def safety(contact_snap: object, groups: tuple[str, ...]) -> SafetySnap:
    return SafetySnap(
        peer_id=contact_snap.fingerprint.replace(" ", "")[:96],  # type: ignore[attr-defined]
        fingerprint=contact_snap.fingerprint,  # type: ignore[attr-defined]
        short_id=contact_snap.short_id,  # type: ignore[attr-defined]
        groups=groups,
    )


def test_verification_is_bound_to_the_identity_that_was_compared(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    conversation = selected(ws)
    load(backend)
    conversation.loadSafetyNumber()
    old_request = backend.one("safety_number")
    backend.reply(old_request, safety(BOB, ("11111",) * 12))
    assert conversation.property("safetyNumber") == ["11111"] * 12
    # A re-pin replaces the identity while the comparison is on screen.
    repinned = replace(BOB, fingerprint="ffff " * 24, short_id="NEWW-0000")
    backend.updates(ContactChanged(repinned))
    assert conversation.property("safetyNumber") == []  # the old digits are gone at once
    failures: list[str] = []
    conversation.actionFailed.connect(failures.append)
    conversation.markVerified()
    assert backend.pending("set_trust") == []
    assert failures == ["Compare the current safety number first."]
    new_request = backend.one("safety_number")  # reloaded for the new identity
    backend.reply(new_request, safety(repinned, ("22222",) * 12))
    assert conversation.property("safetyNumber") == ["22222"] * 12
    assert conversation.property("safetyShortId") == "NEWW-0000"
    conversation.markVerified()
    verify = backend.one("set_trust")
    assert verify.args["trust"] == "verified"
    assert verify.args["compared_peer_id"] == safety(repinned, ()).peer_id


def test_a_late_safety_number_of_the_old_identity_is_ignored(
    backend: FakeBackend, app: AppController
) -> None:
    ws = unlock(backend, app, BOB)
    conversation = selected(ws)
    load(backend)
    conversation.loadSafetyNumber()
    request = backend.one("safety_number")
    repinned = replace(BOB, fingerprint="ffff " * 24, short_id="NEWW-0000")
    backend.updates(ContactChanged(repinned))
    backend.reply(request, safety(BOB, ("11111",) * 12))  # computed before the re-pin
    assert conversation.property("safetyNumber") == []


def test_a_file_offer_is_answered_once(backend: FakeBackend, app: AppController) -> None:
    ws = unlock(backend, app, online(BOB))
    conversation = selected(ws)
    offer = MessageSnap(
        entry_id="f" * 32,
        kind="file",
        direction="in",
        time=2_000_000_000.0,
        status="received",
        text="",
        glass_box=False,
        file=FileSnap(
            file_id="a" * 32,
            name="notes.pdf",
            size=10,
            status="offered",
            path="",
            reason="",
            transferred=None,
        ),
    )
    load(backend, offer)
    conversation.acceptFile("a" * 32)
    conversation.acceptFile("a" * 32)
    conversation.declineFile("a" * 32)
    assert len(backend.pending("accept_file")) == 1
    assert backend.pending("decline_file") == []
    assert conversation.messages.rows()[0].file_busy
    backend.reply(backend.one("accept_file"))
    assert not conversation.messages.rows()[0].file_busy
