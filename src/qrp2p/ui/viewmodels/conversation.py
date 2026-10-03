"""One conversation: the contact, its history, the draft and what can be done (UI_DESIGN §6).

History is loaded when the conversation is first shown. Updates that arrive while a load is under
way are held back and replayed on top of the loaded entries, in order: every stored change is
reported after it is written, so the last update for an entry is never older than what the load
read, and nothing is lost or shown twice.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Final

from PySide6.QtCore import Property, QObject, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices

from qrp2p.ui import ops
from qrp2p.ui.bridge import Scope
from qrp2p.ui.snapshots import ContactSnap, MessageChanged, MessageSnap, Reply, SafetySnap
from qrp2p.ui.text import isolate
from qrp2p.ui.viewmodels.listmodel import RowModel
from qrp2p.ui.viewmodels.qt import ViewModel, constant, items, mapped, readonly
from qrp2p.ui.viewmodels.rows import (
    TRUST_TEXT,
    Formats,
    MessageRow,
    ended_text,
    initial,
    message_rows,
    presence,
)

PAGE: Final = ops.HISTORY_PAGE


class Conversation(ViewModel):
    """The conversation with one contact.

    Args:
        scope: Requests for this unlocked period.
        contact: The contact as last reported.
        formats: Locale formatting for the rows.
        changed: Called when something the contact lists show changed (presence).
        mismatch_pending: Whether a key mismatch for a contact waits for the user; its dialog
            then explains a failed connection, so the banner stays quiet.
    """

    contactChanged = Signal()  # noqa: N815
    bannerChanged = Signal()  # noqa: N815
    historyChanged = Signal()  # noqa: N815
    safetyNumberChanged = Signal()  # noqa: N815
    draftChanged = Signal()  # noqa: N815
    actionFailed = Signal(str)  # noqa: N815
    """A request failed; the text is for the user."""
    draftRestored = Signal(str)  # noqa: N815
    """A message could not be sent; its text goes back into an empty composer."""

    def __init__(
        self,
        scope: Scope,
        contact: ContactSnap,
        formats: Formats,
        changed: Callable[[], None],
        mismatch_pending: Callable[[str], bool],
    ) -> None:
        super().__init__()
        self._scope = scope
        self._contact = contact
        self._formats = formats
        self._changed = changed
        self._mismatch_pending = mismatch_pending
        self._nearby = False
        self._connecting = ""
        self._closing = False
        self._messages: list[MessageSnap] = []
        self._progress: dict[str, int] = {}
        self._held: list[MessageChanged] | None = []
        self.messages: RowModel[MessageRow] = RowModel(MessageRow, lambda r: r.entry_id, self)
        self._draft = ""
        self._banner = ""
        self._banner_text = ""
        self._banner_tone = "neutral"
        self._offered = ""
        """The profile the contact asked for when we refused it (the banner's switch)."""
        self._loading = True
        self._has_earlier = False
        self._safety: SafetySnap | None = None
        self._busy_files: set[str] = set()
        """Files with an answer (accept, decline, cancel) on its way: not actionable again."""
        self._view = self._compute_view()
        self._load(PAGE)

    # -- properties -----------------------------------------------------------------------------

    messagesModel = constant(QObject, "messages")  # noqa: N815
    contactId = mapped(str, "_view", "contact_id", contactChanged)  # noqa: N815
    name = mapped(str, "_view", "name", contactChanged)
    avatarInitial = mapped(str, "_view", "initial", contactChanged)  # noqa: N815
    shortId = mapped(str, "_view", "short_id", contactChanged)  # noqa: N815
    fingerprint = mapped(str, "_view", "fingerprint", contactChanged)
    trust = mapped(str, "_view", "trust", contactChanged)
    trustText = mapped(str, "_view", "trust_text", contactChanged)  # noqa: N815
    profile = mapped(str, "_view", "profile", contactChanged)
    retention = mapped(str, "_view", "retention", contactChanged)
    autoAcceptFiles = mapped(bool, "_view", "auto_accept", contactChanged)  # noqa: N815
    autoAcceptLimit = mapped(float, "_view", "auto_accept_limit", contactChanged)  # noqa: N815
    address = mapped(str, "_view", "address", contactChanged)
    online = mapped(bool, "_view", "online", contactChanged)
    sessionProfile = mapped(str, "_view", "session_profile", contactChanged)  # noqa: N815
    glassBox = mapped(bool, "_view", "glass_box", contactChanged)  # noqa: N815
    initiator = mapped(bool, "_view", "initiator", contactChanged)
    presence = mapped(str, "_view", "presence", contactChanged)
    presenceText = mapped(str, "_view", "presence_text", contactChanged)  # noqa: N815
    banner = readonly(str, "_banner", bannerChanged)
    """``""``, ``connecting``, ``waiting``, ``error``, ``ended`` or ``profile`` (we refused it)."""
    offeredProfile = readonly(str, "_offered", bannerChanged)  # noqa: N815
    """For ``profile``: what the contact asked for."""
    bannerText = readonly(str, "_banner_text", bannerChanged)  # noqa: N815
    bannerTone = readonly(str, "_banner_tone", bannerChanged)  # noqa: N815
    """``neutral`` or ``danger`` (a failure the user should notice)."""
    loading = readonly(bool, "_loading", historyChanged)
    hasEarlier = readonly(bool, "_has_earlier", historyChanged)  # noqa: N815
    draft = readonly(str, "_draft", draftChanged)

    def _safety_groups(self) -> list[str]:
        return list(self._safety.groups) if self._safety is not None else []

    def _safety_short_id(self) -> str:
        return self._safety.short_id if self._safety is not None else ""

    safetyNumber = Property(list, _safety_groups, notify=safetyNumberChanged)  # noqa: N815
    """The digits, only while they belong to the identity pinned now (else empty)."""
    safetyShortId = Property(str, _safety_short_id, notify=safetyNumberChanged)  # noqa: N815
    """The ID of the identity the shown digits were computed for."""

    @property
    def contact(self) -> ContactSnap:
        """The contact as last reported."""
        return self._contact

    @property
    def connecting(self) -> str:
        """``""``, ``connecting`` or ``waiting`` (for the contact lists)."""
        return self._connecting

    # -- updates from the workspace --------------------------------------------------------------

    def set_contact(self, contact: ContactSnap) -> None:
        """The contact changed (name, trust, session, or its pinned identity after a re-pin)."""
        opened = contact.session is not None and self._contact.session is None
        repinned = contact.fingerprint != self._contact.fingerprint
        self._contact = contact
        if repinned and self._safety is not None:
            # The digits belonged to the old identity: never show or verify them for the new one.
            self._safety = None
            self.safetyNumberChanged.emit()
            self.loadSafetyNumber()
        if opened:
            self._connecting = ""
            self._closing = False
            self._set_banner("", "")
        self._refresh()

    def set_nearby(self, *, nearby: bool) -> None:
        """Whether the contact is announced on the LAN (a hint)."""
        if nearby != self._nearby:
            self._nearby = nearby
            self._refresh()

    def set_waiting(self) -> None:
        """Our handshake reached the peer's user (ConnectProgress)."""
        if self._connecting:
            self._connecting = "waiting"
            self._set_banner("waiting", f"Waiting for {self._contact.name} to accept…")
            self._refresh()

    def mismatch_opened(self) -> None:
        """A key mismatch for this contact was detected; its dialog explains what happened."""
        if self._banner in {"connecting", "waiting", "error"}:
            self._set_banner("", "")

    def session_ended(self, reason: str, *, by_peer: bool) -> None:
        """The session ended; say why unless the user closed it."""
        if self._closing and not by_peer:
            self._closing = False
            return
        self._closing = False
        tone = "neutral" if reason in {"", "normal", "locked"} else "danger"
        text = ended_text(reason, by_peer=by_peer, peer=self._contact.name)
        self._set_banner("ended", text, tone)

    def profile_refused(self, offered: str, configured: str) -> None:
        """We refused the contact's session: it asked for ``offered``, we have ``configured``."""
        self._offered = offered
        name = isolate(self._contact.name)
        self._set_banner(
            "profile",
            f"{name} tried to connect with {offered}, but your setting for them is "
            f"{configured}. Both sides must use the same profile.",
            "danger",
        )

    def apply(self, update: MessageChanged) -> None:
        """A history entry was added or changed."""
        if self._held is not None:  # a load is under way: replay this after it
            self._held.append(update)
            return
        self._upsert(update)
        self._rebuild()

    def set_formats(self, formats: Formats) -> None:
        """New formatting (e.g. the date changed, so "Today" moved)."""
        self._formats = formats
        self._rebuild()

    # -- slots: messages -------------------------------------------------------------------------

    @Slot(str)
    def setDraft(self, text: str) -> None:  # noqa: N802
        """The composer's text (kept in memory only, dropped at lock)."""
        self._draft = text

    @Slot(str, result=bool)
    def send(self, text: str) -> bool:
        """Send ``text``; ``False`` (keep the text) if it cannot be sent now."""
        if not text.strip() or self._contact.session is None:
            return False

        def done(reply: Reply) -> None:
            if reply.error is not None:
                self.draftRestored.emit(text)
                self.actionFailed.emit(f"Not sent: {reply.error.message}")

        self._draft = ""
        self.draftChanged.emit()
        return self._scope.request(ops.send_chat(self._contact.contact_id, text), done)

    @Slot(str)
    def retry(self, entry_id: str) -> None:
        """Send a failed message again, as a new message (never silently, UI_DESIGN §6.3)."""
        message = next((m for m in self._messages if m.entry_id == entry_id), None)
        if message is None or message.kind != "chat" or message.status != "failed":
            return
        if not self.send(message.text):
            self.actionFailed.emit("Connect first to send it again.")

    @Slot(str)
    def sendFile(self, url: str) -> None:  # noqa: N802
        """Offer the file at ``url`` (a local file URL or path)."""
        path = _local_path(url)
        if not path:
            return
        self._request(ops.send_file(self._contact.contact_id, path), "Could not offer the file")

    @Slot(str)
    def acceptFile(self, file_id: str) -> None:  # noqa: N802
        """Accept an offered file into the downloads folder."""
        self._file_request(file_id, ops.accept_file(file_id), "Could not accept the file")

    @Slot(str, str)
    def acceptFileTo(self, file_id: str, folder_url: str) -> None:  # noqa: N802
        """Accept an offered file into a chosen folder."""
        folder = _local_path(folder_url)
        if folder:
            op = ops.accept_file(file_id, folder)
            self._file_request(file_id, op, "Could not accept the file")

    @Slot(str)
    def declineFile(self, file_id: str) -> None:  # noqa: N802
        """Decline an offered file."""
        self._file_request(file_id, ops.decline_file(file_id), "Could not decline the file")

    @Slot(str)
    def cancelFile(self, file_id: str) -> None:  # noqa: N802
        """Cancel a transfer."""
        self._file_request(file_id, ops.cancel_file(file_id), "Could not cancel the transfer")

    def _file_request(self, file_id: str, op: ops.Op, failure: str) -> None:
        """One answer per file at a time: its actions stay disabled until the node replies."""
        if file_id in self._busy_files:
            return

        def done(reply: Reply) -> None:
            self._busy_files.discard(file_id)
            self._rebuild()
            if reply.error is not None:
                self.actionFailed.emit(f"{failure}: {reply.error.message}")

        if self._scope.request(op, done):
            self._busy_files.add(file_id)
            self._rebuild()

    @Slot(str)
    def showFile(self, entry_id: str) -> None:  # noqa: N802
        """Open the folder of a received file (the file itself never opens on its own)."""
        message = next((m for m in self._messages if m.entry_id == entry_id), None)
        if message is None or message.file is None or not message.file.path:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(message.file.path).parent)))

    @Slot()
    def loadEarlier(self) -> None:  # noqa: N802
        """Load an older page of history."""
        if self._has_earlier and self._held is None:
            self._load(len(self._messages) + PAGE)

    # -- slots: connection -----------------------------------------------------------------------

    @Slot()
    def connectSession(self) -> None:  # noqa: N802
        """Connect to the contact with its pinned identity and profile."""
        if self._connecting or self._contact.session is not None:
            return

        def done(reply: Reply) -> None:
            self._connecting = ""
            if reply.error is not None and not self._mismatch_pending(self._contact.contact_id):
                self._set_banner("error", f"Could not connect: {reply.error.message}", "danger")
            elif self._banner in {"connecting", "waiting"}:
                self._set_banner("", "")
            self._refresh()

        if self._scope.request(
            ops.connect_contact(self._contact.contact_id, glass_box=False), done
        ):
            self._connecting = "connecting"
            self._set_banner("connecting", f"Connecting to {self._contact.name}…")
            self._refresh()

    @Slot()
    def disconnectSession(self) -> None:  # noqa: N802
        """Close the session."""
        self._closing = True
        self._request(ops.disconnect(self._contact.contact_id), "Could not disconnect")

    @Slot()
    def rekey(self) -> None:
        """Start a post-quantum rekey now (only the side that opened the session can)."""
        self._request(ops.rekey(self._contact.contact_id), "Could not start a rekey")

    @Slot()
    def dismissBanner(self) -> None:  # noqa: N802
        """Hide the connection banner."""
        if self._banner not in {"connecting", "waiting"}:
            self._set_banner("", "")

    # -- slots: contact --------------------------------------------------------------------------

    @Slot()
    def loadSafetyNumber(self) -> None:  # noqa: N802
        """Fetch the 60-digit safety number (12 groups of five)."""

        def done(reply: Reply) -> None:
            snap = reply.value
            # Only digits for the identity pinned now (a re-pin may have overtaken the request).
            if isinstance(snap, SafetySnap) and snap.fingerprint == self._contact.fingerprint:
                self._safety = snap
                self.safetyNumberChanged.emit()

        self._scope.request(ops.safety_number(self._contact.contact_id), done)

    @Slot()
    def markVerified(self) -> None:  # noqa: N802
        """The user compared the shown safety number out of band and it matched.

        The request names the identity those digits belong to; the node refuses if the contact
        was re-pinned in between (DESIGN §5.3).
        """
        safety = self._safety
        if safety is None or safety.fingerprint != self._contact.fingerprint:
            self.actionFailed.emit("Compare the current safety number first.")
            return
        op = ops.set_trust(self._contact.contact_id, "verified", compared_peer_id=safety.peer_id)
        self._request(op, "Could not verify")

    @Slot()
    def unverify(self) -> None:
        """Back to pinned (not verified)."""
        self._request(ops.set_trust(self._contact.contact_id, "pinned"), "Could not change trust")

    @Slot()
    def block(self) -> None:
        """Block: no sessions with this contact (an open one closes)."""
        self._closing = True
        self._request(ops.set_trust(self._contact.contact_id, "blocked"), "Could not block")

    @Slot()
    def unblock(self) -> None:
        """Unblock (pinned again)."""
        self._request(ops.set_trust(self._contact.contact_id, "pinned"), "Could not unblock")

    @Slot(str)
    def rename(self, name: str) -> None:
        """Rename the contact (only on this device)."""
        self._request(ops.rename_contact(self._contact.contact_id, name), "Could not rename")

    @Slot(str)
    def setProfile(self, profile: str) -> None:  # noqa: N802
        """The profile sessions with this contact use."""
        op = ops.set_contact_profile(self._contact.contact_id, profile)
        self._request(op, "Could not change the profile")
        if self._banner == "profile":
            self._set_banner("", "")

    @Slot()
    def useOfferedProfile(self) -> None:  # noqa: N802
        """Switch to the profile the contact asked for when we refused it."""
        if self._banner == "profile" and self._offered:
            self.setProfile(self._offered)

    @Slot(str)
    def setRetention(self, retention: str) -> None:  # noqa: N802
        """How long this conversation is kept."""
        op = ops.set_retention(self._contact.contact_id, retention)
        self._request(op, "Could not change how long history is kept")

    @Slot(bool, float)
    def setAutoAccept(self, enabled: bool, limit: float) -> None:  # noqa: FBT001, N802
        """Accept files up to ``limit`` bytes without asking (verified contacts only)."""
        op = ops.set_auto_accept(self._contact.contact_id, enabled=enabled, limit=int(limit))
        self._request(op, "Could not change file auto-accept")

    @Slot()
    def deleteHistory(self) -> None:  # noqa: N802
        """Delete this conversation's history (the contact stays)."""

        def done(reply: Reply) -> None:
            if reply.error is not None:
                self.actionFailed.emit(f"Could not delete the history: {reply.error.message}")
                return
            self._messages.clear()
            self._progress.clear()
            self._load(PAGE)

        self._scope.request(ops.delete_conversation(self._contact.contact_id), done)

    @Slot()
    def deleteContact(self) -> None:  # noqa: N802
        """Delete the contact and its history."""
        self._closing = True
        self._request(ops.delete_contact(self._contact.contact_id), "Could not delete the contact")

    # -- internals -------------------------------------------------------------------------------

    def _request(self, op: ops.Op, failure: str) -> None:
        def done(reply: Reply) -> None:
            if reply.error is not None:
                self._closing = False
                self.actionFailed.emit(f"{failure}: {reply.error.message}")

        self._scope.request(op, done)

    def _set_banner(self, kind: str, text: str, tone: str = "neutral") -> None:
        if (kind, text, tone) != (self._banner, self._banner_text, self._banner_tone):
            self._banner, self._banner_text, self._banner_tone = kind, text, tone
            self.bannerChanged.emit()

    def _compute_view(self) -> dict[str, object]:
        c = self._contact
        session = c.session
        state, text = presence(c, self._connecting, nearby=self._nearby)
        return {
            "contact_id": c.contact_id,
            "name": c.name,
            "initial": initial(c.name),
            "short_id": c.short_id,
            "fingerprint": c.fingerprint,
            "trust": c.trust,
            "trust_text": TRUST_TEXT.get(c.trust, c.trust),
            "profile": c.profile,
            "retention": c.retention,
            "auto_accept": c.auto_accept_files,
            "auto_accept_limit": float(c.auto_accept_limit),
            "address": c.address,
            "online": session is not None,
            "session_profile": session.profile if session is not None else "",
            "glass_box": session is not None and session.glass_box,
            "initiator": session is not None and session.initiator,
            "presence": state,
            "presence_text": text,
        }

    def _refresh(self) -> None:
        view = self._compute_view()
        if view != self._view:
            self._view = view
            self.contactChanged.emit()
        self._changed()

    def _load(self, limit: int) -> None:
        self._held = []
        self._set_loading(loading=True)

        def done(reply: Reply) -> None:
            held, self._held = self._held or [], None
            if reply.error is None:
                self._messages = items(reply.value, MessageSnap)
                self._has_earlier = len(self._messages) >= limit
            for update in held:
                self._upsert(update)
            self._rebuild()
            self._set_loading(loading=False)
            if reply.error is not None:
                self.actionFailed.emit(f"Could not load the history: {reply.error.message}")

        if not self._scope.request(ops.history(self._contact.contact_id, limit), done):
            self._held = None
            self._set_loading(loading=False)

    def _set_loading(self, *, loading: bool) -> None:
        self._loading = loading
        self.historyChanged.emit()

    def _upsert(self, update: MessageChanged) -> None:
        message = update.message
        file = message.file
        if file is not None:
            if file.transferred is not None:
                self._progress[message.entry_id] = file.transferred
            elif file.status != "transferring":  # a status report keeps the last count
                self._progress.pop(message.entry_id, None)
        at = next(
            (
                i
                for i in range(len(self._messages) - 1, -1, -1)  # recent entries change most
                if self._messages[i].entry_id == message.entry_id
            ),
            None,
        )
        if at is None:
            self._messages.append(message)
        else:
            self._messages[at] = message

    def _rebuild(self) -> None:
        rows = message_rows(
            self._messages,
            self._progress,
            self._contact.name,
            self._formats,
            busy_files=frozenset(self._busy_files),
        )
        self.messages.sync(rows)


def _local_path(url: str) -> str:
    """A local path from a file URL (QML dialogs) or a plain path."""
    if not url:
        return ""
    parsed = QUrl(url)
    if parsed.isLocalFile():
        return parsed.toLocalFile()
    return url if Path(url).is_absolute() else ""
