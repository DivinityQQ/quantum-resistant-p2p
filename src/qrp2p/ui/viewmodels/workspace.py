"""The unlocked app: contacts, discovery, selection, conversations and requests (UI_DESIGN §3, §6).

A workspace is created from the snapshot taken when the node unlocked and lives exactly as long as
that unlocked period: locking destroys it, with every conversation, draft, prompt and cached value
in it, and the next unlock builds a new one. Nothing sensitive can outlive a lock by being
forgotten in a model.
"""

import time
from datetime import date, datetime, timedelta
from typing import Final

from PySide6.QtCore import QDate, QDateTime, QLocale, QObject, QTimer, Signal, Slot

from qrp2p.ui import ops
from qrp2p.ui.bridge import Scope
from qrp2p.ui.snapshots import (
    ActivitySnap,
    ConnectStage,
    ContactChanged,
    ContactRemoved,
    ContactSnap,
    MessageChanged,
    MismatchOpened,
    NearbyChanged,
    NearbySnap,
    NetworkSnap,
    NoticePosted,
    ProfileRefused,
    PromptClosed,
    PromptOpened,
    Reply,
    SessionEnded,
    Update,
    WorkspaceSnap,
)
from qrp2p.ui.tap import SessionDescribed, SessionRemoved, TraceAppended, TraceOverflow
from qrp2p.ui.text import isolate
from qrp2p.ui.viewmodels.conversation import Conversation
from qrp2p.ui.viewmodels.inspector import Inspector
from qrp2p.ui.viewmodels.lab import Lab
from qrp2p.ui.viewmodels.listmodel import RowModel
from qrp2p.ui.viewmodels.prompts import Prompts
from qrp2p.ui.viewmodels.qt import ViewModel, constant, readonly
from qrp2p.ui.viewmodels.rows import (
    ContactRow,
    Formats,
    NearbyRow,
    contact_row,
    nearby_row,
    strip_order,
)
from qrp2p.ui.viewmodels.settings import SettingsModel

STRIP_LIMIT: Final = 5
"""Contacts the strip shows at most (UI_DESIGN §3.1); the window may ask for fewer."""


def locale_formats(today: date) -> Formats:
    """Times, days and sizes in the system locale."""
    locale = QLocale()

    def time_text(seconds: float) -> str:
        moment = QDateTime.fromSecsSinceEpoch(int(seconds))
        return locale.toString(moment.time(), QLocale.FormatType.ShortFormat)

    def day(seconds: float) -> str:
        when = datetime.fromtimestamp(seconds).date()  # noqa: DTZ006  # the local calendar day
        if when == today:
            return "Today"
        if when == today - timedelta(days=1):
            return "Yesterday"
        return locale.toString(
            QDate(when.year, when.month, when.day), QLocale.FormatType.LongFormat
        )

    def size(count: int) -> str:
        return locale.formattedDataSize(count, 1, QLocale.DataSizeFormat.DataSizeSIFormat)

    return Formats(time=time_text, day=day, size=size)


class Workspace(ViewModel):
    """The unlocked app.

    Args:
        scope: Requests for this unlocked period, and its updates.
        snap: Everything the node showed at unlock.
    """

    networkChanged = Signal()  # noqa: N815
    contactsChanged = Signal()  # noqa: N815
    selectionChanged = Signal()  # noqa: N815
    searchChanged = Signal()  # noqa: N815
    addressChanged = Signal()  # noqa: N815
    readyChanged = Signal()  # noqa: N815
    noticePosted = Signal(str)  # noqa: N815
    """A short message for a toast."""
    unreadChanged = Signal()  # noqa: N815
    incomingMessage = Signal(str)  # noqa: N815
    """A message or file offer arrived (the contact's name), to draw attention to the window."""
    addressConnected = Signal(str)  # noqa: N815
    """A connection by address or from Nearby opened; the new or existing contact's ID."""
    verifyRequested = Signal(str)  # noqa: N815
    """Show the safety-number comparison for this contact."""

    shortId = constant(str, "_short_id")  # noqa: N815
    fingerprint = constant(str, "_fingerprint")
    bundleBytes = constant(int, "_bundle_bytes")  # noqa: N815
    identityParts = constant(list, "_identity_parts")  # noqa: N815
    port = readonly(int, "_port", networkChanged)
    addresses = readonly(list, "_addresses", networkChanged)
    discovery = readonly(bool, "_discovery", networkChanged)
    settings = constant(QObject, "_settings")
    prompts = constant(QObject, "_prompts")
    inspector = constant(QObject, "_inspector")
    lab = constant(QObject, "_lab")
    strip = constant(QObject, "_strip")
    contacts = constant(QObject, "_contacts_model")
    nearby = constant(QObject, "_nearby_model")
    contactCount = readonly(int, "_contact_count", contactsChanged)  # noqa: N815
    hiddenUnread = readonly(int, "_hidden_unread", contactsChanged)  # noqa: N815
    unread = readonly(int, "_total_unread", unreadChanged)
    """Unread messages and file offers in all conversations (the window title and app badge)."""
    selectedId = readonly(str, "_selected", selectionChanged)  # noqa: N815
    conversation = readonly(QObject, "_conversation", selectionChanged)
    search = readonly(str, "_search", searchChanged)
    addressBusy = readonly(bool, "_address_busy", addressChanged)  # noqa: N815
    addressStage = readonly(str, "_address_stage", addressChanged)  # noqa: N815
    addressError = readonly(str, "_address_error", addressChanged)  # noqa: N815
    ready = readonly(bool, "_ready", readyChanged)

    def __init__(self, scope: Scope, snap: WorkspaceSnap, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._scope = scope
        identity = snap.identity
        self._short_id = identity.short_id
        self._fingerprint = identity.fingerprint
        self._bundle_bytes = identity.bundle_bytes
        self._identity_parts = [{"name": n, "size": s} for n, s in identity.parts]
        self._port = snap.network.port
        self._addresses = list(snap.network.addresses)
        self._discovery = snap.network.discovery
        self._settings = SettingsModel(scope, snap.settings)
        self._settings.setParent(self)
        self._prompts = Prompts(
            scope, accepting_contact=self._expect_new_contact, verify=self._verify
        )
        self._prompts.setParent(self)
        self._prompts.finished.connect(self._prompt_finished)
        self._inspector = Inspector(scope, preferred=self._preferred_session, parent=self)
        self._lab = Lab(scope, parent=self)
        self._strip: RowModel[ContactRow] = RowModel(ContactRow, lambda r: r.contact_id, self)
        self._contacts_model: RowModel[ContactRow] = RowModel(
            ContactRow, lambda r: r.contact_id, self
        )
        self._nearby_model: RowModel[NearbyRow] = RowModel(NearbyRow, lambda r: r.key, self)
        self._contacts: dict[str, ContactSnap] = {c.contact_id: c for c in snap.contacts}
        self._nearby: tuple[NearbySnap, ...] = snap.nearby
        self._activity: dict[str, float] = {c.contact_id: c.created for c in snap.contacts}
        self._unread: dict[str, int] = {}
        self._conversations: dict[str, Conversation] = {}
        self._strip_ids: list[str] = []
        self._strip_limit = STRIP_LIMIT
        self._contact_count = 0
        self._hidden_unread = 0
        self._total_unread = 0
        self._selected = ""
        self._conversation: Conversation | None = None
        self._search = ""
        self._address_busy = False
        self._address_stage = ""
        self._address_error = ""
        self._ready = False
        self._window_active = True
        self._select_new_contact_until = 0.0
        self._today = date.today()  # noqa: DTZ011  # the local calendar day
        self._formats = locale_formats(self._today)
        self._clock = QTimer(self)
        self._clock.setInterval(60_000)
        self._clock.timeout.connect(self._check_date)
        self._clock.start()
        scope.updates.connect(self.apply)
        for prompt in snap.prompts:
            self._prompts.opened(prompt)
        self._rebuild()
        if not scope.request(ops.recent_activity(), self._activity_loaded):
            self._finish_loading()

    @property
    def settings_model(self) -> SettingsModel:
        """The settings (Python side; QML reads ``settings``)."""
        return self._settings

    @property
    def prompts_model(self) -> Prompts:
        """The requests waiting for the user (Python side; QML reads ``prompts``)."""
        return self._prompts

    @property
    def lab_model(self) -> Lab:
        """The solo lab (Python side; QML reads ``lab``)."""
        return self._lab

    @property
    def inspector_model(self) -> Inspector:
        """The Inspector (Python side; QML reads ``inspector``)."""
        return self._inspector

    @property
    def conversation_model(self) -> Conversation | None:
        """The selected conversation (Python side; QML reads ``conversation``)."""
        return self._conversation

    # -- updates ---------------------------------------------------------------------------------

    def apply(self, updates: tuple[Update, ...]) -> None:  # noqa: C901, PLR0912  # one per update
        """Apply a batch of updates from the node, in order."""
        rebuild = False
        for update in updates:
            match update:
                case ContactChanged(contact=contact):
                    rebuild |= self._contact_changed(contact)
                case ContactRemoved(contact_id=contact_id):
                    self._contact_removed(contact_id)
                    rebuild = True
                case NearbyChanged(peers=peers):
                    self._nearby = peers
                    nearby_ids = {p.contact_id for p in peers if p.contact_id}
                    for contact_id, conversation in self._conversations.items():
                        conversation.set_nearby(nearby=contact_id in nearby_ids)
                    rebuild = True
                case MessageChanged():
                    rebuild |= self._message_changed(update)
                case PromptOpened(prompt=prompt):
                    self._prompts.opened(prompt)
                case PromptClosed(prompt_id=prompt_id, outcome=outcome):
                    self._prompts.closed(prompt_id, outcome)
                case MismatchOpened(mismatch=mismatch):
                    self._prompts.mismatch(mismatch)
                    conversation = self._conversations.get(mismatch.contact_id)
                    if conversation is not None:
                        conversation.mismatch_opened()
                case ConnectStage(contact_id=contact_id, stage=stage):
                    self._connect_stage(contact_id, stage)
                case SessionEnded(contact_id=contact_id, reason=reason, by_peer=by_peer):
                    conversation = self._conversations.get(contact_id)
                    if conversation is not None:
                        conversation.session_ended(reason, by_peer=by_peer)
                case ProfileRefused(contact_id=contact_id, offered=offered):
                    self._profile_refused(contact_id, offered, update.configured)
                case NoticePosted(text=text):
                    self.noticePosted.emit(text)
                case TraceAppended() | TraceOverflow() | SessionDescribed() | SessionRemoved():
                    pass  # the Inspector's own updates
        if rebuild:
            self._rebuild()

    def _contact_changed(self, contact: ContactSnap) -> bool:
        old = self._contacts.get(contact.contact_id)
        self._contacts[contact.contact_id] = contact
        if old is None:
            self._activity[contact.contact_id] = time.time()
            if time.monotonic() < self._select_new_contact_until:
                self._select_new_contact_until = 0.0
                self.select(contact.contact_id)
        elif contact.session is not None and old.session is None:
            self._activity[contact.contact_id] = time.time()
        conversation = self._conversations.get(contact.contact_id)
        if conversation is not None:
            conversation.set_contact(contact)
        self._inspector.refresh_contact(contact.contact_id, contact.name, contact.trust)
        return True

    def _contact_removed(self, contact_id: str) -> None:
        self._contacts.pop(contact_id, None)
        self._activity.pop(contact_id, None)
        self._unread.pop(contact_id, None)
        conversation = self._conversations.pop(contact_id, None)
        if self._selected == contact_id:
            remaining = sorted(self._activity, key=lambda c: -self._activity[c])
            self._select(remaining[0] if remaining else "")
        if conversation is not None:
            conversation.deleteLater()

    def _message_changed(self, update: MessageChanged) -> bool:
        contact_id = update.contact_id
        conversation = self._conversations.get(contact_id)
        if conversation is not None:
            conversation.apply(update)
        if not update.added:
            return False
        self._activity[contact_id] = max(self._activity.get(contact_id, 0.0), update.message.time)
        seen = contact_id == self._selected and self._window_active
        if update.message.direction == "in" and not seen:
            self._unread[contact_id] = self._unread.get(contact_id, 0) + 1
            contact = self._contacts.get(contact_id)
            if contact is not None:
                self.incomingMessage.emit(contact.name)
        return True

    def _connect_stage(self, contact_id: str, stage: str) -> None:
        if stage != "waiting_for_admission":
            return
        conversation = self._conversations.get(contact_id)
        if contact_id and conversation is not None and conversation.connecting:
            conversation.set_waiting()
        elif self._address_busy:
            self._address_stage = "waiting"
            self.addressChanged.emit()

    def _profile_refused(self, contact_id: str, offered: str, configured: str) -> None:
        """We refused the contact for its profile: its conversation offers the switch."""
        contact = self._contacts.get(contact_id)
        if contact is None:
            return
        self._conversation_for(contact_id).profile_refused(offered, configured)
        if contact_id != self._selected:
            self.noticePosted.emit(
                f"{isolate(contact.name)} could not connect: they use {offered}, "
                f"your setting for them is {configured}. Their conversation offers the switch."
            )

    # -- slots -----------------------------------------------------------------------------------

    @Slot(str)
    def select(self, contact_id: str) -> None:
        """Show the conversation with this contact."""
        if contact_id in self._contacts:
            self._select(contact_id)
            self._rebuild()

    @Slot(str)
    def setSearch(self, text: str) -> None:  # noqa: N802
        """Filter the contact chooser by name or short ID."""
        if text != self._search:
            self._search = text
            self.searchChanged.emit()
            self._rebuild()

    @Slot(int)
    def setStripLimit(self, limit: int) -> None:  # noqa: N802
        """How many contacts fit in the strip now (at most :data:`STRIP_LIMIT`)."""
        limit = max(1, min(limit, STRIP_LIMIT))
        if limit != self._strip_limit:
            self._strip_limit = limit
            self._rebuild()

    @Slot(bool)
    def setWindowActive(self, active: bool) -> None:  # noqa: FBT001, N802
        """The window gained or lost focus: unread counts depend on it."""
        self._window_active = active
        if active and self._unread.pop(self._selected, 0):
            self._rebuild()

    @Slot(str, int, str, str)
    def connectAddress(self, host: str, port: int, name: str, profile: str) -> None:  # noqa: N802
        """Connect to ``host:port`` (a first contact, or whoever answers there)."""
        self._address_connect(ops.connect_address(host, port, name, profile))

    @Slot(str)
    def connectNearby(self, key: str) -> None:  # noqa: N802
        """Connect to a peer announced on the LAN."""
        self._address_connect(ops.connect_nearby(key))

    @Slot()
    def clearAddressError(self) -> None:  # noqa: N802
        """Hide the last connection error."""
        if self._address_error:
            self._address_error = ""
            self.addressChanged.emit()

    @Slot()
    def refreshNetwork(self) -> None:  # noqa: N802
        """Look up our addresses again (they can change while the app runs)."""

        def done(reply: Reply) -> None:
            if isinstance(reply.value, NetworkSnap):
                self._port = reply.value.port
                self._addresses = list(reply.value.addresses)
                self._discovery = reply.value.discovery
                self.networkChanged.emit()

        self._scope.request(ops.network(), done)

    # -- internals -------------------------------------------------------------------------------

    def _address_connect(self, op: ops.Op) -> None:
        if self._address_busy:
            return

        def done(reply: Reply) -> None:
            self._address_busy = False
            self._address_stage = ""
            if reply.error is not None:
                self._address_error = reply.error.message[:1].upper() + reply.error.message[1:]
            elif isinstance(reply.value, str):
                self._address_error = ""
                self.select(reply.value)
                self.addressConnected.emit(reply.value)
            self.addressChanged.emit()

        if self._scope.request(op, done):
            self._address_busy = True
            self._address_stage = "connecting"
            self._address_error = ""
            self.addressChanged.emit()

    def _activity_loaded(self, reply: Reply) -> None:
        if isinstance(reply.value, ActivitySnap):
            for contact_id, when in reply.value.times:
                if contact_id in self._contacts:
                    self._activity[contact_id] = max(self._activity.get(contact_id, 0.0), when)
        self._finish_loading()

    def _finish_loading(self) -> None:
        if not self._selected and self._activity:
            self._select(max(self._activity, key=lambda c: (self._activity[c], c)))
        self._rebuild()
        self._ready = True
        self.readyChanged.emit()

    def _select(self, contact_id: str) -> None:
        if contact_id == self._selected and (not contact_id or self._conversation is not None):
            return
        self._selected = contact_id
        self._conversation = self._conversation_for(contact_id) if contact_id else None
        self._unread.pop(contact_id, None)
        self.selectionChanged.emit()

    def _conversation_for(self, contact_id: str) -> Conversation:
        conversation = self._conversations.get(contact_id)
        if conversation is None:
            nearby = any(p.contact_id == contact_id for p in self._nearby)
            conversation = Conversation(
                self._scope,
                self._contacts[contact_id],
                self._formats,
                changed=self._rebuild,
                mismatch_pending=self._prompts.pending_mismatch,
            )
            conversation.set_nearby(nearby=nearby)
            conversation.setParent(self)
            conversation.actionFailed.connect(self.noticePosted)
            self._conversations[contact_id] = conversation
        return conversation

    def _preferred_session(self) -> int:
        """The session the Inspector opens first: the selected contact's, if connected."""
        contact = self._contacts.get(self._selected)
        session = contact.session if contact is not None else None
        return session.session_id if session is not None else -1

    def _expect_new_contact(self) -> None:
        self._select_new_contact_until = time.monotonic() + 10.0

    def _verify(self, contact_id: str) -> None:
        self.select(contact_id)
        self.verifyRequested.emit(contact_id)

    def _prompt_finished(self, toast: str) -> None:
        if toast:
            self.noticePosted.emit(toast)

    def _check_date(self) -> None:
        today = date.today()  # noqa: DTZ011
        if today != self._today:
            self._today = today
            self._formats = locale_formats(today)
            for conversation in self._conversations.values():
                conversation.set_formats(self._formats)

    def _rebuild(self) -> None:
        nearby_ids = {p.contact_id for p in self._nearby if p.contact_id}

        def row(contact: ContactSnap) -> ContactRow:
            conversation = self._conversations.get(contact.contact_id)
            return contact_row(
                contact,
                connecting=conversation.connecting if conversation is not None else "",
                nearby=contact.contact_id in nearby_ids,
                unread=self._unread.get(contact.contact_id, 0),
            )

        self._strip_ids = strip_order(
            self._strip_ids, self._activity, self._selected, self._strip_limit
        )
        self._strip.sync([row(self._contacts[c]) for c in self._strip_ids])
        wanted = self._search.casefold().replace("-", "")
        chosen = [
            c
            for c in sorted(self._contacts.values(), key=lambda c: (c.name.casefold(), c.short_id))
            if not wanted
            or wanted in c.name.casefold()
            or wanted in c.short_id.casefold().replace("-", "")
        ]
        self._contacts_model.sync([row(c) for c in chosen])
        self._nearby_model.sync([nearby_row(p) for p in self._nearby if not p.contact_id])
        shown = set(self._strip_ids)
        count = len(self._contacts)
        hidden = sum(n for c, n in self._unread.items() if c not in shown)
        if (count, hidden) != (self._contact_count, self._hidden_unread):
            self._contact_count = count
            self._hidden_unread = hidden
            self.contactsChanged.emit()
        total = sum(self._unread.values())
        if total != self._total_unread:
            self._total_unread = total
            self.unreadChanged.emit()
