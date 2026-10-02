"""The node: one installation's vault, sessions, discovery and file transfers (DESIGN §12).

:class:`Node` is the API every front end drives: the headless CLI now, the desktop app's bridge in
M3. It lives on one asyncio event loop; the vault runs on a dedicated worker thread, so Argon2id
and disk writes never stall the network. Front ends call its coroutines and subscribe to its
:mod:`~qrp2p.services.events`.

Normal sessions build their provider from the real profiles only (``REAL_PROFILES``), so
``LAB-CLASSICAL`` and the lab's engines are unreachable from here.
"""

import asyncio
import contextlib
import functools
import itertools
import logging
import os
import time
from collections.abc import Awaitable, Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair, safety_number
from qrp2p.core.crypto.profiles import REAL_PROFILES, Profile
from qrp2p.core.crypto.provider import CryptoProvider, PlainProvider
from qrp2p.core.errors import AdmitReason, CloseReason
from qrp2p.core.events import Priority
from qrp2p.core.handshake import (
    ADMISSION_DEADLINE,
    AdmissionRequired,
    KeyMismatch,
    ProfileRejected,
    State,
)
from qrp2p.core.trace import StateChanged as MachineStateChanged
from qrp2p.core.wire import (
    Chat,
    FileAccept,
    FileCancel,
    FileChunk,
    FileDecline,
    FileDone,
    FileOffer,
    FileProgress,
    Inner,
    Receipt,
    profile_bitmask,
)
from qrp2p.services import admission
from qrp2p.services.admission import GlassBoxLimiter, PromptKind
from qrp2p.services.discovery import Discovery, NearbyPeer, instance_name
from qrp2p.services.events import (
    AdmissionPrompt,
    ConnectFailed,
    ConnectProgress,
    ContactsChanged,
    HistoryChanged,
    KeyMismatchDetected,
    NearbyChanged,
    NodeEvent,
    NodeState,
    Notice,
    PromptClosed,
    PromptOutcome,
    SessionEnded,
    SessionOpened,
    StateChanged,
)
from qrp2p.services.files import (
    FileTransfers,
    PeerMisbehavedError,
    Transfer,
    TransferDirection,
    remove_partial,
)
from qrp2p.services.keychain import KeychainUnavailableError, OsKeychain
from qrp2p.services.models import (
    ID_LEN,
    Contact,
    Direction,
    FileInfo,
    FileStatus,
    HistoryEntry,
    MessageKind,
    MessageStatus,
    Settings,
    TrustState,
)
from qrp2p.services.paths import default_downloads_dir
from qrp2p.services.session import Session, SessionEnd, SessionNotOpenError, SessionRole
from qrp2p.services.session_manager import SessionManager
from qrp2p.services.trace_bus import TraceBus, TraceRecord
from qrp2p.services.transport import ConnectFailed as TransportConnectFailed
from qrp2p.services.transport import Listener
from qrp2p.services.vault import DEFAULT_KDF, KdfPolicy, Keychain, Vault

AUTO_LOCK_CHECK: Final = 15.0
"""Seconds between auto-lock checks."""
RETENTION_CHECK: Final = 3600.0
"""Seconds between purges of expired history."""
CONNECT_WAIT: Final = 90.0
"""Upper bound for :meth:`Node.connect_contact` and friends to report an outcome: the handshake
deadline plus the initiator's wait for Admit (DESIGN §6.4)."""

_log = logging.getLogger(__name__)

type Subscriber = Callable[[NodeEvent], None]


class NodeError(Exception):
    """A request the node cannot carry out; the message is for the user."""


class NotConnectedError(NodeError):
    """There is no open session with the contact."""


def profile_by_name(name: str) -> Profile:
    """A real profile by its name, case-insensitively (``HYBRID-1``, ``PQ-CNSA-1``).

    Raises:
        NodeError: No real profile has that name.
    """
    for profile in REAL_PROFILES:
        if profile.name.casefold() == name.casefold():
            return profile
    msg = f"unknown profile (use {', '.join(p.name for p in REAL_PROFILES)})"
    raise NodeError(msg)


def profiles_in(mask: int) -> list[Profile]:
    """The real profiles in a ``ProfileUnsupported`` or mDNS ``pf`` bitmask (DESIGN §6.1)."""
    return [p for p in REAL_PROFILES if profile_bitmask([p]) & mask]


def profile_by_id(profile_id: int) -> Profile:
    """A real profile by wire ID; unknown IDs fall back to ``HYBRID-1``."""
    return next((p for p in REAL_PROFILES if p.id == profile_id), REAL_PROFILES[0])


@dataclass(slots=True)
class _Prompt:
    prompt_id: int
    session: Session
    kind: PromptKind
    peer: IdentityBundle
    contact_id: bytes | None
    glass_box_refused: bool
    deadline: float


@dataclass(slots=True)
class _Mismatch:
    mismatch_id: int
    contact_id: bytes
    actual: IdentityBundle


@dataclass(slots=True)
class _Outgoing:
    """What we know about a connection we opened."""

    target: str
    contact_id: bytes | None
    address: tuple[str, int]
    name_hint: str
    result: asyncio.Future[bytes]
    """The contact ID once open; an exception if it failed."""
    supported: int | None = None
    session: Session | None = None


@dataclass(slots=True)
class _Pending:
    contact_id: bytes
    entry: HistoryEntry


class Node:
    """One QRP2P installation.

    Args:
        data_dir: Where the vault lives.
        kdf: Argon2id policy for new vaults and password changes (tests use a cheap one).
        listen_host: Interface to listen on; ``None``: every interface, IPv4 and IPv6.
        port: Listening port; ``None`` uses the setting (default 47470, the next free one if busy).
        discovery: Announce and browse with mDNS.
        discovery_interfaces: Restrict mDNS to these interface addresses (tests).
        provider_factory: Crypto provider per session (tests record secrets with it).
        keychain: The OS keychain for "Remember on this device", created when first needed.
        clock: Monotonic clock. ``wall``: wall clock for history timestamps.
        random_bytes: Randomness for IDs and keys.
    """

    def __init__(  # noqa: PLR0913
        self,
        data_dir: Path,
        *,
        kdf: KdfPolicy = DEFAULT_KDF,
        listen_host: str | None = None,
        port: int | None = None,
        discovery: bool = True,
        discovery_interfaces: list[str] | None = None,
        provider_factory: Callable[[], CryptoProvider] | None = None,
        keychain: Callable[[], Keychain] = OsKeychain,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self._vault = Vault(data_dir, random_bytes=random_bytes, kdf=kdf)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="qrp2p-vault")
        self._listen_host = listen_host
        self._port_override = port
        self._discovery_enabled = discovery
        self._discovery_interfaces = discovery_interfaces
        self._provider_factory = provider_factory or (
            lambda: PlainProvider(random_bytes, REAL_PROFILES)
        )
        self._keychain_factory = keychain
        self._clock = clock
        self._wall = wall
        self._random = random_bytes
        self._subscribers: list[Subscriber] = []
        self._state = NodeState.CLOSED
        self.trace = TraceBus()
        self.trace.subscribe(self._on_trace)
        self._reset_unlocked_state()

    def _reset_unlocked_state(self) -> None:
        self._identity: IdentityKeyPair | None = None
        self._settings = Settings()
        self._contacts: dict[bytes, Contact] = {}
        self._manager: SessionManager | None = None
        self._listener: Listener | None = None
        self._discovery: Discovery | None = None
        self._transfers: FileTransfers | None = None
        self._session_contact: dict[int, bytes] = {}
        self._outgoing: dict[int, _Outgoing] = {}
        self._outbox: dict[tuple[int, bytes], _Pending] = {}
        self._prompts: dict[int, _Prompt] = {}
        self._mismatches: dict[int, _Mismatch] = {}
        self._transfer_status: dict[tuple[int, bytes], FileStatus] = {}
        self._bound: dict[int, asyncio.Future[bytes | None]] = {}
        """Per session: resolves to the contact ID once the session is bound to a contact."""
        self._limiter = GlassBoxLimiter()
        self._ids = itertools.count(1)
        self._timers: list[asyncio.Task[None]] = []
        self._background: set[asyncio.Task[None]] = set()
        self._last_activity = self._clock()
        self._port: int | None = None

    # -- plumbing -------------------------------------------------------------------------------

    async def _db[**P, T](self, fn: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
        """Run a vault call on the vault's thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, functools.partial(fn, *args, **kwargs))

    def subscribe(self, subscriber: Subscriber) -> Callable[[], None]:
        """Receive every future event on the event loop; returns an unsubscribe function."""
        self._subscribers.append(subscriber)

        def unsubscribe() -> None:
            if subscriber in self._subscribers:
                self._subscribers.remove(subscriber)

        return unsubscribe

    def _emit(self, event: NodeEvent) -> None:
        for subscriber in tuple(self._subscribers):
            try:
                subscriber(event)
            except Exception:  # noqa: BLE001  # a broken front end must not break the node
                _log.exception("an event subscriber failed")

    def _spawn(self, coroutine: Coroutine[object, object, None], name: str) -> None:
        task = asyncio.get_running_loop().create_task(coroutine, name=name)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        task.add_done_callback(_log_failure)

    def touch(self) -> None:
        """Note user activity (postpones auto-lock)."""
        self._last_activity = self._clock()

    def _set_state(self, state: NodeState) -> None:
        self._state = state
        self._emit(StateChanged(state))

    # -- state ----------------------------------------------------------------------------------

    @property
    def state(self) -> NodeState:
        """Where the node is in its life cycle."""
        return self._state

    @property
    def data_dir(self) -> Path:
        """The data directory."""
        return self._vault.directory

    def _require_unlocked(self) -> IdentityKeyPair:
        if self._state is not NodeState.UNLOCKED or self._identity is None:
            msg = "the vault is locked"
            raise NodeError(msg)
        return self._identity

    @property
    def identity(self) -> IdentityBundle:
        """Our identity bundle.

        Raises:
            NodeError: Locked.
        """
        return self._require_unlocked().bundle

    @property
    def settings(self) -> Settings:
        """The current settings (defaults while locked)."""
        return self._settings

    @property
    def port(self) -> int | None:
        """The port we listen on, while unlocked."""
        return self._port

    def now(self) -> float:
        """The node's monotonic clock: prompt deadlines are on it."""
        return self._clock()

    @property
    def discovery_active(self) -> bool:
        """MDNS announces us and browses for peers (unlocked, enabled and working)."""
        return self._discovery is not None and self._discovery.running

    # -- life cycle -----------------------------------------------------------------------------

    async def open(self) -> NodeState:
        """Take the data directory (single instance) and report whether a vault exists.

        Raises:
            VaultInUseError: Another process has the directory open.
        """
        await self._db(self._vault.acquire)
        self._set_state(NodeState.LOCKED if self._vault.exists else NodeState.NO_VAULT)
        return self._state

    async def create(self, password: str, *, display_name: str = "") -> None:
        """Create the vault and a new identity, then go online.

        Raises:
            VaultExistsError: A vault exists already.
            ValueError: The password is empty.
        """
        if self._state is NodeState.CLOSED:
            await self.open()
        settings = Settings(display_name=display_name)
        identity = await self._db(self._vault.create, password, settings)
        await self._unlocked(identity)

    async def unlock(self, password: str) -> None:
        """Unlock with the password (Argon2id runs on the vault thread), then go online.

        Raises:
            WrongPasswordError: The password is wrong.
            NoVaultError: No vault yet.
        """
        if self._state is NodeState.UNLOCKED:
            return
        if self._state is NodeState.CLOSED:
            await self.open()
        identity = await self._db(self._vault.unlock, password)
        await self._unlocked(identity)

    async def unlock_with_device(self) -> None:
        """Unlock with the device key from the OS keychain (opt-in).

        Raises:
            WrongPasswordError: Device unlock is not set up or the key does not match.
            KeychainUnavailableError: No OS keychain.
        """
        if self._state is NodeState.CLOSED:
            await self.open()
        keychain = self._keychain_factory()
        identity = await self._db(self._vault.unlock_with_device, keychain)
        await self._unlocked(identity)

    async def _unlocked(self, identity: IdentityKeyPair) -> None:
        self._reset_unlocked_state()
        self._identity = identity
        self._settings = await self._db(self._vault.settings)
        await self._db(self._vault.purge_session_only)
        await self._db(self._vault.purge_expired, self._wall())
        for final in await self._db(self._vault.fail_interrupted):
            await asyncio.to_thread(remove_partial, Path(final))
        self._contacts = {c.contact_id: c for c in await self._db(self._vault.contacts)}
        self._manager = SessionManager(
            identity=identity,
            hooks=_ManagerHooks(
                admission=self._on_admission,
                key_mismatch=self._on_key_mismatch,
                profile_rejected=self._on_profile_rejected,
                established=self._on_established,
                message=self._on_message,
                sent=self._on_sent,
                ended=self._on_ended,
            ),
            provider_factory=self._provider_factory,
            clock=self._clock,
            trace=self.trace,
        )
        self._transfers = FileTransfers(
            _TransferHooks(
                offered=lambda t: self._spawn(self._file_offered(t), "qrp2p-file-offered"),
                changed=lambda t: self._spawn(self._transfer_changed(t), "qrp2p-file-changed"),
            ),
            random_bytes=self._random,
            max_size=self._settings.max_file_size,
        )
        self._manager.start()
        self._listener = Listener(self._manager.handle_incoming)
        port = self._port_override if self._port_override is not None else self._settings.port
        self._port = await self._listener.start(self._listen_host, port)
        self._state = NodeState.UNLOCKED
        await self._start_discovery()
        self._timers = [
            asyncio.create_task(self._auto_lock_loop(), name="qrp2p-auto-lock"),
            asyncio.create_task(self._retention_loop(), name="qrp2p-retention"),
        ]
        _log.info("unlocked as %s, listening on port %d", identity.bundle.short_id, self._port)
        self._emit(StateChanged(NodeState.UNLOCKED))

    async def _start_discovery(self) -> None:
        if not self._discovery_enabled or self._identity is None or self._port is None:
            return
        bundle = self._identity.bundle
        self._discovery = Discovery(
            on_change=self._nearby_changed,
            own_id_hint=bundle.peer_id[:8],
            interfaces=self._discovery_interfaces,
        )
        name = self._settings.display_name if self._settings.announce_name else ""
        try:
            await self._discovery.start(
                instance=instance_name(name, bundle.short_id),
                port=self._port,
                peer_id=bundle.peer_id,
                profiles=profile_bitmask(REAL_PROFILES),
            )
        except OSError:
            _log.warning("mDNS is unavailable; connect by address instead")
            self._discovery = None
            self._emit(Notice("mDNS discovery is unavailable; connect by address instead."))

    def _nearby_changed(self) -> None:
        self._emit(NearbyChanged(tuple(self.nearby())))

    async def lock(self) -> None:
        """Lock (DESIGN §10.4).

        Closes every session (``locked``), stops listening and mDNS, deletes partial downloads,
        checkpoints the WAL and drops every key reference.
        """
        if self._state is not NodeState.UNLOCKED:
            return
        self._state = NodeState.LOCKED
        for task in self._timers:
            if task is not asyncio.current_task():
                task.cancel()
        if self._discovery is not None:
            await self._discovery.stop()
        if self._listener is not None:
            await self._listener.close()
        if self._manager is not None:
            await self._manager.stop(CloseReason.LOCKED)
        if self._transfers is not None:
            await self._transfers.close()
        others = self._background - {asyncio.current_task()}
        if others:  # let history updates of the closing sessions reach the vault
            _, pending = await asyncio.wait(others, timeout=2.0)
            for task in pending:
                task.cancel()
        await self._db(self._vault.lock)
        self.trace.clear()
        self._reset_unlocked_state()
        _log.info("locked")
        self._emit(StateChanged(NodeState.LOCKED))

    async def close(self) -> None:
        """Lock and release the data directory (on exit)."""
        await self.lock()
        await self._db(self._vault.close)
        self._executor.shutdown(wait=True)
        self._set_state(NodeState.CLOSED)

    async def _auto_lock_loop(self) -> None:
        while True:
            await asyncio.sleep(AUTO_LOCK_CHECK)
            self.check_auto_lock()

    def check_auto_lock(self) -> None:
        """Lock if the user has been idle for the configured time."""
        minutes = self._settings.auto_lock_minutes
        if minutes > 0 and self._clock() - self._last_activity >= minutes * 60:
            _log.info("auto-lock after %d idle minutes", minutes)
            self._spawn(self.lock(), "qrp2p-auto-lock-now")

    async def _retention_loop(self) -> None:
        while True:
            await asyncio.sleep(RETENTION_CHECK)
            await self._db(self._vault.purge_expired, self._wall())

    # -- password and device key ----------------------------------------------------------------

    async def change_password(self, old: str, new: str) -> None:
        """Re-key the vault under a new password (DESIGN §10.4).

        Raises:
            WrongPasswordError: ``old`` is wrong.
            PasswordChangeCleanupError: The new password is active but cleanup failed.
        """
        self._require_unlocked()
        self.touch()
        keychain = None
        if await self._db(lambda: self._vault.device_unlock_enabled):
            with contextlib.suppress(KeychainUnavailableError):  # then device unlock is dropped
                keychain = self._keychain_factory()
        try:
            await self._db(self._vault.change_password, old, new, keychain)
        finally:
            if not await self._db(lambda: self._vault.is_unlocked):
                # An uncertain rotation commit closes the vault. Keep networking and the
                # frontend lifecycle consistent with that fail-closed storage state.
                await self.lock()

    async def device_unlock_enabled(self) -> bool:
        """Whether "Remember on this device" is on."""
        self._require_unlocked()
        return await self._db(lambda: self._vault.device_unlock_enabled)

    async def device_unlock_available(self) -> bool:
        """Whether "Remember on this device" is set up; answerable while locked."""
        return await self._db(lambda: self._vault.device_unlock_configured)

    async def set_device_unlock(self, *, enabled: bool) -> None:
        """Turn "Remember on this device" on or off.

        Raises:
            KeychainUnavailableError: No acceptable OS keychain.
        """
        self._require_unlocked()
        self.touch()
        keychain = self._keychain_factory()
        if enabled:
            await self._db(self._vault.enable_device_unlock, keychain)
        else:
            await self._db(self._vault.disable_device_unlock, keychain)

    # -- settings -------------------------------------------------------------------------------

    async def update_settings(self, **changes: object) -> Settings:
        """Change settings, e.g. ``update_settings(display_name="Alice")``.

        Raises:
            TypeError: An unknown setting.
        """
        self._require_unlocked()
        self.touch()
        settings = replace(self._settings, **changes)
        await self._db(self._vault.save_settings, settings)
        self._settings = settings
        if self._transfers is not None:
            self._transfers.max_size = settings.max_file_size
        return settings

    def downloads_dir(self) -> Path:
        """Where accepted files go."""
        configured = self._settings.downloads_dir
        return Path(configured) if configured else default_downloads_dir()

    # -- contacts -------------------------------------------------------------------------------

    def contacts(self) -> list[Contact]:
        """Every contact, sorted by name."""
        self._require_unlocked()
        return sorted(self._contacts.values(), key=lambda c: (c.name.casefold(), c.short_id))

    def contact(self, contact_id: bytes) -> Contact:
        """A contact by ID.

        Contacts stay readable while a lock is closing the sessions, so front ends can name the
        peers of the last events.

        Raises:
            NodeError: No such contact (or locked).
        """
        contact = self._contacts.get(contact_id)
        if contact is None:
            msg = "no such contact"
            raise NodeError(msg)
        return contact

    def contact_for_peer(self, peer_id: bytes) -> Contact | None:
        """The contact pinned to ``peer_id``, if any."""
        return next((c for c in self._contacts.values() if c.peer_id == peer_id), None)

    def is_online(self, contact_id: bytes) -> bool:
        """Whether a session with the contact is open."""
        return self._live_session(contact_id) is not None

    def session_info(self, contact_id: bytes) -> Session | None:
        """The open session with a contact (read-only use: profile, glass-box, trace ID)."""
        return self._live_session(contact_id)

    def _live_session(self, contact_id: bytes) -> Session | None:
        contact = self._contacts.get(contact_id)
        if contact is None or self._manager is None:
            return None
        return self._manager.live(contact.peer_id)

    def safety_number(self, contact_id: bytes) -> tuple[str, ...]:
        """The 60-digit safety number with a contact, as 12 groups (DESIGN §5.2)."""
        own = self._require_unlocked().bundle.peer_id
        return safety_number(own, self.contact(contact_id).peer_id)

    async def _save_contact(self, contact: Contact) -> Contact:
        await self._db(self._vault.save_contact, contact)
        self._contacts[contact.contact_id] = contact
        self._emit(ContactsChanged(contact.contact_id))
        return contact

    async def _new_contact(self, bundle: IdentityBundle, name: str, profile: Profile) -> Contact:
        contact_id, conv_id = await self._db(self._vault.new_contact_ids)
        contact = Contact(
            contact_id=contact_id,
            conv_id=conv_id,
            bundle=bundle,
            name=name.strip() or bundle.short_id,
            profile_id=profile.id,
            retention=self._settings.default_retention,
            created=self._wall(),
        )
        return await self._save_contact(contact)

    async def update_contact(self, contact_id: bytes, **changes: object) -> Contact:
        """Change a contact's name, profile, retention or file auto-accept.

        Fields: ``name``, ``profile_id``, ``retention``, ``auto_accept_files``,
        ``auto_accept_limit``. Trust changes go through :meth:`set_trust`.
        """
        allowed = {"name", "profile_id", "retention", "auto_accept_files", "auto_accept_limit"}
        if not set(changes) <= allowed:
            msg = "that contact field cannot be changed here"
            raise NodeError(msg)
        self.touch()
        contact = replace(self.contact(contact_id), **changes)
        if contact.auto_accept_files and contact.trust is not TrustState.VERIFIED:
            msg = "file auto-accept needs a verified contact"
            raise NodeError(msg)
        return await self._save_contact(contact)

    async def set_trust(self, contact_id: bytes, trust: TrustState) -> Contact:
        """Mark verified (after comparing safety numbers), back to pinned, or blocked.

        Leaving *verified* turns file auto-accept off; blocking closes an open session.
        """
        self.touch()
        contact = self.contact(contact_id)
        changes: dict[str, object] = {"trust": trust}
        if trust is not TrustState.VERIFIED:
            changes["auto_accept_files"] = False
        contact = await self._save_contact(replace(contact, **changes))
        if trust is TrustState.BLOCKED:
            session = self._live_session(contact_id)
            if session is not None:
                session.close(CloseReason.NORMAL)
        return contact

    async def delete_contact(self, contact_id: bytes) -> None:
        """Delete a contact and its history (the database is vacuumed)."""
        self.touch()
        contact = self.contact(contact_id)
        session = self._live_session(contact_id)
        if session is not None:
            session.close(CloseReason.NORMAL)
        await self._db(self._vault.delete_contact, contact)
        del self._contacts[contact_id]
        self._emit(ContactsChanged(contact_id))

    async def delete_conversation(self, contact_id: bytes) -> None:
        """Delete a conversation's history and key (DESIGN §10.4)."""
        self.touch()
        contact = self.contact(contact_id)
        updated = await self._db(self._vault.delete_conversation, contact)
        self._contacts[contact_id] = updated
        self._emit(ContactsChanged(contact_id))

    async def history(self, contact_id: bytes, limit: int | None = None) -> list[HistoryEntry]:
        """A conversation, oldest first."""
        contact = self.contact(contact_id)
        return await self._db(self._vault.history, contact.conv_id, limit)

    async def _add_entry(self, contact_id: bytes, entry: HistoryEntry) -> None:
        contact = self._contacts.get(contact_id)
        if contact is None:
            return
        await self._db(self._vault.add_entry, contact.conv_id, entry)
        self._emit(HistoryChanged(contact_id, entry, added=True))

    async def _update_entry(self, contact_id: bytes, entry: HistoryEntry) -> None:
        contact = self._contacts.get(contact_id)
        if contact is None:
            return
        await self._db(self._vault.update_entry, contact.conv_id, entry)
        self._emit(HistoryChanged(contact_id, entry, added=False))

    # -- connecting -----------------------------------------------------------------------------

    def nearby(self) -> list[NearbyPeer]:
        """Peers announced on the LAN (hints)."""
        return self._discovery.peers() if self._discovery is not None else []

    def contact_for_nearby(self, peer: NearbyPeer) -> Contact | None:
        """The contact whose peer ID starts with the announced hint, if any (a hint only)."""
        return next(
            (c for c in self._contacts.values() if c.peer_id[: len(peer.id_hint)] == peer.id_hint),
            None,
        )

    async def connect_contact(self, contact_id: bytes, *, glass_box: bool = False) -> None:
        """Connect to a contact with its pinned bundle and configured profile.

        The last address that worked is tried first, then mDNS entries whose ID hint matches.
        Returns once the session is open.

        Raises:
            NodeError: No address is known, the contact is blocked, or the handshake failed.
        """
        self.touch()
        contact = self.contact(contact_id)
        if contact.trust is TrustState.BLOCKED:
            msg = "the contact is blocked"
            raise NodeError(msg)
        if self.is_online(contact_id):
            return
        addresses: list[tuple[str, int]] = [] if contact.address is None else [contact.address]
        for peer in self.nearby():
            if contact.peer_id.startswith(peer.id_hint):
                addresses += [
                    (a, peer.port) for a in peer.addresses if (a, peer.port) != contact.address
                ]
        if not addresses:
            msg = "no address known for this contact; connect by address first"
            raise NodeError(msg)
        await self._connect(
            addresses,
            profile=profile_by_id(contact.profile_id),
            contact=contact,
            glass_box=glass_box,
            name_hint=contact.name,
        )

    async def connect_address(
        self, host: str, port: int, *, profile: Profile | None = None, name: str = ""
    ) -> bytes:
        """Connect to ``host:port`` as a first contact (or to whichever contact answers).

        A new contact is named ``name``, or its short ID. Returns the contact ID once the session is open.

        Raises:
            NodeError: The connection or the handshake failed.
        """
        self.touch()
        chosen = profile or profile_by_id(self._settings.default_profile)
        return await self._connect(
            [(host, port)], profile=chosen, contact=None, glass_box=False, name_hint=name
        )

    async def connect_nearby(self, peer: NearbyPeer) -> bytes:
        """Connect to an announced peer: as its contact if the ID hint matches one."""
        contact = self.contact_for_nearby(peer)
        if contact is not None:
            await self.connect_contact(contact.contact_id)
            return contact.contact_id
        self.touch()
        label = peer.label.rsplit(" (", 1)[0]
        return await self._connect(
            [(address, peer.port) for address in peer.addresses],
            profile=profile_by_id(self._settings.default_profile),
            contact=None,
            glass_box=False,
            name_hint=label,
        )

    async def _connect(
        self,
        addresses: list[tuple[str, int]],
        *,
        profile: Profile,
        contact: Contact | None,
        glass_box: bool,
        name_hint: str,
    ) -> bytes:
        manager = self._manager
        if manager is None:
            msg = "the vault is locked"
            raise NodeError(msg)
        future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        for host, port in addresses:
            if contact is not None and self.is_online(contact.contact_id):
                return contact.contact_id  # the peer connected to us meanwhile
            target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            outgoing = _Outgoing(
                target, contact.contact_id if contact else None, (host, port), name_hint, future
            )

            def register(session: Session, outgoing: _Outgoing = outgoing) -> None:
                outgoing.session = session
                self._outgoing[session.id] = outgoing

            try:
                await manager.connect(
                    host,
                    port,
                    profile=profile,
                    pinned=contact.bundle if contact else None,
                    glass_box=glass_box,
                    on_created=register,
                )
            except TransportConnectFailed:
                continue
            try:
                async with asyncio.timeout(CONNECT_WAIT):
                    return await future
            except TimeoutError:
                if outgoing.session is not None:
                    outgoing.session.close(CloseReason.TIMEOUT)
                msg = "the handshake did not finish in time"
                raise NodeError(msg) from None
        if contact is not None and self.is_online(contact.contact_id):
            return contact.contact_id
        targets = ", ".join(f"{h}:{p}" for h, p in addresses)
        self._emit(ConnectFailed(targets, None, detail="unreachable"))
        msg = "could not reach the peer (is it running, and does its firewall allow the port?)"
        raise NodeError(msg)

    async def disconnect(self, contact_id: bytes) -> None:
        """Close the session with a contact (``normal``)."""
        self.touch()
        self._require_session(contact_id).close(CloseReason.NORMAL)

    async def rekey(self, contact_id: bytes) -> None:
        """Start a PQ rekey now (only the session's initiator can)."""
        self.touch()
        session = self._require_session(contact_id)
        if session.role is not SessionRole.INITIATOR:
            msg = "only the side that opened the session can start a rekey"
            raise NodeError(msg)
        session.start_rekey()

    def _require_session(self, contact_id: bytes) -> Session:
        session = self._live_session(contact_id)
        if session is None:
            msg = "not connected to this contact"
            raise NotConnectedError(msg)
        return session

    # -- admission ------------------------------------------------------------------------------

    def pending_prompts(self) -> list[AdmissionPrompt]:
        """Prompts that wait for an answer."""
        return [self._prompt_event(p) for p in self._prompts.values()]

    def _prompt_event(self, prompt: _Prompt) -> AdmissionPrompt:
        contact = self._contacts.get(prompt.contact_id) if prompt.contact_id else None
        profile = prompt.session.profile
        return AdmissionPrompt(
            prompt_id=prompt.prompt_id,
            kind=prompt.kind,
            short_id=prompt.peer.short_id,
            contact_id=prompt.contact_id,
            name_hint=contact.name if contact else "",
            profile=profile.name if profile else "",
            glass_box_refused=prompt.glass_box_refused,
            deadline=prompt.deadline,
        )

    async def answer_prompt(self, prompt_id: int, *, accept: bool, name: str = "") -> PromptOutcome:
        """Answer an admission prompt and report what actually happened.

        Contact request: ``accept`` pins the contact under ``name``. Glass-box request: ``accept``
        gives a glass-box session, declining a normal one. Either acceptance can still end as
        :attr:`~PromptOutcome.BUSY` if the live-session cap was reached while the prompt was
        open (DESIGN §6.4).

        Raises:
            NodeError: No such prompt, or it expired.
        """
        self.touch()
        prompt = self._prompts.pop(prompt_id, None)
        if prompt is None or not prompt.session.awaiting_admission:
            msg = "that request is no longer waiting"
            raise NodeError(msg)
        session = prompt.session
        peer_id = prompt.peer.peer_id
        if prompt.kind is PromptKind.CONTACT_REQUEST:
            if accept:
                profile = session.profile or profile_by_id(self._settings.default_profile)
                await self._new_contact(prompt.peer, name, profile)
                if not session.awaiting_admission:  # the initiator left while we saved
                    outcome = PromptOutcome.GONE
                elif session.accept(glass_box=False):
                    outcome = PromptOutcome.ACCEPTED
                else:
                    outcome = PromptOutcome.BUSY
            else:
                session.reject(AdmitReason.DECLINED)
                outcome = PromptOutcome.DECLINED
        elif accept:
            self._limiter.accepted(peer_id)
            admitted = session.accept(glass_box=True)
            outcome = PromptOutcome.GLASS_BOX if admitted else PromptOutcome.BUSY
        else:
            self._limiter.declined(peer_id, self._clock())
            admitted = session.accept(glass_box=False)
            outcome = PromptOutcome.NORMAL if admitted else PromptOutcome.BUSY
        self._emit(PromptClosed(prompt_id, outcome))
        return outcome

    async def resolve_mismatch(self, mismatch_id: int, *, repin: bool) -> None:
        """After a key mismatch: cancel, or re-pin the contact to the identity that answered.

        Re-pinning sets the contact to *pinned* (never verified), turns file auto-accept off and
        adds an "identity changed" marker to the history (DESIGN §5.3).
        """
        self.touch()
        mismatch = self._mismatches.pop(mismatch_id, None)
        if mismatch is None:
            msg = "no such key mismatch"
            raise NodeError(msg)
        if not repin:
            return
        other = self.contact_for_peer(mismatch.actual.peer_id)
        if other is not None:
            msg = f"that identity is already the contact {other.name!r}"
            raise NodeError(msg)
        contact = self.contact(mismatch.contact_id)
        old = contact.short_id
        await self._save_contact(
            replace(
                contact, bundle=mismatch.actual, trust=TrustState.PINNED, auto_accept_files=False
            )
        )
        entry = HistoryEntry(
            entry_id=await self._db(self._vault.new_entry_id),
            kind=MessageKind.IDENTITY_CHANGED,
            direction=Direction.LOCAL,
            time=self._wall(),
            text=f"{old} -> {mismatch.actual.short_id}",
        )
        await self._add_entry(contact.contact_id, entry)

    # -- chat -----------------------------------------------------------------------------------

    async def send_chat(self, contact_id: bytes, text: str) -> HistoryEntry:
        """Send a chat message; its status moves sending → sent → delivered.

        Raises:
            NotConnectedError: No open session.
            ValueError: The text is longer than 16,000 bytes of UTF-8.
        """
        self.touch()
        session = self._require_session(contact_id)
        message = Chat(id=self._random(ID_LEN), text=text)
        entry = HistoryEntry(
            entry_id=await self._db(self._vault.new_entry_id),
            kind=MessageKind.CHAT,
            direction=Direction.OUT,
            time=self._wall(),
            message_id=message.id,
            status=MessageStatus.SENDING,
            text=text,
            glass_box=session.glass_box,
        )
        await self._add_entry(contact_id, entry)
        self._outbox[(session.id, message.id)] = _Pending(contact_id, entry)
        try:
            session.send(message, Priority.CHAT)
        except SessionNotOpenError:
            del self._outbox[(session.id, message.id)]
            await self._update_entry(contact_id, replace(entry, status=MessageStatus.FAILED))
            msg = "not connected to this contact"
            raise NotConnectedError(msg) from None
        return entry

    # -- files ----------------------------------------------------------------------------------

    async def send_file(self, contact_id: bytes, path: Path) -> HistoryEntry:
        """Offer a file; it is sent once the peer accepts.

        Raises:
            NotConnectedError: No open session.
            OSError: The file cannot be read.
        """
        self.touch()
        session = self._require_session(contact_id)
        transfers = self._transfers
        assert transfers is not None  # noqa: S101  # exists while unlocked
        entry_id = await self._db(self._vault.new_entry_id)
        transfer = transfers.offer(session, path, entry_id)
        transfer.created = self._wall()
        entry = self._file_entry(transfer)
        self._transfer_status[transfer.key] = transfer.status
        await self._add_entry(contact_id, entry)
        return entry

    def transfers(self) -> list[Transfer]:
        """Transfers in progress or waiting."""
        return self._transfers.active() if self._transfers is not None else []

    async def accept_file(self, file_id: bytes, directory: Path | None = None) -> None:
        """Accept an offered file into ``directory`` (default: the downloads directory)."""
        self.touch()
        transfers = self._require_transfers()
        try:
            await transfers.accept(file_id, directory or self.downloads_dir())
        except KeyError:
            msg = "no such file offer"
            raise NodeError(msg) from None

    async def decline_file(self, file_id: bytes) -> None:
        """Decline an offered file."""
        self.touch()
        try:
            self._require_transfers().decline(file_id)
        except KeyError:
            msg = "no such file offer"
            raise NodeError(msg) from None

    async def cancel_file(self, file_id: bytes) -> None:
        """Cancel a transfer in either direction; a partial download is deleted."""
        self.touch()
        try:
            await self._require_transfers().cancel(file_id)
        except KeyError:
            msg = "no such transfer"
            raise NodeError(msg) from None

    def _require_transfers(self) -> FileTransfers:
        self._require_unlocked()
        assert self._transfers is not None  # noqa: S101
        return self._transfers

    def _file_entry(self, transfer: Transfer) -> HistoryEntry:
        return HistoryEntry(
            entry_id=transfer.entry_id,
            kind=MessageKind.FILE,
            direction=Direction.OUT
            if transfer.direction is TransferDirection.OUT
            else Direction.IN,
            time=transfer.created,
            file=FileInfo(
                file_id=transfer.file_id,
                name=transfer.name,
                size=transfer.size,
                media_type=transfer.media_type,
                status=transfer.status,
                sha256=transfer.sha256,
                path=str(transfer.path)
                if transfer.path is not None and transfer.direction is TransferDirection.IN
                else "",
                reason=transfer.reason.label if transfer.reason is not None else "",
            ),
            glass_box=transfer.session.glass_box,
        )

    def _transfer_contact(self, transfer: Transfer) -> bytes | None:
        """The contact a transfer belongs to, also after its session ended."""
        contact_id = self._session_contact.get(transfer.session.id)
        if contact_id is not None:
            return contact_id
        peer = transfer.session.peer
        contact = self.contact_for_peer(peer.peer_id) if peer is not None else None
        return contact.contact_id if contact is not None else None

    async def _transfer_changed(self, transfer: Transfer) -> None:
        contact_id = self._transfer_contact(transfer)
        if contact_id is None:
            return
        known = self._transfer_status.get(transfer.key)
        if known is None:  # refused before it was offered to the user (size or offer limit)
            transfer.entry_id = await self._db(self._vault.new_entry_id)
            transfer.created = self._wall()
            self._transfer_status[transfer.key] = transfer.status
            await self._add_entry(contact_id, self._file_entry(transfer))
            return
        entry = self._file_entry(transfer)
        if known is not transfer.status:
            self._transfer_status[transfer.key] = transfer.status
            await self._update_entry(contact_id, entry)
        else:
            self._emit(
                HistoryChanged(contact_id, entry, added=False, progress=transfer.transferred)
            )
        if transfer.finished:
            self._transfer_status.pop(transfer.key, None)

    async def _file_offered(self, transfer: Transfer) -> None:
        contact_id = self._transfer_contact(transfer)
        if contact_id is None:
            return
        transfer.entry_id = await self._db(self._vault.new_entry_id)
        transfer.created = self._wall()
        self._transfer_status[transfer.key] = transfer.status
        await self._add_entry(contact_id, self._file_entry(transfer))
        contact = self._contacts.get(contact_id)
        if (
            contact is not None
            and contact.trust is TrustState.VERIFIED
            and contact.auto_accept_files
            and transfer.size <= contact.auto_accept_limit
        ):
            with contextlib.suppress(KeyError, SessionNotOpenError):
                await self._require_transfers().accept(transfer.file_id, self.downloads_dir())

    # -- hooks from the session manager ---------------------------------------------------------

    def _on_admission(self, session: Session, request: AdmissionRequired) -> None:
        peer_id = request.peer.peer_id
        contact = self.contact_for_peer(peer_id)
        decision = admission.decide(
            contact,
            profile_id=request.profile.id,
            gb_request=request.gb_request,
            may_prompt_glass_box=self._limiter.allows(peer_id, self._clock()),
        )
        match decision:
            case admission.Accept(glass_box=glass_box):
                session.accept(glass_box=glass_box)
            case admission.Reject(reason=reason):
                _log.info("rejected %s: %s", request.peer.short_id, reason.label)
                session.reject(reason)
            case admission.Ask(kind=kind, glass_box_refused=refused):
                if kind is PromptKind.GLASS_BOX:
                    self._limiter.prompted(peer_id, self._clock())
                prompt = _Prompt(
                    prompt_id=next(self._ids),
                    session=session,
                    kind=kind,
                    peer=request.peer,
                    contact_id=contact.contact_id if contact else None,
                    glass_box_refused=refused,
                    deadline=self._clock() + ADMISSION_DEADLINE,
                )
                self._prompts[prompt.prompt_id] = prompt
                self._emit(self._prompt_event(prompt))

    def _on_key_mismatch(self, session: Session, event: KeyMismatch) -> None:
        outgoing = self._outgoing.get(session.id)
        if outgoing is None or outgoing.contact_id is None:
            return
        mismatch = _Mismatch(next(self._ids), outgoing.contact_id, event.actual)
        self._mismatches[mismatch.mismatch_id] = mismatch
        self._emit(
            KeyMismatchDetected(
                mismatch.mismatch_id,
                outgoing.contact_id,
                event.expected.short_id,
                event.actual.short_id,
                event.expected.peer_id,
                event.actual.peer_id,
            )
        )

    def _on_trace(self, record: TraceRecord) -> None:
        """Tell front ends when an outgoing handshake waits for the peer's user (DESIGN §7.6)."""
        event = record.event
        if not isinstance(event, MachineStateChanged) or event.state != State.WAIT_ADMIT:
            return
        outgoing = self._outgoing.get(record.session_id)
        if outgoing is not None:
            self._emit(
                ConnectProgress(outgoing.target, outgoing.contact_id, "waiting_for_admission")
            )

    def _on_profile_rejected(self, session: Session, event: ProfileRejected) -> None:
        outgoing = self._outgoing.get(session.id)
        if outgoing is not None:
            outgoing.supported = event.supported

    def _on_established(self, session: Session, replaced: Session | None) -> None:
        self._bound[session.id] = asyncio.get_running_loop().create_future()
        self._spawn(self._established(session, replaced), f"qrp2p-open-{session.id}")

    async def _established(self, session: Session, replaced: Session | None) -> None:
        """Bind the session to its contact; messages wait for this (see :meth:`_contact_of`)."""
        bound = self._bound[session.id]
        contact_id: bytes | None = None
        try:
            contact_id = await self._bind(session, replaced)
        finally:
            if not bound.done():
                bound.set_result(contact_id)

    async def _contact_of(self, session: Session) -> bytes | None:
        bound = self._bound.get(session.id)
        return await asyncio.shield(bound) if bound is not None else None

    async def _bind(self, session: Session, replaced: Session | None) -> bytes | None:
        peer = session.peer
        assert peer is not None  # noqa: S101
        outgoing = self._outgoing.pop(session.id, None)
        contact = self.contact_for_peer(peer.peer_id)
        if contact is None and outgoing is not None:  # a first contact we chose to connect to
            profile = session.profile or profile_by_id(self._settings.default_profile)
            contact = await self._new_contact(peer, outgoing.name_hint, profile)
        if contact is None or contact.trust is TrustState.BLOCKED:
            session.close(CloseReason.NORMAL)
            if outgoing is not None and not outgoing.result.done():
                outgoing.result.set_exception(NodeError("the peer is blocked"))
            return None
        if outgoing is not None and contact.address != outgoing.address:
            contact = await self._save_contact(replace(contact, address=outgoing.address))
        self._session_contact[session.id] = contact.contact_id
        profile = session.profile
        self._emit(
            SessionOpened(
                contact.contact_id,
                profile.name if profile else "",
                session.glass_box,
                initiator=session.role is SessionRole.INITIATOR,
                replaced=replaced is not None,
            )
        )
        if outgoing is not None and not outgoing.result.done():
            outgoing.result.set_result(contact.contact_id)
        return contact.contact_id

    async def _on_message(self, session: Session, message: Inner) -> None:
        contact_id = await self._contact_of(session)
        if contact_id is None:  # the session was refused a contact and is closing
            return
        match message:
            case Chat():
                entry = HistoryEntry(
                    entry_id=await self._db(self._vault.new_entry_id),
                    kind=MessageKind.CHAT,
                    direction=Direction.IN,
                    time=self._wall(),
                    message_id=message.id,
                    status=MessageStatus.RECEIVED,
                    text=message.text,
                    glass_box=session.glass_box,
                )
                await self._add_entry(contact_id, entry)
                with contextlib.suppress(SessionNotOpenError):
                    session.send(Receipt(id=message.id), Priority.CHAT)
            case Receipt():
                pending = self._outbox.pop((session.id, message.id), None)
                if pending is not None:
                    delivered = replace(pending.entry, status=MessageStatus.DELIVERED)
                    await self._update_entry(pending.contact_id, delivered)
            case (
                FileOffer()
                | FileAccept()
                | FileDecline()
                | FileChunk()
                | FileProgress()
                | FileDone()
                | FileCancel()
            ):
                try:
                    await self._require_transfers().handle(session, message)
                except PeerMisbehavedError as error:
                    session.close(error.reason)
            case _:
                session.close(CloseReason.UNEXPECTED_MESSAGE)

    def _on_sent(self, session: Session, message: Inner) -> None:
        if not isinstance(message, Chat):
            return
        pending = self._outbox.get((session.id, message.id))
        if pending is not None and pending.entry.status is MessageStatus.SENDING:
            pending.entry = replace(pending.entry, status=MessageStatus.SENT)
            self._spawn(self._update_entry(pending.contact_id, pending.entry), "qrp2p-sent")

    def _on_ended(self, session: Session, end: SessionEnd, *, superseded: bool) -> None:
        self._spawn(self._ended(session, end, superseded=superseded), f"qrp2p-end-{session.id}")

    async def _ended(self, session: Session, end: SessionEnd, *, superseded: bool) -> None:
        await self._contact_of(session)  # let the binding finish first
        self._bound.pop(session.id, None)
        for prompt_id, prompt in list(self._prompts.items()):
            if prompt.session is session:
                del self._prompts[prompt_id]
                outcome = PromptOutcome.EXPIRED if end.reason else PromptOutcome.WITHDRAWN
                self._emit(PromptClosed(prompt_id, outcome))
        if self._transfers is not None:
            await self._transfers.session_ended(session)
        await self._fail_unsent(session)
        outgoing = self._outgoing.pop(session.id, None)
        contact_id = self._session_contact.pop(session.id, None)
        still_live = contact_id is not None and self._live_session(contact_id) is not None
        if contact_id is not None and not still_live:  # a replaced session is no disconnect
            self._emit(SessionEnded(contact_id, end.reason, end.by_peer))
        elif outgoing is not None and not superseded:
            lost = "connection lost" if end.reason is None and end.admit_reason is None else ""
            self._emit(
                ConnectFailed(
                    outgoing.target, end.reason, end.admit_reason, outgoing.supported, detail=lost
                )
            )
        if outgoing is not None and not outgoing.result.done():
            peer = session.peer or session.expected_peer
            winner = self.contact_for_peer(peer.peer_id) if superseded and peer else None
            if winner is not None:  # the other session with this peer carries on
                outgoing.result.set_result(winner.contact_id)
            else:
                outgoing.result.set_exception(NodeError(_describe_failure(end, outgoing)))

    async def _fail_unsent(self, session: Session) -> None:
        """Chats of an ended session that never reached TCP are marked failed."""
        for key, pending in list(self._outbox.items()):
            if key[0] != session.id:
                continue
            del self._outbox[key]
            if pending.entry.status is MessageStatus.SENDING:
                failed = replace(pending.entry, status=MessageStatus.FAILED)
                await self._update_entry(pending.contact_id, failed)


def _describe_failure(end: SessionEnd, outgoing: _Outgoing) -> str:
    if end.admit_reason is not None:
        return f"the peer rejected the session: {end.admit_reason.label}"
    if end.reason is CloseReason.POLICY and outgoing.supported is not None:
        names = [p.name for p in profiles_in(outgoing.supported)]
        return f"the peer does not serve this profile (it offers: {', '.join(names) or 'none'})"
    if end.reason is None:
        return "the connection dropped during the handshake"
    return f"the handshake failed: {end.reason.label}"


def _log_failure(task: asyncio.Task[None]) -> None:
    if not task.cancelled() and task.exception() is not None:
        _log.error("background task %s failed", task.get_name(), exc_info=task.exception())


@dataclass(frozen=True, slots=True)
class _ManagerHooks:
    """The node's :class:`~qrp2p.services.session_manager.ManagerHooks`."""

    admission: Callable[[Session, AdmissionRequired], None]
    key_mismatch: Callable[[Session, KeyMismatch], None]
    profile_rejected: Callable[[Session, ProfileRejected], None]
    established: Callable[[Session, Session | None], None]
    message: Callable[[Session, Inner], Awaitable[None]]
    sent: Callable[[Session, Inner], None]
    ended: Callable[..., None]


@dataclass(frozen=True, slots=True)
class _TransferHooks:
    """The node's :class:`~qrp2p.services.files.TransferHooks`."""

    offered: Callable[[Transfer], None]
    changed: Callable[[Transfer], None]
