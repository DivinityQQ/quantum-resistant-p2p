"""The services thread: an asyncio loop that owns the node (DESIGN §12, UI_DESIGN §11.2).

Only this module and :mod:`qrp2p.ui.ops` touch the :class:`~qrp2p.services.node.Node`, and only on
the services thread. The Qt side never holds the node or any object of it: it receives
:mod:`~qrp2p.ui.snapshots` deliveries through ``post`` and submits requests (operations that run
here). This module imports no Qt, so it is tested with plain asyncio.

**Generations.** Every delivery carries the lifecycle generation it belongs to. The generation
increases at every node state change (vault created, unlocked, locked, closed), at the moment the
services thread reports that change, so a delivery's generation names the unlocked period its data
belongs to. The Qt side accepts data only of the current unlocked generation, and a request issued
in one generation is refused if it would run in another: a prompt ID from before a lock means
nothing after it, because the node numbers prompts afresh at every unlock.

**Ordering.** Deliveries are posted in the order things happened. Updates are batched, at most 30
batches a second (DESIGN §12); a lifecycle change or a reply first flushes the pending batch, so
the Qt side never sees a reply before the events that preceded it. Consecutive progress reports of
one file transfer are coalesced: only the latest counts.
"""

import asyncio
import contextlib
import inspect
import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final

from qrp2p.lab.recording import RecordingError
from qrp2p.lab.solo import LabError
from qrp2p.services.discovery import local_addresses
from qrp2p.services.events import (
    AdmissionPrompt,
    ConnectFailed,
    ConnectProgress,
    ContactsChanged,
    HistoryChanged,
    KeyMismatchDetected,
    NodeEvent,
    NodeState,
    Notice,
    SessionEnded,
    SessionOpened,
    StateChanged,
)
from qrp2p.services.events import NearbyChanged as NodeNearbyChanged
from qrp2p.services.events import ProfileRefused as NodeProfileRefused
from qrp2p.services.events import PromptClosed as NodePromptClosed
from qrp2p.services.keychain import KeychainUnavailableError
from qrp2p.services.node import Node, NodeError, NotConnectedError
from qrp2p.services.vault import (
    PasswordChangeCleanupError,
    VaultError,
    VaultInUseError,
    WrongPasswordError,
)
from qrp2p.ui.labhost import LabHost
from qrp2p.ui.snapshots import (
    Batch,
    ConnectStage,
    ContactChanged,
    ContactRemoved,
    Delivery,
    ErrorInfo,
    Lifecycle,
    MessageChanged,
    MismatchOpened,
    NearbyChanged,
    NetworkSnap,
    NoticePosted,
    ProfileRefused,
    PromptClosed,
    PromptOpened,
    Reply,
    Update,
    WorkspaceSnap,
    contact_snap,
    identity_snap,
    message_snap,
    mismatch_snap,
    nearby_snap,
    prompt_snap,
    settings_snap,
)
from qrp2p.ui.snapshots import SessionEnded as SessionEndedUpdate
from qrp2p.ui.tap import TraceTap
from qrp2p.ui.text import display_text

BATCH_INTERVAL: Final = 1 / 30
"""Seconds between update batches at most (DESIGN §12: at most 30 a second)."""
STOP_TIMEOUT: Final = 20.0
"""Seconds :meth:`ServiceHost.stop` waits for the node to lock and close."""
IN_USE: Final = "in_use"
"""Lifecycle state: another process has the data directory open."""
FAILED: Final = "failed"
"""Lifecycle state: the node could not start."""
STALE: Final = ErrorInfo("stale", "That request belongs to an earlier session of the app.")
CLOSED: Final = ErrorInfo("closed", "The app is shutting down.")

_log = logging.getLogger(__name__)

type NodeOp = Callable[[Node], Awaitable[object]]
"""A request: runs on the services thread with the node; returns a snapshot or a primitive."""


@dataclass(frozen=True, slots=True)
class TapOp:
    """A request to an Inspector's :class:`~qrp2p.ui.tap.TraceTap` (services thread)."""

    run: Callable[[TraceTap], object]
    source: str = "node"
    """Which tap: the node's (``node``) or the solo lab's (``lab``)."""


@dataclass(frozen=True, slots=True)
class LabOp:
    """A request to the solo lab (services thread): returns a snapshot of the lab."""

    run: Callable[[LabHost], object]


type Op = NodeOp | TapOp | LabOp
type Post = Callable[[Delivery], None]


def network_snap(node: Node) -> NetworkSnap:
    """Where we listen and whether discovery works."""
    return NetworkSnap(
        port=node.port or 0,
        addresses=tuple(display_text(a) for a in local_addresses()),
        discovery=node.discovery_active,
    )


_NAMED: Final[tuple[tuple[type[Exception], str], ...]] = (
    (NotConnectedError, "not_connected"),
    (NodeError, "node"),
    (LabError, "lab"),
    (RecordingError, "recording"),
    (VaultError, "vault"),
    (ValueError, "value"),
)
"""Failures whose message is written for the user (and holds no secret), most specific first."""


def error_info(error: Exception) -> ErrorInfo:  # noqa: PLR0911  # one outcome per kind
    """What a failed request tells the user. Exceptions never cross to the Qt thread."""
    match error:
        case WrongPasswordError():
            return ErrorInfo("wrong_password", "Wrong password.")
        case PasswordChangeCleanupError():
            return ErrorInfo(
                "cleanup",
                "Password changed; vault cleanup failed. The new password is active.",
            )
        case VaultInUseError():
            return ErrorInfo(IN_USE, "Another QRP2P window is using this data folder.")
        case KeychainUnavailableError():
            return ErrorInfo("keychain", str(error) or "No OS keychain is available.")
        case OSError():
            return ErrorInfo("os", str(error.strerror or error))
        case _:
            pass
    for kind, code in _NAMED:
        if isinstance(error, kind):
            return ErrorInfo(code, str(error))
    _log.error("a request failed", exc_info=error)
    return ErrorInfo("internal", "Something went wrong; details are in app.log.")


class ServiceHost:
    """Runs the node on its own thread and event loop; talks to the Qt side by values only.

    Args:
        make_node: Builds the node (on the services thread).
        post: Receives every delivery, on the services thread; it must be thread-safe (the bridge
            passes a queued Qt signal).
        batch_interval: Seconds between update batches at most.
    """

    def __init__(
        self,
        make_node: Callable[[], Node],
        post: Post,
        *,
        batch_interval: float = BATCH_INTERVAL,
    ) -> None:
        self._make_node = make_node
        self._post = post
        self._interval = batch_interval
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        # Everything below belongs to the services thread.
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stopping: asyncio.Event | None = None
        self._node: Node | None = None
        self._gen = 0
        self._outbox: list[Update] = []
        self._progress_at: dict[tuple[str, str], int] = {}
        self._flush_handle: asyncio.TimerHandle | None = None
        self._requests: set[asyncio.Task[None]] = set()
        self._tap: TraceTap | None = None
        self._lab: LabHost | None = None

    # -- Qt thread -------------------------------------------------------------------------------

    def start(self) -> None:
        """Start the services thread; the node opens there and reports its state."""
        thread = threading.Thread(target=self._run, name="qrp2p-services", daemon=True)
        self._thread = thread
        thread.start()
        self._ready.wait()

    def submit(self, gen: int, request_id: int, op: Op, *, scoped: bool) -> None:
        """Run ``op`` on the services thread; its :class:`Reply` comes back through ``post``.

        A ``scoped`` request runs only if ``gen`` is still the current generation.
        """
        loop = self._loop
        try:
            if loop is None:
                raise RuntimeError  # noqa: TRY301  # same outcome as a closed loop
            loop.call_soon_threadsafe(self._start_request, gen, request_id, op, scoped)
        except RuntimeError:  # not started, or already stopped
            self._post(Reply(gen, request_id, error=CLOSED))

    def stop(self, timeout: float = STOP_TIMEOUT) -> bool:
        """Lock and close the node, then end the thread; ``False`` if it did not end in time."""
        loop, stopping, thread = self._loop, self._stopping, self._thread
        if loop is not None and stopping is not None:
            with contextlib.suppress(RuntimeError):  # the loop has ended already
                loop.call_soon_threadsafe(stopping.set)
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    # -- services thread -------------------------------------------------------------------------

    def _run(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stopping = asyncio.Event()
        self._ready.set()
        try:
            node = self._make_node()
        except Exception as error:  # noqa: BLE001  # reported to the user, not raised
            _log.exception("the node could not be created")
            self._lifecycle(FAILED, error=error_info(error).message)
            await self._stopping.wait()
            return
        self._node = node
        node.subscribe(self._on_event)
        self._tap = TraceTap.of_node(node, wake=self._schedule_flush)
        self._lab = LabHost(wake=self._schedule_flush, node=node)
        try:
            await node.open()
        except VaultInUseError:
            self._lifecycle(IN_USE)
        except Exception as error:  # noqa: BLE001
            _log.exception("the node could not open")
            self._lifecycle(FAILED, error=error_info(error).message)
        await self._stopping.wait()
        for task in tuple(self._requests):
            task.cancel()
        await asyncio.gather(*self._requests, return_exceptions=True)
        try:
            await node.close()
        except Exception:  # noqa: BLE001  # exiting anyway; the OS releases the lock
            _log.exception("the node did not close cleanly")
        self._flush()

    def _start_request(self, gen: int, request_id: int, op: Op, scoped: bool) -> None:  # noqa: FBT001
        if self._stopping is not None and self._stopping.is_set():
            self._post(Reply(gen, request_id, error=CLOSED))
            return
        task = asyncio.get_running_loop().create_task(
            self._execute(gen, request_id, op, scoped=scoped), name=f"qrp2p-request-{request_id}"
        )
        self._requests.add(task)
        task.add_done_callback(self._requests.discard)

    async def _execute(self, gen: int, request_id: int, op: Op, *, scoped: bool) -> None:
        node = self._node
        if node is None:
            self._reply(Reply(gen, request_id, error=CLOSED))
            return
        if scoped and gen != self._gen:
            self._reply(Reply(gen, request_id, error=STALE))
            return
        try:
            if isinstance(op, TapOp):
                value = op.run(self._tap_of(op.source))
            elif isinstance(op, LabOp):
                assert self._lab is not None  # noqa: S101  # created with the node
                value = op.run(self._lab)
                if inspect.isawaitable(value):  # recordings go through the vault's thread
                    value = await value
            else:
                value = await op(node)
        except Exception as error:  # noqa: BLE001  # every failure becomes a reply
            self._reply(Reply(gen, request_id, error=error_info(error)))
            return
        self._reply(Reply(gen, request_id, value=value))

    def _tap_of(self, source: str) -> TraceTap:
        tap = self._lab.tap if source == "lab" and self._lab is not None else self._tap
        assert tap is not None  # noqa: S101  # created with the node
        return tap

    def _reply(self, reply: Reply) -> None:
        self._flush()
        self._post(reply)

    # -- node events -----------------------------------------------------------------------------

    def _on_event(self, event: NodeEvent) -> None:
        if isinstance(event, StateChanged):
            self._lifecycle(event.state.value)
            return
        for update in self._convert(event):
            self._queue(update)

    def _lifecycle(self, state: str, *, error: str = "") -> None:
        self._flush()
        if self._tap is not None:
            self._tap.close()  # a lock clears the bus; a new period inspects afresh
        if self._lab is not None:
            self._lab.close()  # the lab's run and values belong to the unlocked period
        self._gen += 1
        workspace = self._workspace() if state == NodeState.UNLOCKED else None
        self._post(Lifecycle(self._gen, state, workspace, error))

    def _workspace(self) -> WorkspaceSnap:
        node = self._node
        assert node is not None  # noqa: S101  # only called for the node's own events
        now = node.now()
        return WorkspaceSnap(
            identity=identity_snap(node),
            network=network_snap(node),
            settings=settings_snap(node),
            contacts=tuple(contact_snap(node, c) for c in node.contacts()),
            nearby=tuple(nearby_snap(node, p) for p in node.nearby()),
            prompts=tuple(prompt_snap(p, now) for p in node.pending_prompts()),
        )

    def _convert(self, event: NodeEvent) -> list[Update]:  # noqa: C901, PLR0911  # one per event
        node = self._node
        assert node is not None  # noqa: S101
        match event:
            case ContactsChanged(contact_id=contact_id) | SessionOpened(contact_id=contact_id):
                return [self._contact_update(node, contact_id)]
            case SessionEnded(contact_id=contact_id, reason=reason, by_peer=by_peer):
                label = reason.label if reason is not None else ""
                ended = SessionEndedUpdate(contact_id.hex(), label, by_peer)
                return [self._contact_update(node, contact_id), ended]
            case NodeNearbyChanged(peers=peers):
                return [NearbyChanged(tuple(nearby_snap(node, p) for p in peers))]
            case HistoryChanged(contact_id=contact_id, entry=entry, added=added):
                message = message_snap(entry, event.progress)
                return [MessageChanged(contact_id.hex(), message, added)]
            case AdmissionPrompt():
                return [PromptOpened(prompt_snap(event, node.now()))]
            case NodePromptClosed(prompt_id=prompt_id, outcome=outcome):
                return [PromptClosed(prompt_id, outcome.value)]
            case KeyMismatchDetected():
                return [MismatchOpened(mismatch_snap(node, event))]
            case ConnectProgress(contact_id=contact_id, target=target, stage=stage):
                hex_id = contact_id.hex() if contact_id is not None else ""
                return [ConnectStage(hex_id, display_text(target), stage)]
            case NodeProfileRefused(contact_id=contact_id, offered=offered, configured=configured):
                return [ProfileRefused(contact_id.hex(), offered, configured)]
            case Notice(text=text):
                return [NoticePosted(text)]
            case ConnectFailed() | StateChanged():
                return []  # failures reach the requester as its reply

    @staticmethod
    def _contact_update(node: Node, contact_id: bytes) -> Update:
        try:
            contact = node.contact(contact_id)
        except NodeError:
            return ContactRemoved(contact_id.hex())
        return ContactChanged(contact_snap(node, contact))

    def _queue(self, update: Update) -> None:
        if isinstance(update, MessageChanged):
            key = (update.contact_id, update.message.entry_id)
            file = update.message.file
            if not update.added and file is not None and file.transferred is not None:
                at = self._progress_at.get(key)
                if at is not None:  # a newer count of the same transfer replaces the older
                    self._outbox[at] = update
                    return
                self._progress_at[key] = len(self._outbox)
            else:
                self._progress_at.pop(key, None)
        self._outbox.append(update)
        self._schedule_flush()

    def _schedule_flush(self) -> None:
        if self._flush_handle is None:
            loop = asyncio.get_running_loop()
            self._flush_handle = loop.call_later(self._interval, self._flush)

    def _flush(self) -> None:
        if self._flush_handle is not None:
            self._flush_handle.cancel()
            self._flush_handle = None
        if self._tap is not None:
            self._outbox.extend(self._tap.drain())
        if self._lab is not None:
            self._outbox.extend(self._lab.tap.drain())
        if not self._outbox:
            return
        batch = Batch(self._gen, tuple(self._outbox))
        self._outbox.clear()
        self._progress_at.clear()
        self._post(batch)
