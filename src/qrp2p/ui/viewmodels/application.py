"""The application: which screen shows, unlock and lock, appearance (UI_DESIGN §4.2, §6.1).

``phase`` decides the screen:

=============  =================================================================
``starting``   the services thread is opening the data directory
``noVault``    first run: create the vault
``locked``     unlock
``opening``    unlocked; the workspace is loading its first data
``unlocked``   the messenger
``locking``    the user locked; the messenger is already gone
``inUse``      another process has this data directory
``failed``     the node could not start (``error`` says why)
``closed``     the app is quitting
=============  =================================================================

Locking drops the workspace at once, with every model, draft and prompt in it; the bridge has
already stopped accepting data, so nothing queued can bring any of it back.
"""

import time
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from typing import Final

from PySide6.QtCore import QObject, Signal, Slot

from qrp2p.ui import ops
from qrp2p.ui.bridge import Bridge
from qrp2p.ui.host import FAILED, IN_USE
from qrp2p.ui.snapshots import Lifecycle, Reply
from qrp2p.ui.viewmodels.qt import ViewModel, constant, readonly
from qrp2p.ui.viewmodels.workspace import Workspace

MIN_PASSWORD: Final = 8
TOUCH_INTERVAL: Final = 15.0
"""Seconds between activity reports to the node (auto-lock needs no finer grain)."""
INTERRUPTED_CHANGE: Final = (
    "QRP2P could not confirm the password change and locked itself. Unlock with your new "
    "password; if it is not accepted, the change did not happen and your old password still "
    "works."
)

_PHASES: Final = {
    "no_vault": "noVault",
    "locked": "locked",
    "unlocked": "opening",
    "closed": "closed",
    IN_USE: "inUse",
    FAILED: "failed",
}


def _version() -> str:
    try:
        return version("qrp2p")
    except PackageNotFoundError:
        return "dev"


class AppController(ViewModel):
    """The root view model QML starts from.

    Args:
        bridge: The bridge (already connected; started by the app).
        data_dir: The data directory, to name it in messages.
        dev_preview: Show development previews (the Inspector layout, M4 work).
        parent: The Qt parent.
    """

    phaseChanged = Signal()  # noqa: N815
    statusChanged = Signal()  # noqa: N815
    workspaceChanged = Signal()  # noqa: N815
    appearanceChanged = Signal()  # noqa: N815
    welcomeChanged = Signal()  # noqa: N815
    passwordChangeFinished = Signal(bool, str)  # noqa: N815
    """After :meth:`changePassword`: whether the new password is active, and what to say."""

    phase = readonly(str, "_phase", phaseChanged)
    busy = readonly(bool, "_busy", statusChanged)
    busyText = readonly(str, "_busy_text", statusChanged)  # noqa: N815
    error = readonly(str, "_error", statusChanged)
    notice = readonly(str, "_notice", statusChanged)
    deviceUnlockAvailable = readonly(bool, "_device_available", statusChanged)  # noqa: N815
    workspace = readonly(QObject, "_workspace", workspaceChanged)
    appearance = readonly(str, "_appearance", appearanceChanged)
    reducedMotion = readonly(bool, "_reduced_motion", appearanceChanged)  # noqa: N815
    textScale = readonly(int, "_text_scale", appearanceChanged)  # noqa: N815
    welcome = readonly(bool, "_welcome", welcomeChanged)
    devPreview = constant(bool, "_dev_preview")  # noqa: N815
    dataDir = constant(str, "_data_dir")  # noqa: N815
    version = constant(str, "_version")

    def __init__(
        self,
        bridge: Bridge,
        *,
        data_dir: str,
        dev_preview: bool = False,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._bridge = bridge
        self._data_dir = data_dir
        self._dev_preview = dev_preview
        self._version = _version()
        self._phase = "starting"
        self._busy = False
        self._busy_text = ""
        self._error = ""
        self._notice = ""
        self._device_available = False
        self._tried_device = False
        self._workspace: Workspace | None = None
        self._appearance = "system"
        self._reduced_motion = False
        self._text_scale = 100
        self._welcome = False
        self._last_touch = 0.0
        bridge.lifecycle.connect(self._lifecycle)

    # -- lifecycle -------------------------------------------------------------------------------

    def _lifecycle(self, lifecycle: Lifecycle) -> None:
        if lifecycle.workspace is not None:
            workspace = Workspace(self._bridge.scope(), lifecycle.workspace, self)
            workspace.readyChanged.connect(self._workspace_ready)
            workspace.settings_model.changed.connect(self._sync_appearance)
            self._set_workspace(workspace)
            self._sync_appearance()
        else:
            self._set_workspace(None)
        if lifecycle.state == FAILED:
            self._status(busy=False, error=lifecycle.error or "QRP2P could not start.")
        self._set_phase(_PHASES.get(lifecycle.state, lifecycle.state))
        if lifecycle.state == "locked":
            self._check_device_unlock()

    def _workspace_ready(self) -> None:
        if self._workspace is not None and self._phase == "opening":
            self._status(busy=False)
            self._set_phase("unlocked")

    def _set_workspace(self, workspace: Workspace | None) -> None:
        old = self._workspace
        if old is workspace:
            return
        self._workspace = workspace
        self.workspaceChanged.emit()
        if old is not None:
            old.deleteLater()

    def _set_phase(self, phase: str) -> None:
        self._set("_phase", phase, self.phaseChanged)

    def _status(
        self, *, busy: bool, text: str = "", error: str = "", notice: str | None = None
    ) -> None:
        self._busy, self._busy_text, self._error = busy, text, error
        if notice is not None:
            self._notice = notice
        self.statusChanged.emit()

    def _sync_appearance(self) -> None:
        workspace = self._workspace
        if workspace is None:
            return  # a lock keeps the last appearance; the vault holds the real one
        settings = workspace.settings_model
        appearance = str(settings.value("appearance"))
        reduced_motion = bool(settings.value("reduced_motion"))
        text_scale = int(str(settings.value("text_scale")))
        if (appearance, reduced_motion, text_scale) != (
            self._appearance,
            self._reduced_motion,
            self._text_scale,
        ):
            self._appearance = appearance
            self._reduced_motion = reduced_motion
            self._text_scale = text_scale
            self.appearanceChanged.emit()

    def _check_device_unlock(self) -> None:
        def done(reply: Reply) -> None:
            available = reply.error is None and bool(reply.value)
            if available != self._device_available:
                self._device_available = available
                self.statusChanged.emit()
            # Only at start: after the user locked, the device key must not undo the lock.
            if available and not self._tried_device and self._phase == "locked":
                self._tried_device = True
                self.unlockWithDevice()
            self._tried_device = True

        self._bridge.request(ops.device_unlock_available(), done, scoped=False)

    # -- slots -----------------------------------------------------------------------------------

    @Slot(str, str, str)
    def createVault(self, name: str, password: str, repeat: str) -> None:  # noqa: N802
        """Create the vault and identity (first run)."""
        if self._busy:
            return
        if len(password) < MIN_PASSWORD:
            self._status(busy=False, error=f"Use at least {MIN_PASSWORD} characters.")
            return
        if password != repeat:
            self._status(busy=False, error="The passwords differ.")
            return

        def done(reply: Reply) -> None:
            if reply.error is not None:
                self._status(busy=False, error=reply.error.message)
                return
            self._welcome = True
            self.welcomeChanged.emit()

        self._run(ops.create_vault(password, name), "Creating your vault…", done)

    @Slot(str)
    def unlock(self, password: str) -> None:
        """Unlock with the password."""
        if self._busy or not password:
            return

        def done(reply: Reply) -> None:
            if reply.error is not None:
                self._status(busy=False, error=reply.error.message)

        self._run(ops.unlock(password), "Unlocking…", done, clear_notice=True)

    @Slot()
    def unlockWithDevice(self) -> None:  # noqa: N802
        """Unlock with the device key in the OS keychain ("Remember on this device")."""
        if self._busy:
            return

        def done(reply: Reply) -> None:
            if reply.error is not None:
                error = (
                    f"Could not unlock with this device: {reply.error.message} Use your password."
                )
                self._status(busy=False, error=error)

        self._run(ops.unlock_with_device(), "Unlocking with this device…", done, clear_notice=True)

    @Slot()
    def lock(self) -> None:
        """Lock now: the messenger disappears at once."""
        if self._phase not in {"unlocked", "opening"}:
            return
        self._set_workspace(None)
        self._set_phase("locking")
        self._bridge.lock()

    @Slot()
    def touch(self) -> None:
        """The user did something: postpone auto-lock."""
        now = time.monotonic()
        if self._phase == "unlocked" and now - self._last_touch >= TOUCH_INTERVAL:
            self._last_touch = now
            self._bridge.request(ops.touch())

    @Slot()
    def dismissWelcome(self) -> None:  # noqa: N802
        """Close the first-run identity summary."""
        self._set("_welcome", value=False, signal=self.welcomeChanged)

    @Slot()
    def dismissNotice(self) -> None:  # noqa: N802
        """Hide the notice on the unlock screen."""
        if self._notice:
            self._notice = ""
            self.statusChanged.emit()

    @Slot(str, str, str)
    def changePassword(self, old: str, new: str, repeat: str) -> None:  # noqa: N802
        """Re-key the vault under a new password (Settings)."""
        if len(new) < MIN_PASSWORD:
            self._password_done(ok=False, text=f"Use at least {MIN_PASSWORD} characters.")
            return
        if new != repeat:
            self._password_done(ok=False, text="The new passwords differ.")
            return

        def done(reply: Reply) -> None:
            error = reply.error
            if error is None:
                self._password_done(ok=True, text="Password changed; everything was re-encrypted.")
            elif error.kind == "cleanup":
                self._password_done(ok=True, text=error.message)
            elif error.kind == "wrong_password":
                self._password_done(ok=False, text="The current password is wrong.")
            elif self._bridge.state != "unlocked":
                self._status(busy=False, notice=INTERRUPTED_CHANGE)
                self._password_done(ok=False, text=INTERRUPTED_CHANGE)
            else:
                self._password_done(ok=False, text=f"The password was not changed: {error.message}")

        # Unscoped: an interrupted change locks the node, and the answer must still arrive.
        self._bridge.request(ops.change_password(old, new), done, scoped=False)

    def _password_done(self, *, ok: bool, text: str) -> None:
        self.passwordChangeFinished.emit(ok, text)

    def _run(
        self, op: ops.Op, text: str, done: Callable[[Reply], None], *, clear_notice: bool = False
    ) -> None:
        if self._bridge.request(op, done, scoped=False):
            self._status(busy=True, text=text, notice="" if clear_notice else None)
