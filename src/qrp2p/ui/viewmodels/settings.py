"""The Settings screen's state (UI_DESIGN §6.5).

Settings live encrypted in the vault; this view model shows the values the node reports and asks
for changes. A change is shown once the node has saved it, so the screen never claims a value the
vault does not hold. Some settings apply to the next connection or the next unlock; the screen says
which.
"""

from typing import Final

from PySide6.QtCore import QUrl, Signal, Slot

from qrp2p.services.models import TEXT_SCALES
from qrp2p.ui import ops
from qrp2p.ui.bridge import Scope
from qrp2p.ui.snapshots import Reply, SettingsSnap
from qrp2p.ui.viewmodels.qt import ViewModel, constant, mapped, readonly

PROFILES: Final = ("HYBRID-1", "PQ-CNSA-1")
"""The real profiles, for choosers (lab profiles never appear in real-session controls)."""


def _values(snap: SettingsSnap) -> dict[str, object]:
    return {
        "display_name": snap.display_name,
        "announce_name": snap.announce_name,
        "default_profile": snap.default_profile,
        "default_retention": snap.default_retention,
        "auto_lock_minutes": snap.auto_lock_minutes,
        "port": snap.port,
        "downloads_dir": snap.downloads_dir,
        "downloads_custom": snap.downloads_custom,
        "max_file_size": float(snap.max_file_size),
        "appearance": snap.appearance,
        "reduced_motion": snap.reduced_motion,
        "text_scale": snap.text_scale,
    }


class SettingsModel(ViewModel):
    """The user's settings and the device-unlock switch."""

    changed = Signal()
    deviceChanged = Signal()  # noqa: N815
    statusChanged = Signal()  # noqa: N815

    displayName = mapped(str, "_values", "display_name", changed)  # noqa: N815
    announceName = mapped(bool, "_values", "announce_name", changed)  # noqa: N815
    defaultProfile = mapped(str, "_values", "default_profile", changed)  # noqa: N815
    defaultRetention = mapped(str, "_values", "default_retention", changed)  # noqa: N815
    autoLockMinutes = mapped(int, "_values", "auto_lock_minutes", changed)  # noqa: N815
    port = mapped(int, "_values", "port", changed)
    downloadsDir = mapped(str, "_values", "downloads_dir", changed)  # noqa: N815
    downloadsCustom = mapped(bool, "_values", "downloads_custom", changed)  # noqa: N815
    maxFileSize = mapped(float, "_values", "max_file_size", changed)  # noqa: N815
    appearance = mapped(str, "_values", "appearance", changed)
    reducedMotion = mapped(bool, "_values", "reduced_motion", changed)  # noqa: N815
    textScale = mapped(int, "_values", "text_scale", changed)  # noqa: N815
    deviceUnlock = readonly(bool, "_device_unlock", deviceChanged)  # noqa: N815
    deviceUnlockKnown = readonly(bool, "_device_known", deviceChanged)  # noqa: N815
    saving = readonly(str, "_saving", statusChanged)
    """The setting being saved, or empty."""
    error = readonly(str, "_error", statusChanged)
    profiles = constant(list, "_profiles")
    textScales = constant(list, "_text_scales")  # noqa: N815

    def __init__(self, scope: Scope, snap: SettingsSnap) -> None:
        super().__init__()
        self._scope = scope
        self._values = _values(snap)
        self._device_unlock = False
        self._device_known = False
        self._saving = ""
        self._error = ""
        self._profiles = list(PROFILES)
        self._text_scales = list(TEXT_SCALES)

    def value(self, name: str) -> object:
        """A setting's current value by its snapshot name."""
        return self._values[name]

    def apply(self, snap: SettingsSnap) -> None:
        """The node reported the settings in use."""
        values = _values(snap)
        if values != self._values:
            self._values = values
            self.changed.emit()

    @Slot(str, "QVariant")
    def set(self, name: str, value: object) -> None:
        """Change one setting (``display_name``, ``appearance``, …)."""

        def done(reply: Reply) -> None:
            self._status("", reply.error.message if reply.error is not None else "")
            if isinstance(reply.value, SettingsSnap):
                self.apply(reply.value)

        if self._scope.request(ops.update_setting(name, value), done):
            self._status(name, "")

    @Slot(str)
    def setDownloadsFolder(self, url: str) -> None:  # noqa: N802
        """Save received files in this folder (a URL from the folder dialog)."""
        path = QUrl(url).toLocalFile() if QUrl(url).isLocalFile() else url
        self.set("downloads_dir", path)

    @Slot()
    def resetDownloadsFolder(self) -> None:  # noqa: N802
        """Back to the OS downloads folder."""
        self.set("downloads_dir", "")

    @Slot()
    def loadDeviceUnlock(self) -> None:  # noqa: N802
        """Find out whether "Remember on this device" is on."""

        def done(reply: Reply) -> None:
            if reply.error is None:
                self._device_unlock = bool(reply.value)
                self._device_known = True
                self.deviceChanged.emit()

        self._scope.request(ops.device_unlock_enabled(), done)

    @Slot(bool)
    def setDeviceUnlock(self, enabled: bool) -> None:  # noqa: FBT001, N802
        """Turn "Remember on this device" on or off (needs the OS keychain)."""

        def done(reply: Reply) -> None:
            self._status("", reply.error.message if reply.error is not None else "")
            if reply.error is None:
                self._device_unlock = enabled
                self._device_known = True
                self.deviceChanged.emit()

        if self._scope.request(ops.set_device_unlock(enabled=enabled), done):
            self._status("device_unlock", "")

    @Slot()
    def clearError(self) -> None:  # noqa: N802
        """Hide the last error."""
        self._status(self._saving, "")

    def _status(self, saving: str, error: str) -> None:
        if (saving, error) != (self._saving, self._error):
            self._saving, self._error = saving, error
            self.statusChanged.emit()
