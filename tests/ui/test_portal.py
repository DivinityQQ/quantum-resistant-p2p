"""Linux file dialogs: the desktop's own through the XDG portal, but only where it runs."""

import sys

import pytest

from qrp2p.ui import app
from qrp2p.ui.portal import portal_running

linux = pytest.mark.skipif(sys.platform != "linux", reason="the portal is a Linux desktop service")


@linux
def test_no_session_bus_means_no_portal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/nonexistent")
    assert not portal_running()


@linux
@pytest.mark.parametrize(("running", "expected"), [(True, "xdgdesktopportal"), (False, None)])
def test_the_portal_theme_is_chosen_only_where_the_portal_runs(
    monkeypatch: pytest.MonkeyPatch, running: bool, expected: str | None
) -> None:
    monkeypatch.delenv("QT_QPA_PLATFORMTHEME", raising=False)
    monkeypatch.setattr(app, "portal_running", lambda: running)
    app.choose_platform_theme()
    assert app.os.environ.get("QT_QPA_PLATFORMTHEME") == expected


def test_a_chosen_platform_theme_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QT_QPA_PLATFORMTHEME", "gtk3")
    monkeypatch.setattr(app, "portal_running", lambda: True)
    app.choose_platform_theme()
    assert app.os.environ["QT_QPA_PLATFORMTHEME"] == "gtk3"
