"""Whether the XDG desktop portal runs (Linux): the desktop's own file dialogs come through it."""

# jeepney (Linux only, in the gui extra) has no type information.
# pyright: reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from typing import Final

PORTAL: Final = "org.freedesktop.portal.Desktop"
QUERY_TIMEOUT: Final = 1.0


def portal_running() -> bool:
    """Whether the portal runs on the session bus.

    Running, not merely startable: Qt asks the portal for settings at start-up and, where the
    bus can start it but it never answers, would wait for that. No bus at all makes Qt warn.
    """
    from jeepney import DBus, DBusErrorResponse  # noqa: PLC0415  # Linux only
    from jeepney.io.blocking import open_dbus_connection  # noqa: PLC0415

    try:
        with open_dbus_connection(bus="SESSION") as bus:
            reply = bus.send_and_get_reply(DBus().NameHasOwner(PORTAL), timeout=QUERY_TIMEOUT)
    except OSError, KeyError, ValueError, TimeoutError, DBusErrorResponse:
        return False  # no session bus (KeyError: no address), or it did not answer
    return reply.body == (True,)
