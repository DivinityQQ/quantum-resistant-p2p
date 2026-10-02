"""What rows show: grouping, delivery states, file states and close reasons (UI_DESIGN §6, §10)."""

from dataclasses import replace

import pytest

from qrp2p.ui.snapshots import FileSnap, MessageSnap, NearbySnap
from qrp2p.ui.text import isolate
from qrp2p.ui.viewmodels.rows import (
    Formats,
    contact_row,
    ended_text,
    file_state,
    initial,
    message_rows,
    nearby_row,
    presence,
    strip_order,
)
from tests.ui.fakes import chat, contact, online

DAY = 86_400.0
T0 = 2_000_000_000.0

FORMATS = Formats(
    time=lambda t: f"t{int(t - T0)}",
    day=lambda t: f"day{int((t - T0) // DAY)}",
    size=lambda n: f"{n}B",
)


def file_message(
    status: str, *, direction: str = "in", reason: str = "", transferred: int | None = None
) -> MessageSnap:
    return MessageSnap(
        entry_id="f" * 32,
        kind="file",
        direction=direction,
        time=T0,
        status="received",
        text="",
        glass_box=False,
        file=FileSnap(
            file_id="a" * 32,
            name="notes.pdf",
            size=1000,
            status=status,
            path="/dl/notes.pdf",
            reason=reason,
            transferred=transferred,
        ),
    )


# -- contacts ---------------------------------------------------------------------------------------


def test_presence_keeps_states_distinct() -> None:
    bob = contact("Bob")
    assert presence(online(bob), "", nearby=True) == ("online", "Online")
    assert presence(bob, "connecting", nearby=True) == ("connecting", "Connecting…")
    assert presence(bob, "waiting", nearby=False) == ("waiting", "Waiting for them to accept")
    assert presence(bob, "", nearby=True) == ("nearby", "Nearby")
    assert presence(bob, "", nearby=False) == ("offline", "Offline")
    assert presence(contact("Eve", trust="blocked"), "", nearby=True)[0] == "blocked"


def test_contact_row_describes_everything_for_screen_readers() -> None:
    row = contact_row(
        online(contact("Bob", trust="verified"), glass_box=True),
        connecting="",
        nearby=False,
        unread=2,
    )
    assert row.description == "Bob, Verified, Online, glass-box session, 2 unread, ID BOBX-0000"
    assert row.glass_box
    assert row.initial == "B"
    assert initial("  ") == "?"
    assert initial("ébène") == "É"


def test_strip_keeps_visible_contacts_in_place() -> None:
    activity = {"a": 3.0, "b": 2.0, "c": 1.0}
    first = strip_order([], activity, "", 3)
    assert first == ["a", "b", "c"]
    activity["c"] = 9.0  # a message from a contact already shown: no reshuffle
    assert strip_order(first, activity, "", 3) == first
    activity["d"] = 10.0  # a newcomer enters at the front, the least recent leaves
    assert strip_order(first, activity, "", 3) == ["d", "a", "c"]


def test_strip_always_shows_the_selected_contact() -> None:
    activity = {"a": 3.0, "b": 2.0, "c": 1.0}
    assert set(strip_order([], activity, "c", 2)) == {"a", "c"}
    assert strip_order([], activity, "gone", 2) == ["a", "b"]


def test_nearby_rows_show_hints_only() -> None:
    row = nearby_row(
        NearbySnap(
            key="k",
            label="Carol (ABCD-EFGH)",
            id_hint="0123456789abcdef",
            profiles=("HYBRID-1",),
            addresses=("10.0.0.3", "fd00::3"),
            port=47470,
            contact_id="",
        )
    )
    assert row.id_hint == "0123 4567"
    assert row.addresses == "10.0.0.3, fd00::3"


# -- messages ---------------------------------------------------------------------------------------


def test_messages_group_by_sender_time_and_day() -> None:
    messages = [
        chat("a", time=T0),
        chat("b", time=T0 + 10),
        chat("c", direction="out", status="delivered", time=T0 + 20),
        chat("d", time=T0 + 500),  # same sender as a/b, but later and after c
        chat("e", time=T0 + DAY),
    ]
    rows = message_rows(messages, {}, "Bob", FORMATS)
    assert [r.group_start for r in rows] == [True, False, True, True, True]
    assert [r.group_end for r in rows] == [False, True, True, True, True]
    assert [r.day_label for r in rows] == ["day0", "", "", "", "day1"]
    assert [r.show_meta for r in rows] == [False, True, True, True, True]
    assert rows[0].time_text == "t0"


def test_outgoing_status_shows_where_it_differs_from_the_group() -> None:
    messages = [
        chat("1", direction="out", status="delivered", time=T0),
        chat("2", direction="out", status="sent", time=T0 + 1),
        chat("3", direction="out", status="sent", time=T0 + 2),
    ]
    rows = message_rows(messages, {}, "Bob", FORMATS)
    assert [r.show_meta for r in rows] == [True, False, True]
    assert [r.status_text for r in rows] == ["Delivered", "Sent", "Sent"]


@pytest.mark.parametrize(
    ("status", "text"),
    [("sending", "Sending…"), ("sent", "Sent"), ("delivered", "Delivered"), ("failed", "Not sent")],
)
def test_delivery_states_are_named_truthfully(status: str, text: str) -> None:
    (row,) = message_rows([chat("x", direction="out", status=status)], {}, "Bob", FORMATS)
    assert row.status_text == text
    (incoming,) = message_rows([chat("x")], {}, "Bob", FORMATS)
    assert incoming.status_text == ""  # a received message claims no delivery state


def test_identity_change_note() -> None:
    note = replace(chat("ABCD-EFGH -> WXYZ-1234"), kind="identity_changed", direction="local")
    (row,) = message_rows([note], {}, "Bob", FORMATS)
    assert row.text.startswith("Identity changed from ABCD-EFGH to WXYZ-1234.")


@pytest.mark.parametrize(
    ("status", "direction", "reason", "text"),
    [
        ("offered", "in", "", "Wants to send you this file"),
        ("offered", "out", "", f"Waiting for {isolate('Bob')} to accept"),
        ("accepted", "in", "", "Starting…"),
        ("complete", "in", "", "Saved and verified"),
        ("complete", "out", "", "Delivered and verified"),
        ("declined", "out", "", "Declined"),
        ("cancelled", "in", "user", "Cancelled"),
        ("cancelled", "in", "disk_full", "Cancelled: not enough disk space"),
        ("failed", "out", "", "Failed"),
        ("failed", "in", "hash_mismatch", "Failed: the checksum did not match"),
    ],
)
def test_file_states(status: str, direction: str, reason: str, text: str) -> None:
    message = file_message(status, direction=direction, reason=reason)
    assert file_state(message, None, "Bob", FORMATS) == (text, -1.0)


def test_transfer_progress_is_measured() -> None:
    message = file_message("transferring", transferred=250)
    assert file_state(message, 250, "Bob", FORMATS) == ("250B of 1000B", 0.25)
    assert file_state(message, None, "Bob", FORMATS) == ("0B of 1000B", 0.0)


def test_only_a_completed_download_offers_its_folder() -> None:
    rows = message_rows(
        [
            file_message("complete"),
            replace(file_message("complete", direction="out"), entry_id="b" * 32),
        ],
        {},
        "Bob",
        FORMATS,
    )
    assert [r.file_path for r in rows] == ["/dl/notes.pdf", ""]


# -- sessions ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "by_peer", "text"),
    [
        ("", False, "Connection lost: no reason was given"),
        ("normal", True, f"{isolate('Bob')} ended the session"),
        ("normal", False, "Disconnected"),
        ("locked", True, f"{isolate('Bob')} locked QRP2P"),
        ("decrypt_failed", False, "Authentication failed (decrypt_failed)"),
        (
            "decrypt_failed",
            True,
            f"Authentication failed (decrypt_failed, reported by {isolate('Bob')})",
        ),
        ("timeout", False, "Connection timed out (timeout)"),
        ("new_reason", False, "Session closed (new_reason)"),
    ],
)
def test_close_reasons_explain_first_then_name_the_code(
    reason: str, by_peer: bool, text: str
) -> None:
    assert ended_text(reason, by_peer=by_peer, peer="Bob") == text
