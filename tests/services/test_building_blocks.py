"""Small service parts: text sanitising, limits, the trace bus, private files, the admission table."""

import sys
from pathlib import Path
from typing import Any

import pytest

from qrp2p.core.errors import AdmitReason
from qrp2p.core.trace import StateChanged
from qrp2p.services import paths as paths_module
from qrp2p.services.admission import (
    DECLINES_TO_MUTE,
    MUTE_SECONDS,
    PROMPT_INTERVAL,
    Accept,
    Ask,
    GlassBoxLimiter,
    PromptKind,
    Reject,
    decide,
)
from qrp2p.services.limits import SlotPool, TokenBucket
from qrp2p.services.models import Contact, TrustState
from qrp2p.services.paths import (
    DATA_DIR_ENV,
    default_data_dir,
    ensure_private_dir,
    write_private_file,
)
from qrp2p.services.text import display_text
from qrp2p.services.trace_bus import ENDED_KEPT, RING_SIZE, TraceBus
from tests.support import identity_from_label

# --- text -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("plain", "plain"),
        ("\x1b[31mred\x1b[0m", "\ufffd[31mred\ufffd[0m"),
        ("bell\x07", "bell\ufffd"),
        ("c1\x9b31m", "c1\ufffd31m"),
        ("abc\u202eexe.txt", "abc\ufffdexe.txt"),
        ("iso\u2066late\u2069", "iso\ufffdlate\ufffd"),
        ("tab\there", "tab here"),
        ("two\nlines", "two\ufffdlines"),
        ("lone \udc80 surrogate", "lone \ufffd surrogate"),
    ],
)
def test_display_text(raw: str, shown: str) -> None:
    assert display_text(raw) == shown


def test_display_text_keeps_newlines_when_asked_and_truncates() -> None:
    assert display_text("a\nb", keep_newlines=True) == "a\nb"
    assert display_text("abcdef", limit=4) == "abc…"


# --- limits ---------------------------------------------------------------------------------------


def test_token_bucket() -> None:
    bucket = TokenBucket(rate=2.0, burst=3)
    assert [bucket.take(0.0) for _ in range(4)] == [True, True, True, False]
    assert bucket.take(0.5)  # one token refilled
    assert not bucket.take(0.5)
    assert [bucket.take(100.0) for _ in range(4)] == [True, True, True, False]  # capped at burst


def test_slot_pool() -> None:
    pool = SlotPool(total=3, per_source=2)
    assert pool.acquire("a")
    assert pool.acquire("a")
    assert not pool.acquire("a")
    assert pool.acquire("b")
    assert not pool.acquire("c")  # global cap
    pool.release("a")
    assert pool.acquire("c")
    assert pool.in_use == 3
    with pytest.raises(ValueError, match="no slot"):
        pool.release("z")


# --- trace bus ------------------------------------------------------------------------------------


def test_trace_ring_and_subscribers() -> None:
    bus = TraceBus()
    seen: list[int] = []
    unsubscribe = bus.subscribe(lambda record: seen.append(record.session_id))
    for n in range(RING_SIZE + 5):
        bus.publish(1, float(n), StateChanged("m", str(n)))
    events = bus.events(1)
    assert len(events) == RING_SIZE
    assert events[0].time == 5.0
    unsubscribe()
    bus.publish(1, 0.0, StateChanged("m", "x"))
    assert len(seen) == RING_SIZE + 5


def test_trace_rings_of_ended_sessions_are_bounded() -> None:
    bus = TraceBus()
    for session in range(ENDED_KEPT + 3):
        bus.publish(session, 0.0, StateChanged("m", "s"))
        bus.session_ended(session)
    assert bus.events(0) == ()
    assert bus.events(ENDED_KEPT + 2) != ()
    bus.clear()
    assert bus.events(ENDED_KEPT + 2) == ()


# --- paths ----------------------------------------------------------------------------------------


def test_write_private_file_replaces_atomically(tmp_path: Path) -> None:
    target = tmp_path / "vault.json"
    write_private_file(target, b"one")
    write_private_file(target, b"two")
    assert target.read_bytes() == b"two"
    assert [p.name for p in tmp_path.iterdir()] == ["vault.json"]  # no temporary files left
    if sys.platform != "win32":
        assert target.stat().st_mode & 0o777 == 0o600


def test_data_dir_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(DATA_DIR_ENV, str(tmp_path))
    assert default_data_dir() == tmp_path
    monkeypatch.delenv(DATA_DIR_ENV)
    assert default_data_dir().name.lower() == "qrp2p"


# --- the admission table (DESIGN §7.6) ------------------------------------------------------------


def contact(trust: TrustState = TrustState.PINNED, profile_id: int = 1) -> Contact:
    return Contact(
        contact_id=b"c" * 16,
        conv_id=b"v" * 16,
        bundle=identity_from_label("peer").bundle,
        name="Peer",
        trust=trust,
        profile_id=profile_id,
    )


@pytest.mark.parametrize(
    ("who", "profile_id", "gb", "may_prompt", "outcome"),
    [
        (None, 1, False, True, Ask(PromptKind.CONTACT_REQUEST)),
        (None, 1, True, True, Ask(PromptKind.CONTACT_REQUEST, glass_box_refused=True)),
        (contact(TrustState.BLOCKED), 1, False, True, Reject(AdmitReason.DECLINED)),
        (contact(TrustState.BLOCKED), 1, True, True, Reject(AdmitReason.DECLINED)),
        (contact(), 1, False, True, Accept()),
        (contact(TrustState.VERIFIED), 1, False, True, Accept()),
        (contact(), 2, False, True, Reject(AdmitReason.PROFILE_POLICY)),
        (contact(), 2, True, True, Reject(AdmitReason.PROFILE_POLICY)),
        (contact(), 1, True, True, Ask(PromptKind.GLASS_BOX)),
        (contact(), 1, True, False, Accept(glass_box=False)),
    ],
)
def test_admission_table(
    who: Contact | None, profile_id: int, gb: bool, may_prompt: bool, outcome: object
) -> None:
    assert (
        decide(who, profile_id=profile_id, gb_request=gb, may_prompt_glass_box=may_prompt)
        == outcome
    )


def test_glass_box_limiter() -> None:
    limiter = GlassBoxLimiter()
    peer = b"p" * 48
    assert limiter.allows(peer, 0.0)
    limiter.prompted(peer, 0.0)
    assert not limiter.allows(peer, PROMPT_INTERVAL - 1)
    assert limiter.allows(peer, PROMPT_INTERVAL)
    now = PROMPT_INTERVAL
    for _ in range(DECLINES_TO_MUTE):
        limiter.prompted(peer, now)
        limiter.declined(peer, now)
        now += PROMPT_INTERVAL
    assert not limiter.allows(peer, now)
    assert limiter.allows(peer, now - PROMPT_INTERVAL + MUTE_SECONDS)
    limiter.declined(peer, now + MUTE_SECONDS)
    limiter.accepted(peer)  # an accept resets the count
    limiter.declined(peer, now + MUTE_SECONDS)
    assert limiter.allows(peer, now + MUTE_SECONDS + PROMPT_INTERVAL)


# --- found by mutation testing of the services ----------------------------------------------------


def test_limiter_counts_declines_in_a_row() -> None:
    limiter = GlassBoxLimiter()
    peer, now = b"q" * 48, 0.0
    limiter.declined(peer, now)  # a decline without an earlier prompt is fine
    limiter.declined(peer, now)
    limiter.accepted(peer)  # resets: two more declines do not mute
    limiter.declined(peer, now)
    limiter.declined(peer, now)
    assert limiter.allows(peer, now + PROMPT_INTERVAL)
    limiter.declined(peer, now)  # the third in a row
    assert not limiter.allows(peer, now + PROMPT_INTERVAL)
    later = now + MUTE_SECONDS
    limiter.declined(peer, later)  # after a mute the count starts from zero
    limiter.declined(peer, later)
    assert limiter.allows(peer, later + PROMPT_INTERVAL)


def test_display_text_limit_is_inclusive() -> None:
    assert display_text("abcd", limit=4) == "abcd"


def test_slot_counts_per_source() -> None:
    pool = SlotPool(total=10, per_source=5)
    for _ in range(3):
        pool.acquire("a")
    pool.release("a")
    assert pool.in_use == 2


def test_trace_records_and_the_ended_limit() -> None:
    bus = TraceBus()
    event = StateChanged("m", "s")
    bus.publish(7, 1.5, event)
    (record,) = bus.events(7)
    assert (record.session_id, record.time, record.event) == (7, 1.5, event)
    for session in range(ENDED_KEPT):
        bus.publish(session + 100, 0.0, event)
        bus.session_ended(session + 100)
    assert all(bus.events(session + 100) for session in range(ENDED_KEPT))  # exactly kept
    bus.session_ended(999)  # an ended session that never traced anything
    bus.session_ended(998)
    assert bus.events(100) == ()


def test_private_directory(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b"
    ensure_private_dir(nested)
    assert nested.is_dir()
    if sys.platform != "win32":
        loose = tmp_path / "loose"
        loose.mkdir(mode=0o755)
        loose.chmod(0o755)
        ensure_private_dir(loose)
        assert loose.stat().st_mode & 0o777 == 0o700


def test_private_file_is_written_next_to_its_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []
    real = paths_module.tempfile.mkstemp

    def spy(**kwargs: Any) -> tuple[int, str]:  # noqa: ANN401
        seen.append(kwargs.get("dir"))
        return real(**kwargs)

    monkeypatch.setattr(paths_module.tempfile, "mkstemp", spy)
    write_private_file(tmp_path / "x", b"1")
    assert seen == [tmp_path]  # same file system, so the rename is atomic


def test_a_failed_private_write_leaves_no_temporary_file(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "occupied").write_bytes(b"")  # a non-empty directory cannot be replaced
    with pytest.raises(OSError):  # noqa: PT011  # whichever the OS reports
        write_private_file(target, b"data")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["target"]
