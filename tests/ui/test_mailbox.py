"""Trace backpressure bounds captured bytes before Qt processes its first wake."""

import pytest

from qrp2p.core.trace import Direction, FrameTraced
from qrp2p.core.wire import Frame, FrameType
from qrp2p.ui.inspect.model import TraceItem, item_bytes
from qrp2p.ui.mailbox import Mailbox
from qrp2p.ui.snapshots import Batch, Lifecycle, NoticePosted, Reply
from qrp2p.ui.tap import InspectSnap, TraceAppended, TraceOverflow
from tests.ui.inspect_support import session_facts


def appended(n: int, *, source: str = "node") -> TraceAppended:
    frame = FrameTraced(Direction.OUT, Frame(FrameType.RECORD, bytes(16_000)), ())
    return TraceAppended(7, (TraceItem(n, float(n), frame),), source)


def test_a_slow_qt_thread_gets_one_overflow_per_source_and_keeps_reply_order() -> None:
    mailbox = Mailbox()
    assert mailbox.put(Lifecycle(1, "unlocked"))
    for n in range(1000):
        assert not mailbox.put(Batch(1, (appended(n), appended(n, source="lab"))))
    mailbox.put(Batch(1, (NoticePosted("still delivered"),)))
    mailbox.put(Reply(1, 5, "snapshot request completed"))
    for n in range(1000, 2000):
        mailbox.put(Batch(1, (appended(n), appended(n, source="lab"))))
    queued = mailbox.take()
    updates = [u for d in queued if isinstance(d, Batch) for u in d.updates]
    assert [u for u in updates if isinstance(u, TraceOverflow)] == [
        TraceOverflow(7),
        TraceOverflow(7, "lab"),
    ]
    assert not any(isinstance(u, TraceAppended) for u in updates)
    assert len(queued) == 4  # lifecycle, overflow batch, notice batch, reply
    assert isinstance(queued[0], Lifecycle)
    assert queued[-1] == Reply(1, 5, "snapshot request completed")
    assert mailbox.put(Batch(1, (appended(2000),)))  # a new wake and stream after drain


def test_a_non_overflowing_delivery_keeps_its_captured_bytes() -> None:
    mailbox = Mailbox()
    update = appended(0)
    mailbox.put(Batch(1, (update,)))
    queued = mailbox.take()
    assert queued == [Batch(1, (update,))]
    assert sum(item_bytes(i) for i in update.items) == 16_005


def test_lock_discards_payloads_and_scoped_snapshots_immediately() -> None:
    mailbox = Mailbox()
    mailbox.put(Batch(1, (appended(0),)))
    mailbox.put(Reply(1, 5, b"captured session secret"))
    mailbox.put(Reply(1, 6, "lock result"))
    mailbox.put(Lifecycle(2, "locked"))
    mailbox.clear_scoped({5}, gen=1)
    assert mailbox.take() == [Reply(1, 6, "lock result"), Lifecycle(2, "locked")]


def test_snapshot_replies_are_bounded_and_keep_a_named_retry_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    monkeypatch.setattr("qrp2p.ui.mailbox.MAILBOX_BYTES", 20_000)
    mailbox = Mailbox()
    snapshot = InspectSnap(session_facts(), appended(0).items, missing=False)
    mailbox.put(Reply(1, 5, snapshot))
    mailbox.put(Reply(1, 6, snapshot))
    queued = mailbox.take()
    assert len(queued) == 2
    for delivery in queued:
        assert isinstance(delivery, Reply)
        assert delivery.value is None
        assert delivery.error is not None
        assert delivery.error.kind == "trace_overflow"


def test_lock_refuses_late_old_payloads_and_preserves_future_generation_budgets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("qrp2p.ui.mailbox.MAILBOX_BYTES", 20_000)
    mailbox = Mailbox()
    mailbox.put(Batch(1, (NoticePosted("old generation"),)))
    mailbox.put(Batch(3, (appended(1),)))
    mailbox.clear_scoped(set(), gen=1)
    assert not mailbox.put(Batch(1, (appended(2),)))
    assert not mailbox.put(Reply(1, 5, InspectSnap(session_facts(), appended(2).items, False)))
    mailbox.put(Batch(3, (appended(3),)))
    assert mailbox.take() == [Batch(3, (TraceOverflow(7),))]
    mailbox.close()
    assert not mailbox.put(Batch(4, (appended(4),)))
    assert not mailbox.take()
