"""The mailbox between the threads: one wake signal, order kept, a bounded trace stream."""

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


def test_replies_are_never_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("qrp2p.ui.mailbox.MAILBOX_BYTES", 20_000)
    mailbox = Mailbox()
    snapshot = Reply(1, 5, InspectSnap(session_facts(), appended(0).items, missing=False))
    mailbox.put(snapshot)
    mailbox.put(Batch(1, (appended(1),)))
    mailbox.put(Batch(1, (appended(2),)))  # beyond the budget: the stream overflows
    assert mailbox.take() == [snapshot, Batch(1, (TraceOverflow(7),))]


def test_a_closed_mailbox_drops_everything() -> None:
    mailbox = Mailbox()
    mailbox.put(Batch(1, (appended(0),)))
    mailbox.close()
    assert not mailbox.put(Batch(1, (appended(1),)))
    assert mailbox.take() == []
