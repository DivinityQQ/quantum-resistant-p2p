"""Serve the lab's requests from a real :class:`~qrp2p.ui.labhost.LabHost` on the test thread.

The fake backend records each request with its op; :func:`serve` runs the lab's ops (and the
lab Inspector's tap ops) against the host, answers them, and delivers the tap's updates as the
services host would, so the QML and view models see the real lab without a services thread.
"""

from qrp2p.ui.host import LabOp, TapOp, error_info
from qrp2p.ui.labhost import LabHost
from tests.support import DeterministicRandom
from tests.ui.fakes import FakeBackend, Request


def lab_host() -> LabHost:
    return LabHost(wake=lambda: None, random_source=DeterministicRandom("lab"))


def _ours(request: Request) -> bool:
    op = request.op
    return isinstance(op, LabOp) or (isinstance(op, TapOp) and op.source == "lab")


def serve(backend: FakeBackend, host: LabHost, rounds: int = 10) -> None:
    """Answer every pending lab request (and those its answers cause), then flush the tap."""
    for _ in range(rounds):
        pending = [r for r in backend.requests if r.request_id not in backend.answered and _ours(r)]
        if not pending:
            break
        for request in pending:
            op = request.op
            try:
                if isinstance(op, LabOp):
                    value = op.run(host)
                else:
                    assert isinstance(op, TapOp)
                    value = op.run(host.tap)
            except Exception as error:  # noqa: BLE001  # becomes the reply, as on the host
                backend.reply(request, error=error_info(error))
            else:
                backend.reply(request, value)
            updates = host.tap.drain()
            if updates:
                backend.updates(*updates)
