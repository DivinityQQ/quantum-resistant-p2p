"""Serve the lab's requests from a real :class:`~qrp2p.ui.labhost.LabHost` on the test thread.

The fake backend records each request with its op; :func:`serve` runs the lab's ops (and the
lab Inspector's tap ops, and the recording ops) against the host and an in-memory recording
store, answers them, and delivers the tap's updates as the services host would, so the QML and
view models see the real lab without a services thread.
"""

import asyncio
import inspect
import secrets
from typing import cast

from qrp2p.lab.recording import LabRecording, Meta, Recording, RecordingError, decode, encode
from qrp2p.lab.solo import LabRun, lab_profile
from qrp2p.services.node import Node
from qrp2p.services.recordings import RecordingInfo
from qrp2p.ui.host import LabOp, TapOp, error_info
from qrp2p.ui.labhost import LabHost
from tests.support import DeterministicRandom
from tests.ui.fakes import FakeBackend, Request

RECORDING_OPS = frozenset({"recordings", "delete_recording", "save_session_recording"})


class Recordings:
    """The node's recording methods, in memory; every recording goes through the codec."""

    def __init__(self) -> None:
        self.saved: dict[str, bytes] = {}
        self.clock = 1_800_000_000.0

    async def save_lab_recording(self, title: str, run: LabRun) -> RecordingInfo:
        meta = Meta(title=title, created=self.clock, profile=lab_profile(run.profile).name)
        return self.add(LabRecording(meta=meta, run=run))

    def add(self, recording: Recording) -> RecordingInfo:
        file_id = secrets.token_hex(16)
        self.saved[file_id] = encode(recording)
        return self.info(file_id)

    def info(self, file_id: str) -> RecordingInfo:
        recording = decode(self.saved[file_id])
        kind = "lab" if isinstance(recording, LabRecording) else "glass_box"
        meta = recording.meta
        size = len(self.saved[file_id])
        return RecordingInfo(file_id, meta.title, kind, meta.profile, meta.created, size)

    async def recordings(self) -> list[RecordingInfo]:
        return [self.info(f) for f in reversed(self.saved)]

    async def open_recording(self, file_id: str) -> Recording:
        if file_id not in self.saved:
            msg = "that recording no longer exists"
            raise RecordingError(msg)
        return decode(self.saved[file_id])

    async def delete_recording(self, file_id: str) -> None:
        self.saved.pop(file_id, None)

    async def save_session_recording(self, session_id: int, title: str) -> RecordingInfo:
        del session_id, title
        msg = "only a glass-box session can be saved: a normal session reveals nothing"
        raise RecordingError(msg)


def lab_host(store: Recordings | None = None) -> LabHost:
    return LabHost(
        wake=lambda: None,
        random_source=DeterministicRandom("lab"),
        node=cast("Node", store or Recordings()),
    )


def _ours(request: Request) -> bool:
    op = request.op
    if isinstance(op, LabOp) or (isinstance(op, TapOp) and op.source == "lab"):
        return True
    return request.name in RECORDING_OPS


def _run(request: Request, host: LabHost) -> object:
    op = request.op
    if isinstance(op, LabOp):
        value = op.run(host)
    elif isinstance(op, TapOp):
        value = op.run(host.tap)
    else:
        assert op is not None
        value = op(cast("Node", host._node))  # the recording ops ask the node
    if inspect.isawaitable(value):
        value = asyncio.run(_awaited(value))
    return value


async def _awaited(value: object) -> object:
    return await value  # type: ignore[misc]


def serve(backend: FakeBackend, host: LabHost, rounds: int = 10) -> None:
    """Answer every pending lab request (and those its answers cause), then flush the tap."""
    for _ in range(rounds):
        pending = [r for r in backend.requests if r.request_id not in backend.answered and _ours(r)]
        if not pending:
            break
        for request in pending:
            try:
                value = _run(request, host)
            except Exception as error:  # noqa: BLE001  # becomes the reply, as on the host
                backend.reply(request, error=error_info(error))
            else:
                backend.reply(request, value)
            updates = host.tap.drain()
            if updates:
                backend.updates(*updates)
