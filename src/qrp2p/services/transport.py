"""TCP transport: frame streams, the listener and outgoing connections (DESIGN §6.2, §6.3).

A :class:`FrameStream` reads exactly one frame at a time: the 5-byte header first, whose length is
checked by the core (:func:`~qrp2p.core.wire.parse_header`) **before** the body is read, so a peer
can make us hold at most one maximum-size frame. The stream reader's buffer limit equals the
maximum frame.

Sessions (``qrp2p.services.session``) own the streams; this module knows nothing about the
protocol beyond frame boundaries.
"""

import asyncio
import contextlib
import errno
import logging
from collections.abc import Awaitable, Callable
from typing import Final

from qrp2p.core.crypto.profiles import FRAME_HEADER_LEN, MAX_FRAME_BODY
from qrp2p.core.wire import Frame, parse_header
from qrp2p.services.limits import CONNECT_TIMEOUT

STREAM_LIMIT: Final = FRAME_HEADER_LEN + MAX_FRAME_BODY
"""The stream reader's buffer limit: one maximum-size frame (DESIGN §6.3)."""
PORT_ATTEMPTS: Final = 16
"""Ports tried, starting at the configured one, when it is busy (DESIGN §6.2)."""
_PORT_BUSY: Final = frozenset(
    code
    for name in ("EADDRINUSE", "EACCES", "WSAEADDRINUSE", "WSAEACCES")
    if (code := getattr(errno, name, None)) is not None
)
"""In use, or reserved (Windows reserves port ranges for Hyper-V and reports them as EACCES)."""

_log = logging.getLogger(__name__)


class ConnectionLost(Exception):  # noqa: N818  # an event, not a programming error
    """The TCP connection ended or failed outside a frame boundary."""


class ConnectFailed(Exception):  # noqa: N818
    """No TCP connection could be opened to any address of the target."""


class FrameStream:
    """One TCP connection, read and written as frames.

    Args:
        reader: The connection's reader, created with ``limit=STREAM_LIMIT``.
        writer: The connection's writer.
    """

    __slots__ = ("_reader", "_source", "_writer")

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        match writer.get_extra_info("peername"):
            case (str() as host, *_):
                self._source = host
            case _:
                self._source = "unknown"

    @property
    def source(self) -> str:
        """The peer's address (without port), used for per-source limits and logs."""
        return self._source

    async def read_frame(self) -> Frame | None:
        """Read one frame; ``None`` when the peer closed the connection between frames.

        Raises:
            ProtocolError: ``oversize`` or ``schema_error`` from the header, before the body is read.
            ConnectionLost: The connection failed, or ended inside a frame.
        """
        try:
            header = await self._reader.readexactly(FRAME_HEADER_LEN)
        except asyncio.IncompleteReadError as error:
            if not error.partial:
                return None
            raise ConnectionLost from None
        except OSError:
            raise ConnectionLost from None
        frame_type, length = parse_header(header)
        try:
            body = await self._reader.readexactly(length)
        except asyncio.IncompleteReadError, OSError:
            raise ConnectionLost from None
        return Frame(frame_type, body)

    def write(self, frame: Frame) -> None:
        """Buffer ``frame`` for sending; call :meth:`drain` to wait until it is handed to TCP."""
        self._writer.write(frame.encode())

    async def drain(self) -> None:
        """Wait until the write buffer is below its high-water mark.

        Raises:
            ConnectionLost: The connection failed.
        """
        try:
            await self._writer.drain()
        except OSError:
            raise ConnectionLost from None

    def abort(self) -> None:
        """Drop the connection now, discarding anything unsent."""
        self._writer.transport.abort()

    async def close(self) -> None:
        """Close after flushing what is buffered; never raises."""
        self._writer.close()
        with contextlib.suppress(OSError):
            await self._writer.wait_closed()


async def open_stream(host: str, port: int, *, timeout: float = CONNECT_TIMEOUT) -> FrameStream:  # noqa: ASYNC109  # one bound per address
    """Open a TCP connection to ``host:port``.

    Raises:
        ConnectFailed: The connection was refused, timed out or could not be routed.
    """
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port, limit=STREAM_LIMIT)
    except OSError, TimeoutError:
        raise ConnectFailed from None
    return FrameStream(reader, writer)


type StreamHandler = Callable[[FrameStream], Awaitable[None]]


class Listener:
    """The TCP server that accepts incoming sessions.

    Args:
        on_stream: Called with each accepted connection, in its own task. It owns the stream.
    """

    __slots__ = ("_on_stream", "_port", "_server")

    def __init__(self, on_stream: StreamHandler) -> None:
        self._on_stream = on_stream
        self._server: asyncio.Server | None = None
        self._port: int | None = None

    @property
    def port(self) -> int | None:
        """The port we listen on, while listening."""
        return self._port

    async def start(self, host: str | None, port: int) -> int:
        """Listen on ``host`` (``None``: every interface, IPv4 and IPv6) and return the port.

        When ``port`` is busy, the next ports are tried (DESIGN §6.2); ``0`` picks a free one.

        Raises:
            OSError: No port could be bound.
        """
        if self._server is not None:
            msg = "already listening"
            raise RuntimeError(msg)
        candidates = [0] if port == 0 else range(port, min(port + PORT_ATTEMPTS, 65536))
        last_error: OSError | None = None
        for candidate in candidates:
            try:
                server = await asyncio.start_server(
                    self._accept, host=host, port=candidate, limit=STREAM_LIMIT
                )
            except OSError as error:
                if error.errno not in _PORT_BUSY:
                    raise
                last_error = error
                continue
            self._server = server
            self._port = int(server.sockets[0].getsockname()[1])
            return self._port
        assert last_error is not None  # noqa: S101  # the loop ran at least once
        raise last_error

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await self._on_stream(FrameStream(reader, writer))

    async def close(self) -> None:
        """Stop accepting connections. Connections already accepted are not affected."""
        server, self._server, self._port = self._server, None, None
        if server is not None:
            server.close()  # closes the listening sockets; wait_closed() would wait for clients
