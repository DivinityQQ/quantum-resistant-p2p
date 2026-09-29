"""``qrp2p-cli``: run a node from a terminal.

```text
qrp2p-cli [--data-dir DIR] [--port N] [--listen HOST] [--no-mdns] [--name NAME]
          [--password-stdin] [--verbose]
```

The first run creates the vault; later runs unlock it. Then a prompt takes commands (``/help``)
and chat lines. ``--password-stdin`` reads the password from the first line of standard input,
for scripts; everything after it is read as commands.
"""

import argparse
import asyncio
import contextlib
import getpass
import logging
import logging.handlers
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Final, TextIO

from qrp2p.cli.commands import Cli
from qrp2p.services.events import NodeState
from qrp2p.services.node import Node
from qrp2p.services.paths import default_data_dir, ensure_private_dir
from qrp2p.services.vault import VaultInUseError

LOG_FILE: Final = "app.log"
LOG_BYTES: Final = 1_000_000
PROMPT: Final = "> "


class Terminal:
    """Reads lines and passwords without blocking the event loop, and prints.

    Each read runs in a daemon thread, so a pending read never keeps the process alive at exit.
    """

    def __init__(self, stdin: TextIO, stdout: TextIO, *, password_from_stdin: bool) -> None:
        self._in = stdin
        self._out = stdout
        self.interactive = stdin.isatty() and not password_from_stdin
        self._reading = False

    def print(self, text: str) -> None:
        """Print a message; re-show the prompt if the user is typing."""
        if self._reading and self.interactive:
            self._out.write("\r")
        self._out.write(text + "\n")
        if self._reading and self.interactive:
            self._out.write(PROMPT)
        self._out.flush()

    async def line(self, prompt: str = PROMPT) -> str | None:
        """The next line, or ``None`` at end of input."""
        self._reading = True
        try:
            return await self._in_thread(lambda: self._read_line(prompt))
        finally:
            self._reading = False

    async def secret(self, prompt: str) -> str | None:
        """A password: without echo on a terminal, else the next line."""
        if self.interactive:
            return await self._in_thread(lambda: _getpass(prompt))
        return await self._in_thread(lambda: self._read_line(""))

    def _read_line(self, prompt: str) -> str | None:
        if self.interactive:
            try:
                return input(prompt)
            except EOFError:
                return None
        line = self._in.readline()
        return None if not line else line.rstrip("\r\n")

    @staticmethod
    async def _in_thread[T](read: Callable[[], T]) -> T:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[T] = loop.create_future()

        def work() -> None:
            try:
                result = read()
            except BaseException as error:  # noqa: BLE001  # handed to the loop
                loop.call_soon_threadsafe(_fail, future, error)
            else:
                loop.call_soon_threadsafe(_resolve, future, result)

        threading.Thread(target=work, name="qrp2p-input", daemon=True).start()
        return await future


def _getpass(prompt: str) -> str | None:
    try:
        return getpass.getpass(prompt)
    except EOFError:
        return None


def _resolve[T](future: asyncio.Future[T], value: T) -> None:
    if not future.done():
        future.set_result(value)


def _fail[T](future: asyncio.Future[T], error: BaseException) -> None:
    if not future.done():
        future.set_exception(error)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """The command line."""
    parser = argparse.ArgumentParser(
        prog="qrp2p-cli", description="QRP2P: LAN messenger with a hybrid post-quantum channel."
    )
    parser.add_argument("--data-dir", type=Path, help="data directory (default: per-user)")
    parser.add_argument("--port", type=int, help="listening port (default: setting, 47470)")
    parser.add_argument("--listen", metavar="HOST", help="listen on this address only")
    parser.add_argument("--no-mdns", action="store_true", help="no mDNS announce or discovery")
    parser.add_argument("--name", default="", help="display name for a new vault")
    parser.add_argument(
        "--password-stdin", action="store_true", help="read the password from standard input"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log to standard error")
    return parser.parse_args(argv)


def setup_logging(data_dir: Path, *, verbose: bool) -> None:
    """Diagnostics to ``app.log`` in the data directory (never secrets or message text)."""
    ensure_private_dir(data_dir)
    handler = logging.handlers.RotatingFileHandler(
        data_dir / LOG_FILE, maxBytes=LOG_BYTES, backupCount=1, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    logging.getLogger("zeroconf").setLevel(logging.WARNING)
    if verbose:
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
        root.addHandler(stream)


async def run(args: argparse.Namespace, terminal: Terminal) -> int:
    """Open the node, create or unlock the vault, then read commands until the end."""
    data_dir: Path = args.data_dir or default_data_dir()
    node = Node(data_dir, port=args.port, listen_host=args.listen, discovery=not args.no_mdns)
    try:
        state = await node.open()
    except VaultInUseError:
        terminal.print(f"Another QRP2P process is using {data_dir}.")
        return 1
    cli = Cli(node, terminal.print, terminal.secret)
    node.subscribe(cli.on_event)
    try:
        ready = (
            await cli.create_vault(args.name) if state is NodeState.NO_VAULT else await cli.unlock()
        )
        if not ready:
            terminal.print("Not unlocked; bye.")
            return 1
        while True:
            line = await terminal.line()
            if line is None or not await cli.handle(line):
                return 0
    finally:
        await node.close()


def set_up_stream(stream: TextIO | None) -> None:
    """Pipes and files carry UTF-8 on every OS; a terminal keeps its own encoding.

    Windows otherwise reads and writes pipes in the ANSI code page (cp1250, cp1252, …), which
    garbles "é" and turns bytes it lacks into lone surrogates. Input that is not valid text
    becomes U+FFFD, and a console that cannot show ✓ shows ? instead: neither is an error.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if stream is None or reconfigure is None:
        return
    if stream.isatty():
        reconfigure(errors="replace")
    else:
        reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    """The ``qrp2p-cli`` entry point."""
    args = parse_args(argv)
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        set_up_stream(stream)
    data_dir: Path = args.data_dir or default_data_dir()
    try:
        setup_logging(data_dir, verbose=args.verbose)
    except OSError as error:
        sys.stderr.write(f"Cannot use the data directory {data_dir}: {error.strerror or error}\n")
        return 1
    terminal = Terminal(sys.stdin, sys.stdout, password_from_stdin=args.password_stdin)
    with contextlib.suppress(KeyboardInterrupt):
        return asyncio.run(run(args, terminal))
    return 130


if __name__ == "__main__":
    sys.exit(main())
