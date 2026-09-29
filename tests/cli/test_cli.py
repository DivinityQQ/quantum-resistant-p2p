"""The headless CLI: commands over real nodes, rendering, and two real processes."""

import asyncio
import os
import re
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from qrp2p.cli import commands, render
from qrp2p.cli.app import parse_args
from qrp2p.cli.commands import Cli, Command, _host_port, split_words
from qrp2p.services.events import SessionOpened
from qrp2p.services.models import FileStatus, TrustState
from qrp2p.services.vault import Vault
from tests.services.support import CHEAP_KDF, LOOPBACK, NodeHarness, until

ESC = "\x1b"


class Screen:
    """A CLI with its output captured and scripted answers to secret prompts."""

    def __init__(self, harness: NodeHarness) -> None:
        self.harness = harness
        self.lines: list[str] = []
        self.answers: list[str] = []
        self.cli = Cli(harness.node, self.lines.append, self._secret)
        harness.node.subscribe(self.cli.on_event)

    async def _secret(self, _prompt: str) -> str | None:
        return self.answers.pop(0) if self.answers else None

    async def run(self, line: str) -> None:
        assert await self.cli.handle(line)

    def text(self) -> str:
        return "\n".join(self.lines)

    async def shows(self, pattern: str) -> re.Match[str]:
        found: list[re.Match[str]] = []

        def check() -> bool:
            match = re.search(pattern, self.text())
            if match:
                found.append(match)
            return match is not None

        await until(check)
        return found[0]


@pytest.fixture
async def screens(tmp_path: Path) -> AsyncIterator[tuple[Screen, Screen]]:
    alice = Screen(await NodeHarness(tmp_path, "alice").start())
    bob = Screen(await NodeHarness(tmp_path, "bob").start())
    yield alice, bob
    await alice.harness.node.close()
    await bob.harness.node.close()


async def connected(alice: Screen, bob: Screen) -> None:
    await alice.run(f"/connect {LOOPBACK}:{bob.harness.port} Bob")
    number = (await bob.shows(r"/admit (\d+)")).group(1)
    await bob.run(f"/admit {number} Alice")
    await alice.shows("Connected to Bob")
    await bob.shows("Connected to Alice")


async def test_contact_request_and_chat(screens: tuple[Screen, Screen]) -> None:
    alice, bob = screens
    await connected(alice, bob)
    await alice.run(f"hello {ESC}[2J{ESC}]0;title\x07 bob\u202e")  # hostile control characters
    line = (await bob.shows(r"Alice: hello.*")).group(0)
    assert ESC not in bob.text()
    assert "\x07" not in bob.text()
    assert "\u202e" not in bob.text()
    assert line.startswith("Alice: hello \ufffd[2J")
    await alice.shows("✓✓")  # delivered


async def test_contact_management(screens: tuple[Screen, Screen]) -> None:
    alice, bob = screens
    await connected(alice, bob)
    await alice.run("/contacts")
    assert re.search(r"1\. ● Bob\s+\S{4}-\S{4}\s+pinned \(not verified\)", alice.text())
    await alice.run("/verify Bob")
    await bob.run("/verify 1")
    grid = re.compile(r"(\d{5} ){3}\d{5}")
    assert grid.findall(alice.text()) == grid.findall(bob.text())
    await alice.run("/verified bo")  # a unique name prefix
    assert alice.harness.node.contacts()[0].trust is TrustState.VERIFIED
    short = alice.harness.node.contacts()[0].short_id
    await alice.run(f"/rename {short} 'Bob B.'")
    assert alice.harness.node.contacts()[0].name == "Bob B."
    await alice.run("/profile 1 PQ-CNSA-1")
    await alice.run("/retention 1 30d")
    await alice.run("/autoaccept 1 10M")
    contact = alice.harness.node.contacts()[0]
    assert (contact.retention.value, contact.auto_accept_limit) == ("30d", 10 * 2**20)
    await alice.run("/nosuch")
    assert "Unknown command /nosuch" in alice.text()
    await alice.run("/rename")
    assert "Usage: /rename <contact> <name>" in alice.text()
    await alice.run("/chat zed")
    assert "No single contact matches 'zed'" in alice.text()


async def test_file_transfer_through_commands(
    tmp_path: Path, screens: tuple[Screen, Screen]
) -> None:
    alice, bob = screens
    await connected(alice, bob)
    source = tmp_path / "notes.txt"
    source.write_bytes(os.urandom(100_000))
    await alice.run(f"/send '{source}'")
    number = (await bob.shows(r"/accept (\d+)")).group(1)
    target = tmp_path / "incoming"
    await bob.run(f"/accept {number} '{target}'")
    await bob.shows("saved to")
    assert (target / "notes.txt").read_bytes() == source.read_bytes()
    await until(
        lambda: (
            any(t.status is FileStatus.COMPLETE for t in alice.harness.node.transfers())
            or not alice.harness.node.transfers()
        )
    )


async def test_trace_shows_public_events_only(screens: tuple[Screen, Screen]) -> None:
    alice, bob = screens
    await connected(alice, bob)
    await alice.run("/trace Bob 50")
    text = alice.text()
    assert "FrameTraced direction=out frame=HELLO" in text
    assert "SecretDerived label=ap_I[0]" in text


async def test_delete_needs_confirmation(screens: tuple[Screen, Screen]) -> None:
    alice, bob = screens
    await connected(alice, bob)
    alice.answers = ["no"]
    await alice.run("/delete Bob")
    assert len(alice.harness.node.contacts()) == 1
    alice.answers = ["yes"]
    await alice.run("/delete Bob")
    assert alice.harness.node.contacts() == []


async def test_lock_and_unlock(screens: tuple[Screen, Screen]) -> None:
    alice, _ = screens
    await alice.run("/lock")
    await alice.shows("Locked")
    await alice.run("/contacts")
    assert "Error: the vault is locked" in alice.text()
    alice.answers = ["wrong", "pw"]
    await alice.run("/unlock")
    assert "Wrong password." in alice.text()
    await alice.shows("Unlocked")


async def test_odd_numbers_are_usage_errors_not_crashes(screens: tuple[Screen, Screen]) -> None:
    alice, _ = screens
    for line in ("/admit \u00b2", "/deny \u0663", "/set autolock \u00b9", "/set maxfile inf"):
        await alice.run(line)
    assert "Internal error" not in alice.text()
    assert alice.text().count("Usage:") == 4


async def test_a_failing_command_does_not_stop_the_cli(
    screens: tuple[Screen, Screen], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, _ = screens

    async def broken(_: list[str]) -> None:
        raise ZeroDivisionError

    whoami = alice.cli.commands["whoami"]
    monkeypatch.setitem(alice.cli.commands, "whoami", Command(broken, whoami.usage, whoami.help))
    assert await alice.cli.handle("/whoami")
    assert "Internal error in /whoami" in alice.text()


async def test_quit(screens: tuple[Screen, Screen]) -> None:
    alice, _ = screens
    assert not await alice.cli.handle("/quit")


@pytest.mark.parametrize(
    ("text", "parsed"),
    [
        ("127.0.0.1:47470", ("127.0.0.1", 47470)),
        ("host.local:1", ("host.local", 1)),
        ("[fe80::1%eth0]:47470", ("fe80::1%eth0", 47470)),
        ("fe80::1:47470", None),  # IPv6 needs brackets
        ("bob", None),
        ("bob:0", None),
        ("bob:70000", None),
        (":47470", None),
    ],
)
def test_host_port(text: str, parsed: tuple[str, int] | None) -> None:
    assert _host_port(text) == parsed


@pytest.mark.parametrize(
    ("windows", "line", "words"),
    [
        (True, r"send bob C:\Users\me\a.txt", ["send", "bob", r"C:\Users\me\a.txt"]),
        (True, r'send bob "C:\My Files\a b.txt"', ["send", "bob", r"C:\My Files\a b.txt"]),
        (True, r"send bob \\server\share\a.txt", ["send", "bob", r"\\server\share\a.txt"]),
        (False, r"send bob my\ file.txt", ["send", "bob", "my file.txt"]),
        (False, "send bob 'a b.txt' #1", ["send", "bob", "a b.txt", "#1"]),
    ],
)
def test_split_words(
    monkeypatch: pytest.MonkeyPatch, windows: bool, line: str, words: list[str]
) -> None:
    monkeypatch.setattr(commands, "WINDOWS", windows)
    assert split_words(line) == words


async def test_windows_paths_reach_the_command(
    screens: tuple[Screen, Screen], monkeypatch: pytest.MonkeyPatch
) -> None:
    alice, _ = screens
    monkeypatch.setattr(commands, "WINDOWS", True)
    await alice.run(r"/set name A\B")
    await alice.run("/settings")
    assert r"name: A\B " in alice.text()


async def test_downloads_needs_a_full_path(screens: tuple[Screen, Screen], tmp_path: Path) -> None:
    alice, _ = screens
    await alice.run("/set downloads relative/dl")
    assert alice.lines[-1].startswith("Give the full path of a folder.")
    await alice.run(f'/set downloads "{tmp_path / "dl"}"')
    assert alice.lines[-1] == "Saved."
    assert alice.harness.node.downloads_dir() == tmp_path / "dl"


def test_sizes() -> None:
    assert render.parse_size("10M") == 10 * 2**20
    assert render.parse_size("1.5KiB") == 1536
    assert render.parse_size("4G") == 4 * 2**30
    assert render.parse_size("123") == 123
    assert render.size(3 * 2**20) == "3.0 MiB"
    with pytest.raises(ValueError, match=r"could not convert|invalid"):
        render.parse_size("lots")


def test_arguments() -> None:
    args = parse_args(["--data-dir", "/x", "--port", "5", "--no-mdns", "--password-stdin"])
    assert args.data_dir == Path("/x")
    assert (args.port, args.no_mdns, args.password_stdin) == (5, True, True)


# --- two real processes ---------------------------------------------------------------------------

# Not ASCII, so a pipe read in a Windows ANSI code page garbles them (and a byte cp1250 lacks, as
# in the emoji, becomes a lone surrogate).
PASSWORD = "pässwörd"
MESSAGE = "café ✓ 😀 across processes"
# What Windows gives a child process whose standard streams are pipes, imitated on every OS.
WINDOWS_PIPES = "cp1250:surrogateescape"


class Process:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.lines: list[str] = []

    async def start(self) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "qrp2p.cli.app",
            "--data-dir",
            str(self.directory),
            "--no-mdns",
            "--listen",
            LOOPBACK,
            "--port",
            "0",
            "--password-stdin",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=os.environ | {"PYTHONIOENCODING": WINDOWS_PIPES},
        )
        self._pump = asyncio.create_task(self._read())
        self.send(PASSWORD)

    async def _read(self) -> None:
        assert self.proc.stdout is not None
        while line := await self.proc.stdout.readline():
            self.lines.append(line.decode("utf-8", "replace").rstrip())

    def send(self, line: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((line + "\n").encode())

    async def shows(self, pattern: str) -> re.Match[str]:
        found: list[re.Match[str]] = []

        def check() -> bool:
            match = re.search(pattern, "\n".join(self.lines))
            if match:
                found.append(match)
            return match is not None

        await until(check, timeout=30)
        return found[0]


def cheap_vault(directory: Path) -> None:
    vault = Vault(directory, kdf=CHEAP_KDF)
    vault.create(PASSWORD)
    vault.close()


async def test_two_cli_processes(tmp_path: Path) -> None:
    alice, bob = Process(tmp_path / "alice"), Process(tmp_path / "bob")
    for process in (alice, bob):
        await asyncio.to_thread(cheap_vault, process.directory)
        await process.start()
    try:
        port = (await bob.shows(r"listening on port (\d+)")).group(1)
        await alice.shows("Unlocked")
        alice.send(f"/connect {LOOPBACK}:{port} Bob")
        number = (await bob.shows(r"/admit (\d+)")).group(1)
        bob.send(f"/admit {number} Alice")
        await alice.shows("Connected to Bob")
        alice.send(MESSAGE)
        await bob.shows(re.escape(f"Alice: {MESSAGE}"))
        for process in (alice, bob):
            process.send("/quit")
        codes = await asyncio.wait_for(
            asyncio.gather(alice.proc.wait(), bob.proc.wait()), timeout=30
        )
        assert codes == [0, 0]
        log = (tmp_path / "alice" / "app.log").read_text()
        assert "across processes" not in log  # diagnostics never hold message text
    finally:
        for process in (alice, bob):
            if process.proc.returncode is None:
                process.proc.kill()
                await process.proc.wait()


async def test_opened_event_selects_the_conversation(screens: tuple[Screen, Screen]) -> None:
    alice, bob = screens
    await connected(alice, bob)
    opened = alice.harness.of(SessionOpened)[0]
    assert alice.cli.current == opened.contact_id


async def test_set_says_when_a_change_applies(screens: tuple[Screen, Screen]) -> None:
    alice, _ = screens
    await alice.run("/set autolock 5")
    assert alice.lines[-1] == "Saved."
    await alice.run("/set name Alice B")
    assert alice.lines[-1] == "Saved; it applies at the next unlock."
    await alice.run("/set announce off")
    assert alice.lines[-1] == "Saved; it applies at the next unlock."
