"""The CLI's commands and its view of node events.

Plain lines are chat messages to the current conversation; lines starting with ``/`` are commands.
Contacts are named by list number, name or short ID; nearby peers, files, prompts and key
mismatches by the numbers the CLI shows.
"""

import asyncio
import contextlib
import logging
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from qrp2p.cli import render
from qrp2p.services.admission import PromptKind
from qrp2p.services.discovery import NearbyPeer
from qrp2p.services.events import (
    AdmissionPrompt,
    ConnectFailed,
    ContactsChanged,
    HistoryChanged,
    KeyMismatchDetected,
    NearbyChanged,
    NodeEvent,
    NodeState,
    Notice,
    PromptClosed,
    SessionEnded,
    SessionOpened,
    StateChanged,
)
from qrp2p.services.files import TransferDirection
from qrp2p.services.keychain import KeychainUnavailableError
from qrp2p.services.models import (
    Contact,
    Direction,
    FileStatus,
    HistoryEntry,
    MessageStatus,
    Retention,
    TrustState,
)
from qrp2p.services.node import Node, NodeError, profile_by_id, profile_by_name
from qrp2p.services.text import display_text
from qrp2p.services.vault import VaultError, WrongPasswordError

MIN_PASSWORD: Final = 8
TRACE_DEFAULT: Final = 20
MAX_SLEEP: Final = 86_400.0

_log = logging.getLogger(__name__)

type Output = Callable[[str], None]
type AskSecret = Callable[[str], Awaitable[str | None]]


class UsageError(Exception):
    """The command was used wrongly; the message says how to use it."""


@dataclass(frozen=True, slots=True)
class Command:
    """A slash command."""

    handler: Callable[[list[str]], Awaitable[None]]
    usage: str
    help: str


class Cli:
    """Commands over a :class:`Node`, printing through ``out``.

    Args:
        node: The node (already opened).
        out: Prints one message (may contain newlines).
        ask_secret: Reads a password without echo; ``None`` at end of input.
    """

    def __init__(self, node: Node, out: Output, ask_secret: AskSecret) -> None:
        self.node = node
        self.out = out
        self.ask_secret = ask_secret
        self.current: bytes | None = None
        self._nearby: list[NearbyPeer] = []
        self._tasks: set[asyncio.Task[None]] = set()
        self.commands: dict[str, Command] = {}
        self._register()

    # -- start ----------------------------------------------------------------------------------

    async def create_vault(self, display_name: str) -> bool:
        """Create the vault with a new password; ``False`` if the user gave up."""
        self.out("No vault here yet: creating one. Choose a password (at least 8 characters).")
        self.out("Deriving the key takes about a second on purpose: it slows down guessing.")
        for _ in range(3):
            first = await self.ask_secret("New password: ")
            if first is None:
                return False
            if len(first) < MIN_PASSWORD:
                self.out("Too short.")
                continue
            second = await self.ask_secret("Repeat password: ")
            if second != first:
                self.out("The passwords differ.")
                continue
            await self.node.create(first, display_name=display_name)
            self._welcome()
            return True
        return False

    async def unlock(self) -> bool:
        """Unlock with the device key if set up, else ask for the password (three tries)."""
        if await self.node.device_unlock_available():
            with contextlib.suppress(WrongPasswordError, KeychainUnavailableError):
                await self.node.unlock_with_device()
                self._welcome()
                return True
        for _ in range(3):
            password = await self.ask_secret("Password: ")
            if password is None:
                return False
            try:
                await self.node.unlock(password)
            except WrongPasswordError:
                self.out("Wrong password.")
                continue
            self._welcome()
            return True
        return False

    def _welcome(self) -> None:
        me = self.node.identity
        self.out(f"Unlocked. You are {me.short_id}; listening on port {self.node.port}.")
        self.out("Type /help for commands. Plain lines are chat messages to /chat's contact.")

    # -- dispatch -------------------------------------------------------------------------------

    async def handle(self, line: str) -> bool:  # noqa: PLR0911  # one exit per outcome
        """Run one input line; ``False`` means quit."""
        line = line.strip()
        if not line:
            return True
        self.node.touch()
        if not line.startswith("/"):
            await self._chat_line(line)
            return True
        try:
            words = shlex.split(line[1:])
        except ValueError:
            self.out("Unbalanced quotes.")
            return True
        if not words:
            return True
        name, args = words[0].lower(), words[1:]
        if name in {"quit", "exit", "q"}:
            return False
        command = self.commands.get(name)
        if command is None:
            self.out(f"Unknown command /{display_text(name)}. Try /help.")
            return True
        await self._run(name, command, args)
        return True

    async def _run(self, name: str, command: Command, args: list[str]) -> None:
        try:
            await command.handler(args)
        except UsageError as error:
            self.out(f"{error}\nUsage: /{name} {command.usage}".rstrip())
        except (NodeError, VaultError, KeychainUnavailableError) as error:
            self.out(f"Error: {display_text(str(error))}")  # may quote a contact's name
        except OSError as error:
            self.out(f"Error: {display_text(str(error.strerror or error))}")
        except Exception:  # noqa: BLE001  # a bug in one command must not stop the node
            _log.exception("command /%s failed", name)
            self.out(f"Internal error in /{name}; details are in app.log. Please report it.")

    async def _chat_line(self, text: str) -> None:
        if self.current is None:
            self.out("No conversation selected: /chat <contact> first (or /help).")
            return
        try:
            await self.node.send_chat(self.current, text)
        except NodeError as error:
            self.out(f"Error: {error}")
        except ValueError:
            self.out("That message is too long (16,000 bytes at most).")

    def _background(self, work: Awaitable[None]) -> None:
        async def run() -> None:
            try:
                await work
            except (NodeError, VaultError, OSError) as error:
                self.out(f"Error: {error}")

        task = asyncio.get_running_loop().create_task(run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # -- lookups --------------------------------------------------------------------------------

    def contact(self, ref: str) -> Contact:
        """A contact by list number, short ID (prefix) or name (unique prefix)."""
        contacts = self.node.contacts()
        if _is_number(ref) and 1 <= int(ref) <= len(contacts):
            return contacts[int(ref) - 1]
        wanted = ref.replace("-", "").upper()
        by_id = [c for c in contacts if c.short_id.replace("-", "").startswith(wanted)]
        if len(wanted) >= 4 and len(by_id) == 1:  # noqa: PLR2004
            return by_id[0]
        folded = ref.casefold()
        exact = [c for c in contacts if c.name.casefold() == folded]
        if len(exact) == 1:
            return exact[0]
        prefix = [c for c in contacts if c.name.casefold().startswith(folded)]
        if len(prefix) == 1:
            return prefix[0]
        raise UsageError(f"No single contact matches {display_text(ref)!r}; see /contacts.")

    def _contact_or_current(self, args: list[str]) -> Contact:
        if args:
            return self.contact(args[0])
        if self.current is None:
            raise UsageError("Which contact?")
        return self.node.contact(self.current)

    def _file_id(self, ref: str) -> bytes:
        transfers = self.node.transfers()
        if _is_number(ref) and 1 <= int(ref) <= len(transfers):
            return transfers[int(ref) - 1].file_id
        raise UsageError("No such file; see /files.")

    # -- events ---------------------------------------------------------------------------------

    def on_event(self, event: NodeEvent) -> None:  # noqa: C901
        """Print what the user should see."""
        match event:
            case StateChanged(state=NodeState.LOCKED):
                self.current = None
                self.out("** Locked. /unlock to continue.")
            case SessionOpened():
                contact = self.node.contact(event.contact_id)
                tag = (
                    " [GLASS-BOX: keys and messages of this session are visible]"
                    if event.glass_box
                    else ""
                )
                self.out(f"** Connected to {render.name(contact.name)} ({event.profile}){tag}")
                if self.current is None:
                    self.current = event.contact_id
            case SessionEnded():
                reason = "connection lost" if event.reason is None else event.reason.label
                who = "by the peer" if event.by_peer else ""
                self.out(
                    f"** Disconnected from {self._name(event.contact_id)}: {reason} {who}".rstrip()
                )
            case ConnectFailed():
                reason = event.admit_reason or event.reason
                label = reason.label if reason is not None else event.detail
                self.out(f"** Connection to {display_text(event.target)} failed: {label}")
            case AdmissionPrompt():
                self._show_prompt(event)
            case PromptClosed(outcome="expired" | "withdrawn"):
                self.out(f"** Request {event.prompt_id} {event.outcome}.")
            case KeyMismatchDetected():
                self._show_mismatch(event)
            case HistoryChanged():
                self._show_history(event)
            case NearbyChanged():
                self._nearby = list(event.peers)
            case Notice(text=text):
                self.out(f"** {text}")
            case ContactsChanged() | StateChanged() | PromptClosed():
                pass

    def _name(self, contact_id: bytes) -> str:
        try:
            return render.name(self.node.contact(contact_id).name)
        except NodeError:
            return "a deleted contact"

    def _show_prompt(self, prompt: AdmissionPrompt) -> None:
        n = prompt.prompt_id
        if prompt.kind is PromptKind.CONTACT_REQUEST:
            self.out(
                f"** Contact request from {prompt.short_id} ({prompt.profile}). "
                f"Accept with /admit {n} <name>, refuse with /deny {n} (60 s)."
            )
            if prompt.glass_box_refused:
                self.out(
                    "   They asked for a glass-box session: that needs a pinned contact, so it will be a normal one."
                )
        else:
            self.out(
                f"** {render.name(prompt.name_hint)} ({prompt.short_id}) asks for a GLASS-BOX session. "
                "All keys and messages of this session will be visible to both of you and can be "
                f"saved. /admit {n} to agree, /deny {n} for a normal session (60 s)."
            )

    def _show_mismatch(self, event: KeyMismatchDetected) -> None:
        n = event.mismatch_id
        self.out(
            f"!! KEY MISMATCH for {self._name(event.contact_id)}: expected {event.expected_short_id}, "
            f"but {event.actual_short_id} answered.\n"
            "!! This can mean an attack (a man in the middle) or that they reinstalled. Nothing was "
            "revealed.\n"
            f"!! /keep {n} to cancel; /repin {n} only after confirming out of band, then /verify."
        )

    def _show_history(self, event: HistoryChanged) -> None:
        entry = event.entry
        try:
            contact = self.node.contact(event.contact_id)
        except NodeError:
            return
        info = entry.file
        if info is not None:
            if event.progress is None:  # progress is shown by /files
                self._show_file(contact, entry)
            return
        if event.added and entry.direction is Direction.OUT:
            return  # the user just typed it
        if not event.added and entry.status in {MessageStatus.SENDING, MessageStatus.SENT}:
            return  # only delivery and failure are worth a line
        prefix = "" if event.contact_id == self.current else f"({render.name(contact.name)}) "
        self.out(f"{prefix}{render.entry_line(contact, entry)}")

    def _show_file(self, contact: Contact, entry: HistoryEntry) -> None:
        info = entry.file
        assert info is not None  # noqa: S101  # file entries carry file info
        if info.status is FileStatus.OFFERED and entry.direction is Direction.IN:
            n = next(
                (i for i, t in enumerate(self.node.transfers(), 1) if t.file_id == info.file_id),
                None,
            )
            self.out(
                f"** {render.name(contact.name)} offers {render.name(info.name)!r} "
                f"({render.size(info.size)}): /accept {n} or /decline {n}"
            )
            return
        self.out(render.entry_line(contact, entry))

    # -- commands -------------------------------------------------------------------------------

    def _register(self) -> None:
        table: list[tuple[str, Callable[[list[str]], Awaitable[None]], str, str]] = [
            ("help", self.cmd_help, "", "list commands"),
            ("whoami", self.cmd_whoami, "", "your short ID, port and data directory"),
            ("nearby", self.cmd_nearby, "", "peers announced on the LAN (mDNS)"),
            ("contacts", self.cmd_contacts, "", "your contacts"),
            (
                "connect",
                self.cmd_connect,
                "<contact|nearby N|host:port [name]> [--glass-box] [--profile NAME]",
                "open a session",
            ),
            ("disconnect", self.cmd_disconnect, "[contact]", "close a session"),
            ("chat", self.cmd_chat, "<contact>", "choose the conversation for plain lines"),
            ("msg", self.cmd_msg, "<contact> <text>", "send one message"),
            ("history", self.cmd_history, "[contact] [N]", "show the last N messages"),
            ("send", self.cmd_send, "[contact] <path>", "offer a file"),
            ("files", self.cmd_files, "", "transfers in progress and offers"),
            ("accept", self.cmd_accept, "<file N> [directory]", "accept a file offer"),
            ("decline", self.cmd_decline, "<file N>", "decline a file offer"),
            ("cancel", self.cmd_cancel, "<file N>", "cancel a transfer"),
            ("prompts", self.cmd_prompts, "", "requests that wait for you"),
            (
                "admit",
                self.cmd_admit,
                "<request N> [name]",
                "accept a contact or glass-box request",
            ),
            ("deny", self.cmd_deny, "<request N>", "refuse a request"),
            (
                "repin",
                self.cmd_repin,
                "<mismatch N>",
                "trust the new identity after a key mismatch",
            ),
            ("keep", self.cmd_keep, "<mismatch N>", "keep the old identity after a key mismatch"),
            ("verify", self.cmd_verify, "[contact]", "show the safety number to compare"),
            ("verified", self.cmd_verified, "[contact]", "mark as verified after comparing"),
            ("unverify", self.cmd_unverify, "[contact]", "back to pinned"),
            ("block", self.cmd_block, "<contact>", "block a contact"),
            ("unblock", self.cmd_unblock, "<contact>", "unblock (pinned again)"),
            ("rename", self.cmd_rename, "<contact> <name>", "rename a contact"),
            (
                "profile",
                self.cmd_profile,
                "<contact> <HYBRID-1|PQ-CNSA-1>",
                "the contact's profile",
            ),
            (
                "retention",
                self.cmd_retention,
                "<contact> <forever|30d|session>",
                "how long history is kept",
            ),
            (
                "autoaccept",
                self.cmd_autoaccept,
                "<contact> <off|SIZE>",
                "auto-accept files (verified only)",
            ),
            ("rekey", self.cmd_rekey, "[contact]", "post-quantum rekey now"),
            ("trace", self.cmd_trace, "[contact] [N]", "the session's last protocol events"),
            ("forget", self.cmd_forget, "<contact>", "delete the conversation history"),
            ("delete", self.cmd_delete, "<contact>", "delete the contact and history"),
            (
                "set",
                self.cmd_set,
                "<name|announce|autolock|downloads|profile|maxfile> <value>",
                "settings",
            ),
            ("settings", self.cmd_settings, "", "show settings"),
            ("passwd", self.cmd_passwd, "", "change the vault password"),
            (
                "remember",
                self.cmd_remember,
                "<on|off>",
                "unlock with the OS keychain on this device",
            ),
            ("lock", self.cmd_lock, "", "lock now"),
            ("unlock", self.cmd_unlock, "", "unlock"),
            ("sleep", self.cmd_sleep, "<seconds>", "wait (for scripts)"),
        ]
        self.commands = {name: Command(fn, usage, text) for name, fn, usage, text in table}

    async def cmd_help(self, _: list[str]) -> None:
        """``/help``."""
        width = max(len(n) for n in self.commands)
        lines = [f"  /{n:<{width}}  {c.help}" for n, c in self.commands.items()]
        self.out("\n".join(["Commands (/quit to leave):", *lines]))

    async def cmd_whoami(self, _: list[str]) -> None:
        """``/whoami``."""
        me = self.node.identity
        self.out(
            f"You are {me.short_id} (peer ID {me.peer_id.hex()[:32]}…)\n"
            f"Listening on port {self.node.port}; data in {self.node.data_dir}"
        )

    async def cmd_nearby(self, _: list[str]) -> None:
        """``/nearby``."""
        self._nearby = self.node.nearby()
        if not self._nearby:
            self.out("Nobody announced on the LAN (mDNS may be blocked: /connect host:port works).")
            return
        for i, peer in enumerate(self._nearby, 1):
            self.out(render.nearby_line(i, peer, self.node.contact_for_nearby(peer)))

    async def cmd_contacts(self, _: list[str]) -> None:
        """``/contacts``."""
        contacts = self.node.contacts()
        if not contacts:
            self.out("No contacts yet. /nearby, then /connect.")
            return
        for i, contact in enumerate(contacts, 1):
            session = self.node.session_info(contact.contact_id)
            detail = profile_by_id(contact.profile_id).name
            if session is not None and session.glass_box:
                detail += "  GLASS-BOX"
            self.out(render.contact_line(i, contact, online=session is not None, detail=detail))

    async def cmd_connect(self, args: list[str]) -> None:
        """``/connect``."""
        glass_box = "--glass-box" in args
        args = [a for a in args if a != "--glass-box"]
        profile = None
        if "--profile" in args:
            at = args.index("--profile")
            if at + 1 >= len(args):
                raise UsageError("--profile needs a name.")
            profile = profile_by_name(args[at + 1])
            del args[at : at + 2]
        if not args:
            raise UsageError("Connect to what?")
        target = args[0]
        if target == "nearby":
            if (
                len(args) < 2  # noqa: PLR2004  # "nearby" and a number
                or not _is_number(args[1])
                or not 1 <= int(args[1]) <= len(self._nearby)
            ):
                raise UsageError("Which nearby peer? See /nearby.")
            peer = self._nearby[int(args[1]) - 1]
            self.out(f"Connecting to {render.name(peer.label)}…")
            self._background(self._after(self.node.connect_nearby(peer)))
            return
        host_port = _host_port(target)
        if host_port is not None:
            if glass_box:
                raise UsageError("Glass-box needs a pinned contact; connect normally first.")
            host, port = host_port
            label = " ".join(args[1:])
            self.out(f"Connecting to {display_text(target)}…")
            self._background(
                self._after(self.node.connect_address(host, port, profile=profile, name=label))
            )
            return
        contact = self.contact(target)
        if profile is not None and profile.id != contact.profile_id:
            raise UsageError("Change the contact's profile with /profile first.")
        self.out(
            f"Connecting to {render.name(contact.name)}…"
            + (" (asking for glass-box)" if glass_box else "")
        )
        self._background(self.node.connect_contact(contact.contact_id, glass_box=glass_box))

    async def _after(self, connecting: Awaitable[bytes]) -> None:
        await connecting

    async def cmd_disconnect(self, args: list[str]) -> None:
        """``/disconnect``."""
        await self.node.disconnect(self._contact_or_current(args).contact_id)

    async def cmd_chat(self, args: list[str]) -> None:
        """``/chat``."""
        if not args:
            raise UsageError("Chat with whom?")
        contact = self.contact(args[0])
        self.current = contact.contact_id
        online = "online" if self.node.is_online(contact.contact_id) else "offline: /connect first"
        self.out(f"Chatting with {render.name(contact.name)} ({online}).")
        await self._print_history(contact, 10)

    async def cmd_msg(self, args: list[str]) -> None:
        """``/msg``."""
        if len(args) < 2:  # noqa: PLR2004
            raise UsageError("Send what to whom?")
        contact = self.contact(args[0])
        await self.node.send_chat(contact.contact_id, " ".join(args[1:]))

    async def cmd_history(self, args: list[str]) -> None:
        """``/history``."""
        count = 20
        if args and _is_number(args[-1]) and (len(args) > 1 or self.current is not None):
            count = int(args.pop())
        await self._print_history(self._contact_or_current(args), count)

    async def _print_history(self, contact: Contact, count: int) -> None:
        for entry in await self.node.history(contact.contact_id, count):
            self.out(render.entry_line(contact, entry))

    async def cmd_send(self, args: list[str]) -> None:
        """``/send``."""
        if not args:
            raise UsageError("Send which file?")
        contact = self._contact_or_current(args[:-1])
        path = Path(args[-1]).expanduser()  # noqa: ASYNC240  # reads $HOME, no disk access
        entry = await self.node.send_file(contact.contact_id, path)
        info = entry.file
        assert info is not None  # noqa: S101
        self.out(
            f"Offered {render.name(info.name)!r} ({render.size(info.size)}); waiting for them to accept."
        )

    async def cmd_files(self, _: list[str]) -> None:
        """``/files``."""
        transfers = self.node.transfers()
        if not transfers:
            self.out("No transfers.")
            return
        for i, t in enumerate(transfers, 1):
            arrow = "→" if t.direction is TransferDirection.OUT else "←"
            percent = f"{100 * t.transferred // t.size}%" if t.size else "100%"
            self.out(
                f"{i:>3}. {arrow} {render.name(t.name)!r} {render.size(t.size)} {t.status.value} {percent}"
            )

    async def cmd_accept(self, args: list[str]) -> None:
        """``/accept``."""
        if not args:
            raise UsageError("Accept which file?")
        directory = Path(args[1]).expanduser() if len(args) > 1 else None  # noqa: ASYNC240
        await self.node.accept_file(self._file_id(args[0]), directory)
        self.out(f"Receiving into {directory or self.node.downloads_dir()}.")

    async def cmd_decline(self, args: list[str]) -> None:
        """``/decline``."""
        if not args:
            raise UsageError("Decline which file?")
        await self.node.decline_file(self._file_id(args[0]))

    async def cmd_cancel(self, args: list[str]) -> None:
        """``/cancel``."""
        if not args:
            raise UsageError("Cancel which file?")
        await self.node.cancel_file(self._file_id(args[0]))
        self.out("Cancelled.")

    async def cmd_prompts(self, _: list[str]) -> None:
        """``/prompts``."""
        prompts = self.node.pending_prompts()
        if not prompts:
            self.out("Nothing waits for you.")
        for prompt in prompts:
            self._show_prompt(prompt)

    async def cmd_admit(self, args: list[str]) -> None:
        """``/admit``."""
        if not args or not _is_number(args[0]):
            raise UsageError("Admit which request? See /prompts.")
        await self.node.answer_prompt(int(args[0]), accept=True, name=" ".join(args[1:]))

    async def cmd_deny(self, args: list[str]) -> None:
        """``/deny``."""
        if not args or not _is_number(args[0]):
            raise UsageError("Deny which request? See /prompts.")
        await self.node.answer_prompt(int(args[0]), accept=False)

    async def cmd_repin(self, args: list[str]) -> None:
        """``/repin``."""
        if not args or not _is_number(args[0]):
            raise UsageError("Which mismatch?")
        await self.node.resolve_mismatch(int(args[0]), repin=True)
        self.out(
            "Re-pinned to the new identity (pinned, not verified). Compare /verify out of band."
        )

    async def cmd_keep(self, args: list[str]) -> None:
        """``/keep``."""
        if not args or not _is_number(args[0]):
            raise UsageError("Which mismatch?")
        await self.node.resolve_mismatch(int(args[0]), repin=False)
        self.out("Kept the old identity.")

    async def cmd_verify(self, args: list[str]) -> None:
        """``/verify``."""
        contact = self._contact_or_current(args)
        grid = render.safety_grid(self.node.safety_number(contact.contact_id))
        self.out(
            f"Safety number with {render.name(contact.name)} ({contact.short_id}):\n{grid}\n"
            "Compare it with theirs in person or on a call. If it matches: /verified "
            f"{render.name(contact.name)}"
        )

    async def cmd_verified(self, args: list[str]) -> None:
        """``/verified``."""
        contact = await self.node.set_trust(
            self._contact_or_current(args).contact_id, TrustState.VERIFIED
        )
        self.out(f"{render.name(contact.name)} is now verified.")

    async def cmd_unverify(self, args: list[str]) -> None:
        """``/unverify``."""
        await self.node.set_trust(self._contact_or_current(args).contact_id, TrustState.PINNED)

    async def cmd_block(self, args: list[str]) -> None:
        """``/block``."""
        if not args:
            raise UsageError("Block whom?")
        await self.node.set_trust(self.contact(args[0]).contact_id, TrustState.BLOCKED)
        self.out("Blocked.")

    async def cmd_unblock(self, args: list[str]) -> None:
        """``/unblock``."""
        if not args:
            raise UsageError("Unblock whom?")
        await self.node.set_trust(self.contact(args[0]).contact_id, TrustState.PINNED)

    async def cmd_rename(self, args: list[str]) -> None:
        """``/rename``."""
        if len(args) < 2:  # noqa: PLR2004
            raise UsageError("Rename whom to what?")
        await self.node.update_contact(self.contact(args[0]).contact_id, name=" ".join(args[1:]))

    async def cmd_profile(self, args: list[str]) -> None:
        """``/profile``."""
        if len(args) != 2:  # noqa: PLR2004
            raise UsageError("Which contact and profile?")
        profile = profile_by_name(args[1])
        await self.node.update_contact(self.contact(args[0]).contact_id, profile_id=profile.id)
        self.out(f"Sessions with them now use {profile.name}; both sides must agree.")

    async def cmd_retention(self, args: list[str]) -> None:
        """``/retention``."""
        if len(args) != 2:  # noqa: PLR2004
            raise UsageError("Which contact and retention?")
        try:
            retention = Retention(args[1].lower())
        except ValueError:
            raise UsageError("Retention is forever, 30d or session.") from None
        await self.node.update_contact(self.contact(args[0]).contact_id, retention=retention)

    async def cmd_autoaccept(self, args: list[str]) -> None:
        """``/autoaccept``."""
        if len(args) != 2:  # noqa: PLR2004
            raise UsageError("Which contact, and off or a size?")
        contact = self.contact(args[0])
        if args[1].lower() == "off":
            await self.node.update_contact(contact.contact_id, auto_accept_files=False)
            return
        try:
            limit = render.parse_size(args[1])
        except ValueError:
            raise UsageError("Give a size such as 10M.") from None
        await self.node.update_contact(
            contact.contact_id, auto_accept_files=True, auto_accept_limit=limit
        )

    async def cmd_rekey(self, args: list[str]) -> None:
        """``/rekey``."""
        await self.node.rekey(self._contact_or_current(args).contact_id)
        self.out("Rekey started.")

    async def cmd_trace(self, args: list[str]) -> None:
        """``/trace``: the Inspector's raw material, public values only."""
        count = TRACE_DEFAULT
        if args and _is_number(args[-1]):
            count = int(args.pop())
        contact = self._contact_or_current(args)
        session = self.node.session_info(contact.contact_id)
        if session is None:
            self.out("Not connected.")
            return
        records = self.node.trace.events(session.id)[-count:]
        start = records[0].time if records else 0.0
        for record in records:
            self.out(f"  +{record.time - start:8.3f}s  {_trace_text(record.event)}")

    async def cmd_forget(self, args: list[str]) -> None:
        """``/forget``."""
        if not args:
            raise UsageError("Whose history?")
        contact = self.contact(args[0])
        answer = await self.ask_secret(
            f"Delete the history with {render.name(contact.name)}? Type yes: "
        )
        if answer == "yes":
            await self.node.delete_conversation(contact.contact_id)
            self.out("Deleted. Backups made earlier stay readable with the password of that time.")

    async def cmd_delete(self, args: list[str]) -> None:
        """``/delete``."""
        if not args:
            raise UsageError("Delete whom?")
        contact = self.contact(args[0])
        answer = await self.ask_secret(
            f"Delete {render.name(contact.name)} and the history? Type yes: "
        )
        if answer == "yes":
            await self.node.delete_contact(contact.contact_id)
            if self.current == contact.contact_id:
                self.current = None
            self.out("Deleted.")

    async def cmd_set(self, args: list[str]) -> None:
        """``/set``."""
        if len(args) < 2:  # noqa: PLR2004
            raise UsageError("Set what?")
        key, value = args[0].lower(), " ".join(args[1:])
        match key:
            case "name":
                await self.node.update_settings(display_name=value)
            case "announce":
                await self.node.update_settings(
                    announce_name=value.lower() in {"on", "yes", "true"}
                )
            case "autolock":
                if not _is_number(value):
                    raise UsageError("Minutes, 0 to turn off.")
                await self.node.update_settings(auto_lock_minutes=int(value))
            case "downloads":
                downloads = Path(value).expanduser()  # noqa: ASYNC240  # no disk access
                await self.node.update_settings(downloads_dir=str(downloads))
            case "profile":
                await self.node.update_settings(default_profile=profile_by_name(value).id)
            case "maxfile":
                try:
                    await self.node.update_settings(max_file_size=render.parse_size(value))
                except ValueError:
                    raise UsageError("Give a size such as 4G.") from None
            case _:
                raise UsageError("Unknown setting.")
        self.out("Saved. (Name and announce changes apply at the next unlock.)")

    async def cmd_settings(self, _: list[str]) -> None:
        """``/settings``."""
        s = self.node.settings
        self.out(
            f"name: {render.name(s.display_name) or '(none)'}   announce: {'on' if s.announce_name else 'off'}\n"
            f"profile: {profile_by_id(s.default_profile).name}   autolock: {s.auto_lock_minutes} min\n"
            f"downloads: {self.node.downloads_dir()}   maxfile: {render.size(s.max_file_size)}"
        )

    async def cmd_passwd(self, _: list[str]) -> None:
        """``/passwd``."""
        old = await self.ask_secret("Current password: ")
        new = await self.ask_secret("New password: ")
        if old is None or new is None:
            return
        if len(new) < MIN_PASSWORD:
            self.out("Too short.")
            return
        if await self.ask_secret("Repeat new password: ") != new:
            self.out("The passwords differ.")
            return
        await self.node.change_password(old, new)
        self.out("Password changed; everything was re-encrypted.")

    async def cmd_remember(self, args: list[str]) -> None:
        """``/remember``."""
        if not args or args[0] not in {"on", "off"}:
            raise UsageError("on or off?")
        await self.node.set_device_unlock(enabled=args[0] == "on")
        self.out("Done.")

    async def cmd_lock(self, _: list[str]) -> None:
        """``/lock``."""
        await self.node.lock()

    async def cmd_unlock(self, _: list[str]) -> None:
        """``/unlock``."""
        if self.node.state is NodeState.UNLOCKED:
            self.out("Already unlocked.")
            return
        await self.unlock()

    async def cmd_sleep(self, args: list[str]) -> None:
        """``/sleep``."""
        try:
            seconds = float(args[0])
        except IndexError, ValueError:
            raise UsageError("How many seconds?") from None
        if not 0 <= seconds < MAX_SLEEP:
            raise UsageError(f"Between 0 and {MAX_SLEEP:.0f} seconds.")
        await asyncio.sleep(seconds)


def _is_number(text: str) -> bool:
    """Whether ``text`` is ASCII digits only.

    ``str.isdigit`` alone also accepts characters such as superscript two, which ``int`` refuses.
    """
    return text.isascii() and text.isdigit()


def _host_port(text: str) -> tuple[str, int] | None:
    """``host:port`` or ``[v6]:port``; ``None`` if ``text`` is not an address."""
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]:")
    else:
        host, sep, rest = text.rpartition(":")
    if not sep or not host or not _is_number(rest) or (":" in host and not text.startswith("[")):
        return None
    port = int(rest)
    if not 0 < port < 65536:  # noqa: PLR2004
        return None
    return host, port


def _trace_text(event: object) -> str:
    """One trace event as text: its type and public fields (bytes shortened)."""
    fields = getattr(event, "__slots__", ())
    parts: list[str] = []
    for field in fields:
        value = getattr(event, field)
        if isinstance(value, bytes):
            parts.append(f"{field}={value[:8].hex()}…({len(value)} B)")
        elif hasattr(value, "type") and hasattr(value, "body"):
            parts.append(f"{field}={value.type.name}({len(value.body)} B)")
        elif isinstance(value, tuple):
            parts.append(f"{field}=[{len(value)}]")  # pyright: ignore[reportUnknownArgumentType]
        else:
            parts.append(f"{field}={value}")
    return f"{type(event).__name__} " + " ".join(parts)
