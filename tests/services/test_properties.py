"""Property-based tests of what the services parse or produce from untrusted input."""

import asyncio
import contextlib
import hashlib
import ipaddress
import os
import tempfile
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import cast

import msgspec
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qrp2p.cli import render
from qrp2p.cli.commands import _host_port
from qrp2p.core.errors import FileCancelReason
from qrp2p.core.wire import (
    FileAccept,
    FileCancel,
    FileChunk,
    FileDecline,
    FileDone,
    FileOffer,
    FileProgress,
)
from qrp2p.services.discovery import (
    MAX_LABEL_BYTES,
    LocalInterfaces,
    instance_name,
    parse_txt,
    rank_addresses,
)
from qrp2p.services.files import (
    NAME_BUDGET,
    PART_SUFFIX,
    FileTransfers,
    PeerMisbehavedError,
    TransferMessage,
    sanitize_name,
)
from qrp2p.services.models import Contact, Direction, HistoryEntry, MessageKind
from qrp2p.services.session import Session
from qrp2p.services.text import display_text, is_unsafe_char
from qrp2p.services.vault import (
    Vault,
    VaultCorruptError,
    VaultFile,
    pad,
    unpad,
)
from tests.services.support import CHEAP_KDF
from tests.services.test_files import Hooks, StubSession
from tests.support import identity_from_label

# --- names and text -------------------------------------------------------------------------------

_FORBIDDEN = set('/\\:<>"|?*')
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    f"{d}{n}" for d in ("COM", "LPT") for n in (*"123456789", "\u00b9", "\u00b2", "\u00b3")
}


@given(st.text())
def test_sanitized_names_are_safe(name: str) -> None:
    safe = sanitize_name(name)
    assert safe
    assert not any(c in _FORBIDDEN or is_unsafe_char(c) for c in safe)
    assert not safe.startswith(".")
    assert not safe.endswith((".", " "))
    assert len(safe.encode("utf-8")) <= NAME_BUDGET
    assert safe.split(".", 1)[0].rstrip(" ").upper() not in _RESERVED
    assert unicodedata.is_normalized("NFC", safe)


@given(st.text())
def test_sanitizing_is_idempotent(name: str) -> None:
    once = sanitize_name(name)
    assert sanitize_name(once) == once


@given(st.text(), st.booleans(), st.none() | st.integers(min_value=1, max_value=50))
def test_display_text_never_passes_control_characters(
    text: str, newlines: bool, limit: int | None
) -> None:
    shown = display_text(text, keep_newlines=newlines, limit=limit)
    assert not any(is_unsafe_char(c) and not (newlines and c == "\n") for c in shown)
    if limit is not None:
        assert len(shown) <= limit


@given(st.text())
def test_instance_names_fit_one_dns_label(display: str) -> None:
    name = instance_name(display, "ABCD-EFGH")
    assert len(name.encode("utf-8")) <= MAX_LABEL_BYTES
    assert name.endswith(" (ABCD-EFGH)")
    assert "." not in name
    assert not any(is_unsafe_char(c) for c in name)


# --- small parsers --------------------------------------------------------------------------------


@given(st.dictionaries(st.binary(max_size=4), st.none() | st.binary(max_size=40)))
def test_txt_parsing_never_raises(properties: dict[bytes, bytes | None]) -> None:
    parsed = parse_txt(properties)
    if parsed is not None:
        id_hint, profiles = parsed
        assert len(id_hint) == 8
        assert 0 <= profiles <= 0xFF


ADDRESSES = st.lists(
    st.ip_addresses().map(str)
    | st.text(max_size=20)
    | st.builds(lambda a, n: f"{a}%{n}", st.ip_addresses(v=6).map(str), st.integers(0, 9)),
    max_size=12,
)
LOCAL = LocalInterfaces(
    frozenset({ipaddress.ip_address("192.168.1.5"), ipaddress.ip_address("172.17.0.1")}),
    (ipaddress.ip_network("192.168.1.0/24"), ipaddress.ip_network("2001:db8::/64")),
)


def rank_group(text: str) -> int:
    """0: a subnet we share; 1: elsewhere; 2: one of our own addresses."""
    address = ipaddress.ip_address(text.split("%", 1)[0])
    if address in LOCAL.addresses:
        return 2
    return 0 if any(address in network for network in LOCAL.networks) else 1


@given(ADDRESSES, st.integers(1, 65535), st.none() | st.integers(1, 65535))
def test_ranking_only_reorders_what_was_announced(
    announced: list[str], port: int, own_port: int | None
) -> None:
    ranked = rank_addresses(announced, port, LOCAL, own_port)
    remaining = list(announced)
    for text in ranked:  # every ranked address was announced (as often as it was)
        remaining.remove(text)
        address = ipaddress.ip_address(text.split("%", 1)[0])
        assert not address.is_loopback
        assert not address.is_unspecified
        assert not address.is_multicast
        assert not (port == own_port and address in LOCAL.addresses)
    groups = [rank_group(text) for text in ranked]
    assert groups == sorted(groups)  # a shared subnet, then the rest, then our own


@given(st.text())
def test_host_port_parsing_never_raises(text: str) -> None:
    parsed = _host_port(text)
    if parsed is not None:
        host, port = parsed
        assert host
        assert 0 < port < 65536


@given(st.text(max_size=20))
def test_size_parsing_is_total(text: str) -> None:
    try:
        size = render.parse_size(text)
    except ValueError:
        return
    assert size >= 0


# --- vault encodings ------------------------------------------------------------------------------


@given(st.binary(max_size=300))
def test_padding_round_trips(data: bytes) -> None:
    assert unpad(pad(data)) == data


@given(st.binary(max_size=300))
def test_unpadding_accepts_only_canonical_padding(data: bytes) -> None:
    try:
        plain = unpad(data)
    except VaultCorruptError:
        return
    assert pad(plain) == data  # exactly one padded form per plaintext


_hex = st.binary(max_size=40).map(bytes.hex)
_json_values = st.none() | st.booleans() | st.integers() | st.text(max_size=10) | _hex
_vault_docs = st.fixed_dictionaries(
    {
        "format": st.sampled_from(["qrp2p-vault", "other"]),
        "format_version": st.integers(-1, 3),
        "vault_id": _hex,
        "kdf": st.fixed_dictionaries(
            {
                "algorithm": st.sampled_from(["argon2id", "scrypt"]),
                "t": st.integers(-5, 2000),
                "m_kib": st.integers(-5, 2**33),
                "p": st.integers(-5, 100),
            }
        )
        | _json_values,
        "salt": _hex,
        "wrapped_dek": _hex,
    },
    optional={"device_kek": _hex | st.none(), "extra": _json_values},
)


@given(_vault_docs)
def test_vault_json_is_parsed_strictly(doc: dict[str, object]) -> None:
    try:
        parsed = VaultFile.from_json(msgspec.json.encode(doc))
    except VaultCorruptError:
        return
    kdf = parsed.header.kdf
    assert 1 <= kdf.t <= 1000
    assert 1 <= kdf.p <= 64
    assert 8 * kdf.p <= kdf.m_kib <= 4 * 2**20
    assert len(parsed.header.vault_id) == 16
    assert len(parsed.header.salt) == 16


@given(st.binary(max_size=500))
def test_vault_json_garbage_is_corrupt(data: bytes) -> None:
    try:
        VaultFile.from_json(data)
    except VaultCorruptError:
        return


# --- file transfer under arbitrary peer messages --------------------------------------------------

_FILE_IDS = [bytes([n]) * 16 for n in range(3)]
_file_ids = st.sampled_from(_FILE_IDS)
_peer_messages = st.one_of(
    st.builds(
        FileOffer,
        file_id=_file_ids,
        name=st.text(max_size=20),
        size=st.integers(0, 40_000),
        media_type=st.just("x/y"),
    ),
    st.builds(FileAccept, file_id=_file_ids),
    st.builds(FileDecline, file_id=_file_ids),
    st.builds(FileChunk, file_id=_file_ids, data=st.binary(max_size=20_000).map(bytes)),
    st.builds(FileProgress, file_id=_file_ids, received=st.integers(0, 50_000)),
    st.builds(FileDone, file_id=_file_ids, sha256=st.binary(min_size=32, max_size=32)),
    st.builds(FileCancel, file_id=_file_ids, reason=st.sampled_from(FileCancelReason)),
)
_actions = st.lists(
    st.one_of(
        _peer_messages.map(lambda m: ("peer", m)),
        _file_ids.map(lambda f: ("accept", f)),
        _file_ids.map(lambda f: ("decline", f)),
        _file_ids.map(lambda f: ("cancel", f)),
        _file_ids.map(lambda f: ("fill", f)),  # the peer sends exactly the rest of the file
        _file_ids.map(lambda f: ("done_ok", f)),  # ... and a file_done with the right hash
        _file_ids.map(lambda f: ("incoming", f)),  # a whole correct transfer to us
        _file_ids.map(lambda f: ("ack", f)),  # the peer acknowledges all we sent
        st.just(("outgoing", b"")),  # a whole correct transfer from us
        st.just(("offer", b"")),
    ),
    max_size=25,
)


class _Peer:
    """What the fuzzed peer has sent, so it can also behave correctly on request."""

    def __init__(self) -> None:
        self.sizes: dict[bytes, int] = {}
        self.data: dict[bytes, bytearray] = {}

    def saw(self, message: object) -> None:
        match message:
            case FileOffer(file_id=fid, size=size):
                self.sizes[fid] = size
                self.data[fid] = bytearray()
            case FileChunk(file_id=fid, data=data):
                self.data.setdefault(fid, bytearray()).extend(data)
            case _:
                pass

    def rest(self, fid: bytes) -> list[FileChunk]:
        missing = max(self.sizes.get(fid, 0) - len(self.data.get(fid, b"")), 0)
        body = os.urandom(missing)
        return [
            FileChunk(file_id=fid, data=body[i : i + 16_000]) for i in range(0, missing, 16_000)
        ]

    def done(self, fid: bytes) -> FileDone:
        return FileDone(file_id=fid, sha256=hashlib.sha256(self.data.get(fid, b"")).digest())


def _pool_ids() -> Callable[[int], bytes]:
    ids = iter(_FILE_IDS * 100)
    return lambda n: next(ids)[:n]


class _Driver:
    """Runs one fuzzed action sequence against a receiver and sender of one session."""

    def __init__(self, directory: Path, source: Path) -> None:
        self.directory = directory
        self.source = source
        self.transfers = FileTransfers(Hooks(), max_size=30_000, random_bytes=_pool_ids())
        self.session = cast("Session", StubSession())
        self.peer = _Peer()

    async def send(self, message: TransferMessage) -> None:
        self.peer.saw(message)
        await self.transfers.handle(self.session, message)

    async def run(self, actions: list[tuple[str, object]]) -> None:
        for kind, value in actions:
            try:
                await getattr(self, f"do_{kind}")(value)
            except PeerMisbehavedError:
                break  # the node closes the session here
            except KeyError:
                continue  # the user named a transfer that is not pending: a UI error
            await asyncio.sleep(0)
        await self.transfers.session_ended(self.session)
        for _ in range(20):  # let scheduled clean-ups run
            await asyncio.sleep(0.001)
        await asyncio.sleep(0.01)

    async def do_peer(self, message: object) -> None:
        await self.send(cast("TransferMessage", message))

    async def do_fill(self, fid: object) -> None:
        for chunk in self.peer.rest(cast("bytes", fid)):
            await self.send(chunk)

    async def do_done_ok(self, fid: object) -> None:
        await self.send(self.peer.done(cast("bytes", fid)))

    async def do_accept(self, fid: object) -> None:
        await self.transfers.accept(cast("bytes", fid), self.directory)

    async def do_decline(self, fid: object) -> None:
        self.transfers.decline(cast("bytes", fid))

    async def do_cancel(self, fid: object) -> None:
        await self.transfers.cancel(cast("bytes", fid))

    async def do_offer(self, _: object) -> None:
        self.transfers.offer(self.session, self.source)

    async def do_incoming(self, fid: object) -> None:
        file_id = cast("bytes", fid)
        await self.send(FileOffer(file_id=file_id, name="doc.txt", size=20_000, media_type="x/y"))
        await self.do_accept(file_id)
        await self.do_fill(file_id)
        await self.do_done_ok(file_id)

    async def do_outgoing(self, _: object) -> None:
        ours = self.transfers.offer(self.session, self.source)
        await self.send(FileAccept(file_id=ours.file_id))
        await self.do_ack(ours.file_id)

    async def do_ack(self, fid: object) -> None:
        await asyncio.sleep(0.005)  # let our sender run
        ours = self.transfers.get(cast("bytes", fid))
        if ours is not None:
            await self.send(FileProgress(file_id=ours.file_id, received=ours.transferred))


async def _drive(actions: list[tuple[str, object]], directory: Path, source: Path) -> None:
    await _Driver(directory, source).run(actions)


@settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(_actions)
def test_transfers_survive_any_message_sequence(actions: list[tuple[str, object]]) -> None:
    """Only a named protocol error, no stray files, nothing outside the download directory."""
    with tempfile.TemporaryDirectory() as root:
        directory = Path(root) / "downloads"
        source = Path(root) / "source.bin"
        source.write_bytes(os.urandom(1000))
        asyncio.run(_drive(actions, directory, source))
        assert {p.name for p in Path(root).iterdir()} <= {"downloads", "source.bin"}
        leftovers = list(directory.iterdir()) if directory.exists() else []
        assert not any(p.name.endswith(PART_SUFFIX) for p in leftovers)
        assert len(leftovers) <= len(_FILE_IDS)  # only completed, verified files remain


# --- vault rows that authenticate but do not parse ------------------------------------------------

_BUNDLE = identity_from_label("row-fuzz").bundle.encode()
_row_scalars = (
    st.none()
    | st.booleans()
    | st.integers(-(2**63), 2**64 - 1)  # what MessagePack can hold
    | st.floats(allow_nan=True)
    | st.text(max_size=12)
    | st.binary(max_size=40)
    | st.sampled_from(
        [_BUNDLE, "pinned", "verified", "blocked", "forever", "30d", "chat", "file", "in", "out"]
    )
)
_ROW_KEYS = [
    *("bundle", "name", "trust", "profile", "retention", "auto_accept_files", "created"),
    *("address_host", "address_port", "kind", "direction", "time", "message_id", "status"),
    *("text", "file", "glass_box", "display_name", "default_retention", "port"),
    *("file_id", "size", "media_type", "sha256", "path"),
]
_row_plaintexts = st.binary(max_size=120) | st.dictionaries(
    st.sampled_from(_ROW_KEYS),
    _row_scalars | st.dictionaries(st.sampled_from(_ROW_KEYS), _row_scalars, max_size=4),
    max_size=12,
).map(msgspec.msgpack.encode)


def test_rows_that_decrypt_but_do_not_parse_are_corrupt(tmp_path: Path) -> None:
    """Only VaultCorruptError, whatever an authenticated row contains (a bug or a newer app)."""
    vault = Vault(tmp_path / "vault", kdf=CHEAP_KDF)
    vault.create("pw")
    contact_id, conv_id = vault.new_contact_ids()
    vault.save_contact(
        Contact(
            contact_id=contact_id,
            conv_id=conv_id,
            bundle=identity_from_label("row-fuzz").bundle,
            name="x",
        )
    )
    entry_id = vault.new_entry_id()
    vault.add_entry(
        conv_id,
        HistoryEntry(entry_id=entry_id, kind=MessageKind.CHAT, direction=Direction.IN, time=1.0),
    )
    db = vault._state().db
    (settings_uid,) = db.execute("SELECT row_uid FROM settings").fetchone()
    targets = {
        "contacts": (vault._key("contacts"), contact_id, vault.contacts),
        "messages": (vault._conv_key(conv_id), entry_id, lambda: vault.history(conv_id)),
        "settings": (vault._key("settings"), settings_uid, vault.settings),
    }

    @settings(max_examples=300, deadline=None)
    @given(st.sampled_from(sorted(targets)), _row_plaintexts)
    def check(table: str, plaintext: bytes) -> None:
        key, uid, read = targets[table]
        value = vault._seal_row(key, table, uid, "data", plaintext)
        db.execute(f"UPDATE {table} SET data = ? WHERE row_uid = ?", (value, uid))  # noqa: S608
        with contextlib.suppress(VaultCorruptError):
            read()

    try:
        check()
    finally:
        vault.close()
