"""mDNS (DESIGN §6.1): records are built and parsed strictly; real mDNS runs only when asked."""

import asyncio
import os
from typing import cast

import pytest
from zeroconf.asyncio import AsyncServiceInfo

from qrp2p.services.discovery import (
    MAX_ADDRESSES,
    MAX_LABEL_BYTES,
    SERVICE_TYPE,
    Discovery,
    instance_name,
    parse_txt,
    txt_properties,
)
from tests.support import identity_from_label

PEER_ID = identity_from_label("alice").bundle.peer_id


def test_instance_name() -> None:
    assert instance_name("Alice", "ABCD-EFGH") == "Alice (ABCD-EFGH)"
    assert instance_name("", "ABCD-EFGH") == "QRP2P (ABCD-EFGH)"
    assert instance_name("a.b", "ABCD-EFGH") == "a\u2024b (ABCD-EFGH)"  # no dots in a DNS label
    long = instance_name("\u00e9" * 100, "ABCD-EFGH")
    assert len(long.encode("utf-8")) <= MAX_LABEL_BYTES
    assert long.endswith(" (ABCD-EFGH)")
    assert "\x1b" not in instance_name("\x1b[2J", "ABCD-EFGH")


def test_txt_round_trip() -> None:
    properties = txt_properties(PEER_ID, 0b11)
    assert properties == {"v": "2", "id": PEER_ID[:8].hex(), "pf": "3"}
    wire = {k.encode(): v.encode() for k, v in properties.items()}
    assert parse_txt(wire) == (PEER_ID[:8], 3)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize(
    "properties",
    [
        {},
        {b"v": b"1", b"id": b"00" * 8, b"pf": b"3"},
        {b"v": b"2", b"id": b"00" * 7, b"pf": b"3"},
        {b"v": b"2", b"id": b"zz" * 8, b"pf": b"3"},
        {b"v": b"2", b"id": b"00" * 8, b"pf": b"xyz"},
        {b"v": b"2", b"id": b"00" * 8, b"pf": None},
        {b"v": b"2", b"id": b"00" * 8, b"pf": b"\xff"},
    ],
)
def test_malformed_txt_is_ignored(properties: dict[bytes, bytes | None]) -> None:
    assert parse_txt(properties) is None


class FakeInfo:
    def __init__(
        self, properties: dict[bytes, bytes | None], port: int | None, addresses: list[str]
    ) -> None:
        self.properties = properties
        self.port = port
        self._addresses = addresses

    def parsed_scoped_addresses(self, _version: object) -> list[str]:
        return self._addresses


def discovery(own: bytes = b"\x00" * 8) -> Discovery:
    return Discovery(on_change=lambda: None, own_id_hint=own)


def info(
    port: int | None = 47470, addresses: list[str] | None = None, id_hint: bytes = PEER_ID[:8]
) -> AsyncServiceInfo:
    properties: dict[bytes, bytes | None] = {b"v": b"2", b"id": id_hint.hex().encode(), b"pf": b"1"}
    found = ["192.0.2.7"] if addresses is None else addresses
    return cast("AsyncServiceInfo", FakeInfo(properties, port, found))


def test_resolved_peer_is_validated() -> None:
    name = f"Alice (ABCD-EFGH).{SERVICE_TYPE}"
    peer = discovery().peer_from_info(name, info())
    assert peer is not None
    assert (peer.label, peer.id_hint, peer.profiles, peer.port) == (
        "Alice (ABCD-EFGH)",
        PEER_ID[:8],
        1,
        47470,
    )
    assert discovery().peer_from_info(name, info(port=0)) is None
    assert discovery().peer_from_info(name, info(port=None)) is None
    assert discovery().peer_from_info(name, info(addresses=[])) is None
    many = discovery().peer_from_info(name, info(addresses=[f"192.0.2.{n}" for n in range(20)]))
    assert many is not None
    assert len(many.addresses) == MAX_ADDRESSES


def test_our_own_announcement_is_skipped() -> None:
    assert discovery(own=PEER_ID[:8]).peer_from_info(f"x.{SERVICE_TYPE}", info()) is None


def test_hostile_instance_names_are_made_safe() -> None:
    peer = discovery().peer_from_info(f"\x1b]0;pwned\x07Eve.{SERVICE_TYPE}", info())
    assert peer is not None
    assert "\x1b" not in peer.label
    assert "\x07" not in peer.label


@pytest.mark.skipif(
    os.environ.get("QRP2P_TEST_MDNS") != "1",
    reason="real multicast; set QRP2P_TEST_MDNS=1 on a machine with a LAN interface",
)
async def test_two_nodes_find_each_other() -> None:
    alice, bob = identity_from_label("alice").bundle, identity_from_label("bob").bundle
    changed = asyncio.Event()
    a = Discovery(on_change=changed.set, own_id_hint=alice.peer_id[:8])
    b = Discovery(on_change=lambda: None, own_id_hint=bob.peer_id[:8])
    await a.start(instance="Alice (x)", port=47470, peer_id=alice.peer_id, profiles=3)
    await b.start(instance="Bob (y)", port=47471, peer_id=bob.peer_id, profiles=3)
    try:
        async with asyncio.timeout(10):
            while not a.peers():
                changed.clear()
                await changed.wait()
        (peer,) = a.peers()
        assert (peer.id_hint, peer.port) == (bob.peer_id[:8], 47471)
    finally:
        await a.stop()
        await b.stop()
