"""mDNS (DESIGN §6.1): records are built and parsed strictly; real mDNS runs only when asked."""

import asyncio
import os
from types import SimpleNamespace
from typing import ClassVar, cast

import pytest
from zeroconf import IPVersion, NotRunningException, ServiceStateChange
from zeroconf.asyncio import AsyncServiceInfo

from qrp2p.services import discovery as discovery_module
from qrp2p.services.discovery import (
    MAX_ADDRESSES,
    MAX_LABEL_BYTES,
    SERVICE_TYPE,
    Discovery,
    LocalInterfaces,
    instance_name,
    local_addresses,
    local_interfaces,
    mdns_interfaces,
    parse_txt,
    rank_addresses,
    txt_properties,
)
from tests.services.support import until
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


# --- found by mutation testing of the services ----------------------------------------------------


def test_txt_profile_field_bounds() -> None:
    base = {b"v": b"2", b"id": b"00" * 8}
    assert parse_txt({**base, b"pf": b"ff"}) == (bytes(8), 255)
    assert parse_txt({**base, b"pf": b"a"}) == (bytes(8), 10)  # hex, not decimal
    assert parse_txt({**base, b"pf": b"abc"}) is None


def test_instance_name_cut() -> None:
    suffix = " (ABCD-EFGH)"
    budget = MAX_LABEL_BYTES - len(suffix)
    exact = "a" * budget
    assert instance_name(exact, "ABCD-EFGH") == exact + suffix
    assert instance_name("b" * 100, "ABCD-EFGH") == "b" * budget + suffix
    spaced = "c" * (budget - 1) + " " + "d" * 10  # the cut falls just after a space
    assert instance_name(spaced, "ABCD-EFGH") == "c" * (budget - 1) + suffix


@pytest.mark.parametrize(("port", "ok"), [(1, True), (65535, True), (0, False), (65536, False)])
def test_announced_port_bounds(port: int, ok: bool) -> None:
    name = f"Alice (ABCD-EFGH).{SERVICE_TYPE}"
    peer = discovery().peer_from_info(name, info(port=port, addresses=["192.0.2.7", "fe80::1%2"]))
    assert (peer is not None) is ok
    if peer is not None:
        assert peer.instance == name
        assert peer.addresses == ("192.0.2.7", "fe80::1%2")


class FakeZeroconf:
    """Stands in for AsyncZeroconf: records what discovery asks of it."""

    created: ClassVar[list[FakeZeroconf]] = []

    def __init__(self, interfaces: object = None, ip_version: object = None) -> None:
        self.interfaces = interfaces
        self.ip_version = ip_version
        self.zeroconf = object()
        self.registered: list[tuple[object, bool]] = []
        self.unregistered: list[object] = []
        self.closed = False
        FakeZeroconf.created.append(self)

    async def async_register_service(self, info: object, allow_name_change: bool = False) -> object:
        self.registered.append((info, allow_name_change))
        return asyncio.sleep(0)

    async def async_unregister_service(self, info: object) -> object:
        self.unregistered.append(info)
        return asyncio.sleep(0)

    async def async_close(self) -> None:
        self.closed = True


class FakeBrowser:
    last: FakeBrowser | None = None

    def __init__(self, zc: object, types: list[str], handlers: list[object]) -> None:
        self.zc = zc
        self.types = types
        self.handlers = handlers
        self.cancelled = False
        FakeBrowser.last = self

    async def async_cancel(self) -> None:
        self.cancelled = True


class FakeServiceInfo:
    """Registration records its arguments; resolving answers from RESOLVABLE."""

    RESOLVABLE: ClassVar[dict[str, tuple[dict[bytes, bytes | None], int, list[str]]]] = {}
    requests: ClassVar[list[tuple[object, object, str]]] = []
    hold: ClassVar[asyncio.Event | None] = None

    def __init__(self, type_: str, name: str, **kwargs: object) -> None:
        self.type_ = type_
        self.name = name
        self.kwargs = kwargs
        self.properties: dict[bytes, bytes | None] = {}
        self.port: int | None = None
        self._addresses: list[str] = []

    async def async_request(self, zc: object, timeout_ms: int) -> bool:
        self.requests.append((zc, timeout_ms, self.type_))
        if self.hold is not None:
            await self.hold.wait()
        found = self.RESOLVABLE.get(self.name)
        if found is None:
            return False
        self.properties, self.port, self._addresses = found
        return True

    def parsed_scoped_addresses(self, version: object) -> list[str]:
        assert version is IPVersion.All
        return self._addresses


def adapter(index: int | None, *ips: tuple[object, int]) -> SimpleNamespace:
    """An ``ifaddr`` adapter: ``(address, prefix length)`` pairs; IPv6 as ``(addr, 0, scope)``."""
    return SimpleNamespace(
        index=index, ips=[SimpleNamespace(ip=ip, network_prefix=prefix) for ip, prefix in ips]
    )


LAN = [
    adapter(1, ("127.0.0.1", 8), (("::1", 0, 0), 128)),
    adapter(2, ("192.168.1.5", 24), (("fe80::5", 0, 2), 64), (("2001:db8::5", 0, 0), 64)),
    adapter(3, ("172.17.0.1", 16)),
]
"""Loopback, a LAN interface and a Docker bridge."""


@pytest.fixture
def fake_zeroconf(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery_module.ifaddr, "get_adapters", lambda: LAN)
    FakeZeroconf.created.clear()
    FakeServiceInfo.RESOLVABLE.clear()
    FakeServiceInfo.requests.clear()
    FakeServiceInfo.hold = None
    monkeypatch.setattr(discovery_module, "AsyncZeroconf", FakeZeroconf)
    monkeypatch.setattr(discovery_module, "AsyncServiceBrowser", FakeBrowser)
    monkeypatch.setattr(discovery_module, "AsyncServiceInfo", FakeServiceInfo)


def change(name: str, state: ServiceStateChange, service_type: str = SERVICE_TYPE) -> None:
    browser = FakeBrowser.last
    assert browser is not None
    (handler,) = browser.handlers
    handler(zeroconf=None, service_type=service_type, name=name, state_change=state)  # type: ignore[operator]


@pytest.mark.usefixtures("fake_zeroconf")
async def test_announce_browse_and_stop() -> None:
    changes: list[int] = []
    node = Discovery(on_change=lambda: changes.append(1), own_id_hint=b"\x00" * 8)
    await node.start(
        instance="Alice (ABCD-EFGH)",
        port=47470,
        peer_id=PEER_ID,
        profiles=3,
        addresses=["192.0.2.1"],
    )
    await node.start(instance="again", port=1, peer_id=PEER_ID, profiles=3)  # no-op
    (zc,) = FakeZeroconf.created
    ((registered, rename_allowed),) = zc.registered
    assert isinstance(registered, FakeServiceInfo)
    assert rename_allowed
    assert (registered.type_, registered.name) == (
        SERVICE_TYPE,
        f"Alice (ABCD-EFGH).{SERVICE_TYPE}",
    )
    assert zc.ip_version is IPVersion.All
    assert registered.kwargs["port"] == 47470
    assert registered.kwargs["properties"] == txt_properties(PEER_ID, 3)
    assert registered.kwargs["parsed_addresses"] == ["192.0.2.1"]
    assert registered.kwargs["server"] == f"qrp2p-{PEER_ID[:8].hex()}.local."
    assert FakeBrowser.last is not None
    assert FakeBrowser.last.types == [SERVICE_TYPE]
    assert node.running

    bob = f"Bob (XXXX-YYYY).{SERVICE_TYPE}"
    txt: dict[bytes, bytes | None] = {b"v": b"2", b"id": b"11" * 8, b"pf": b"1"}
    FakeServiceInfo.RESOLVABLE[bob] = (txt, 47471, ["192.0.2.2"])
    change(bob, ServiceStateChange.Added)
    await until(lambda: len(node.peers()) == 1)
    assert node.peers()[0].addresses == ("192.0.2.2",)
    assert changes == [1]
    change(bob, ServiceStateChange.Updated)  # the same record again: nothing changes
    await asyncio.sleep(0.01)
    assert changes == [1]
    change(bob, ServiceStateChange.Removed, service_type="_other._tcp.local.")  # not ours
    assert len(node.peers()) == 1
    change(f"Nobody.{SERVICE_TYPE}", ServiceStateChange.Added)  # does not resolve
    await asyncio.sleep(0.01)
    assert len(node.peers()) == 1
    change(bob, ServiceStateChange.Removed)
    assert node.peers() == []
    assert changes == [1, 1]

    change(bob, ServiceStateChange.Added)
    await until(lambda: len(node.peers()) == 1)
    await node.stop()
    assert zc.unregistered == [registered]
    assert zc.closed
    assert FakeBrowser.last.cancelled
    assert node.peers() == []
    assert not node.running
    await node.stop()  # twice is harmless


@pytest.mark.usefixtures("fake_zeroconf")
async def test_nothing_to_announce_still_browses() -> None:
    node = Discovery(on_change=lambda: None, own_id_hint=b"\x00" * 8, interfaces=["127.0.0.1"])
    await node.start(instance="x", port=1, peer_id=PEER_ID, profiles=1, addresses=[])
    (zc,) = FakeZeroconf.created
    assert zc.registered == []
    assert zc.interfaces == ["127.0.0.1"]
    assert zc.ip_version is IPVersion.All
    assert FakeBrowser.last is not None
    await node.stop()
    assert zc.unregistered == []


def test_local_addresses_skip_loopback_link_local_and_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def adapter(*ips: object) -> SimpleNamespace:
        return SimpleNamespace(ips=[SimpleNamespace(ip=ip) for ip in ips])

    adapters = [
        adapter("127.0.0.1", ("::1", 0, 0)),
        adapter("not an address", "192.168.1.5", ("fe80::1", 0, 2), ("2001:db8::5", 0, 0)),
        adapter("192.168.1.5", "169.254.3.4", "224.0.0.251"),
    ]
    monkeypatch.setattr(discovery_module.ifaddr, "get_adapters", lambda: adapters)
    assert local_addresses() == ["192.168.1.5", "2001:db8::5"]


def test_long_announced_labels_are_cut() -> None:
    name = "x" * 200 + f".{SERVICE_TYPE}"
    peer = discovery().peer_from_info(name, info())
    assert peer is not None
    assert len(peer.label) <= MAX_LABEL_BYTES


@pytest.mark.usefixtures("fake_zeroconf")
async def test_discovery_details(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery_module, "local_addresses", lambda: ["192.0.2.9"])
    node = Discovery(on_change=lambda: None, own_id_hint=b"\x00" * 8)
    await node.start(instance="me", port=1, peer_id=PEER_ID, profiles=1)
    (zc,) = FakeZeroconf.created
    ((registered, _),) = zc.registered
    assert isinstance(registered, FakeServiceInfo)
    assert registered.kwargs["parsed_addresses"] == ["192.0.2.9"]  # from the interfaces
    assert zc.interfaces == ["192.168.1.5", 2, "172.17.0.1"]  # all but loopback
    browser = FakeBrowser.last
    assert browser is not None
    assert browser.zc is zc.zeroconf
    for n, label in enumerate(["bravo", "Alpha", "charlie"]):
        name = f"{label}.{SERVICE_TYPE}"
        txt: dict[bytes, bytes | None] = {
            b"v": b"2",
            b"id": bytes([n + 1]).hex().encode() * 8,
            b"pf": b"1",
        }
        FakeServiceInfo.RESOLVABLE[name] = (txt, 47470, ["192.0.2.2"])
        change(name, ServiceStateChange.Added)
    await until(lambda: len(node.peers()) == 3)
    assert [p.label for p in node.peers()] == ["Alpha", "bravo", "charlie"]
    assert FakeServiceInfo.requests
    assert all(
        r == (zc.zeroconf, discovery_module.RESOLVE_TIMEOUT_MS, SERVICE_TYPE)
        for r in FakeServiceInfo.requests
    )
    await until(lambda: not node._tasks)  # finished resolves are forgotten
    change(f"never-seen.{SERVICE_TYPE}", ServiceStateChange.Removed)  # unknown: no error
    await node.stop()


@pytest.mark.usefixtures("fake_zeroconf")
async def test_a_resolve_finishing_after_stop_is_dropped() -> None:
    node = Discovery(on_change=lambda: None, own_id_hint=b"\x00" * 8)
    await node.start(instance="me", port=1, peer_id=PEER_ID, profiles=1, addresses=[])
    name = f"late.{SERVICE_TYPE}"
    txt: dict[bytes, bytes | None] = {b"v": b"2", b"id": b"22" * 8, b"pf": b"1"}
    FakeServiceInfo.RESOLVABLE[name] = (txt, 47470, ["192.0.2.2"])
    FakeServiceInfo.hold = asyncio.Event()
    change(name, ServiceStateChange.Added)
    await asyncio.sleep(0.01)
    tasks = set(node._tasks)
    node._zc, zc = None, node._zc  # stop() has begun: the node no longer runs
    FakeServiceInfo.hold.set()
    await asyncio.gather(*tasks, return_exceptions=True)
    assert node.peers() == []
    node._zc = zc
    await node.stop()


@pytest.mark.parametrize("error", [OSError, NotRunningException])
@pytest.mark.usefixtures("fake_zeroconf")
async def test_stop_survives_a_failed_unregister(error: type[Exception]) -> None:
    node = Discovery(on_change=lambda: None, own_id_hint=b"\x00" * 8)
    await node.start(instance="me", port=1, peer_id=PEER_ID, profiles=1, addresses=["192.0.2.1"])
    (zc,) = FakeZeroconf.created

    async def failing(_info: object) -> object:
        raise error

    zc.async_unregister_service = failing  # type: ignore[method-assign]
    await node.stop()
    assert zc.closed


# --- found on the LAN test --------------------------------------------------------------------------


def test_local_interfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery_module.ifaddr, "get_adapters", lambda: LAN)
    local = local_interfaces()
    assert {str(a) for a in local.addresses} == {
        "127.0.0.1",
        "::1",
        "192.168.1.5",
        "fe80::5",
        "2001:db8::5",
        "172.17.0.1",
    }
    assert [str(n) for n in local.networks] == [
        "192.168.1.0/24",
        "2001:db8::/64",
        "172.17.0.0/16",
    ]  # no loopback or link-local subnets


def test_mdns_skips_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    unindexed = adapter(None, (("2001:db8::9", 0, 0), 64))  # IPv6 needs an interface index
    duplicate = adapter(2, ("192.168.1.5", 24))
    monkeypatch.setattr(
        discovery_module.ifaddr, "get_adapters", lambda: [*LAN, unindexed, duplicate]
    )
    assert mdns_interfaces() == ["192.168.1.5", 2, "172.17.0.1"]


@pytest.mark.usefixtures("fake_zeroconf")
async def test_no_interface_for_mdns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery_module.ifaddr, "get_adapters", lambda: LAN[:1])
    node = Discovery(on_change=lambda: None, own_id_hint=b"\x00" * 8)
    with pytest.raises(OSError, match="no network interface"):
        await node.start(instance="x", port=1, peer_id=PEER_ID, profiles=1)
    assert FakeZeroconf.created == []
    assert not node.running


def test_addresses_are_ranked_for_dialling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery_module.ifaddr, "get_adapters", lambda: LAN)
    local = local_interfaces()
    announced = [
        "172.17.0.1",  # Docker: ours too
        "172.19.0.1",  # another bridge of theirs
        "100.65.110.41",  # a VPN
        "192.168.1.2",  # the LAN
        "2001:db8::2",  # the LAN, IPv6
        "fe80::2%2",
        "127.0.0.1",
        "::1",
        "0.0.0.0",  # noqa: S104
        "224.0.0.251",
        "not an address",
    ]
    far = ["172.19.0.1", "100.65.110.41", "fe80::2%2"]
    assert rank_addresses(announced, 47470, local, own_port=47470) == [
        "192.168.1.2",
        "2001:db8::2",
        *far,
    ]
    # At another port, our own address may be a second node on this machine: tried last.
    assert rank_addresses(announced, 47471, local, own_port=47470) == [
        "192.168.1.2",
        "2001:db8::2",
        *far,
        "172.17.0.1",
    ]
    assert rank_addresses(announced, 47470, local, own_port=None)[-1] == "172.17.0.1"
    nothing = LocalInterfaces(frozenset(), ())
    assert rank_addresses(["10.0.0.1", "10.0.0.2"], 1, nothing, own_port=1) == [
        "10.0.0.1",
        "10.0.0.2",
    ]  # the announced order when nothing is known


@pytest.mark.usefixtures("fake_zeroconf")
async def test_the_lan_address_survives_the_cap() -> None:
    node = Discovery(on_change=lambda: None, own_id_hint=b"\x00" * 8)
    await node.start(instance="me", port=47470, peer_id=PEER_ID, profiles=1)
    busy = [f"10.{n}.0.1" for n in range(MAX_ADDRESSES + 2)]  # many bridges, the LAN last
    name = f"Bob (XXXX-YYYY).{SERVICE_TYPE}"
    txt: dict[bytes, bytes | None] = {b"v": b"2", b"id": b"11" * 8, b"pf": b"1"}
    FakeServiceInfo.RESOLVABLE[name] = (txt, 47470, [*busy, "172.17.0.1", "192.168.1.2"])
    change(name, ServiceStateChange.Added)
    await until(lambda: len(node.peers()) == 1)
    (peer,) = node.peers()
    assert peer.addresses[0] == "192.168.1.2"
    assert len(peer.addresses) == MAX_ADDRESSES
    assert "172.17.0.1" not in peer.addresses  # our own, at our own port
    await node.stop()
