"""mDNS/DNS-SD announcement and browsing (DESIGN §6.1).

```text
service type   _qrp2p._tcp.local.
instance name  "<display name or QRP2P> (<short_id>)"
TXT            v=2  id=<hex of peer_id[0:8]>  pf=<hex bitmask: bit0 HYBRID-1, bit1 PQ-CNSA-1>
```

Everything learnt from mDNS is an unauthenticated hint: a peer is identified only by the bundle it
proves in a handshake. Records from the network are parsed strictly and bounded; names are shown
through :func:`~qrp2p.services.text.display_text`. Announcements stop while the app is locked.
"""

import asyncio
import contextlib
import errno
import ipaddress
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Final, cast

import ifaddr
from zeroconf import IPVersion, NotRunningException, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

from qrp2p.services.text import display_text

SERVICE_TYPE: Final = "_qrp2p._tcp.local."
TXT_VERSION: Final = "2"
ID_HINT_LEN: Final = 8
MAX_LABEL_BYTES: Final = 63
"""A DNS label, and so an instance name, is at most 63 bytes."""
MAX_ADDRESSES: Final = 8
RESOLVE_TIMEOUT_MS: Final = 3000
DEFAULT_NAME: Final = "QRP2P"

_log = logging.getLogger(__name__)

type _TwoStep = Callable[..., Awaitable[Awaitable[object]]]
"""zeroconf's (un)register: awaiting it returns a task that completes once announced."""
type _Address = ipaddress.IPv4Address | ipaddress.IPv6Address
type _Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True, slots=True)
class NearbyPeer:
    """A peer announced on the LAN. Every field is an unauthenticated hint."""

    instance: str
    """The full instance name (the key); show :attr:`label` instead."""
    label: str
    """The instance name without the service type, safe to display."""
    id_hint: bytes
    """``peer_id[0:8]``: matches a contact's pin only as a hint."""
    profiles: int
    addresses: tuple[str, ...]
    port: int


def instance_name(display_name: str, short_id: str) -> str:
    """``"<display name or QRP2P> (<short_id>)"``, cut to fit one DNS label."""
    suffix = f" ({short_id})"
    # A dot would split the DNS name; replace it before measuring (U+2024 takes 3 bytes).
    name = display_text(display_name).strip().replace(".", "\u2024") or DEFAULT_NAME
    budget = MAX_LABEL_BYTES - len(suffix.encode("utf-8"))
    encoded = name.encode("utf-8")
    if len(encoded) > budget:
        name = encoded[:budget].decode("utf-8", "ignore").rstrip() or DEFAULT_NAME
    return name + suffix


def txt_properties(peer_id: bytes, profiles: int) -> dict[str, str]:
    """The TXT record: version, ID hint and supported-profile bitmask."""
    return {"v": TXT_VERSION, "id": peer_id[:ID_HINT_LEN].hex(), "pf": f"{profiles:x}"}


def parse_txt(properties: dict[bytes, bytes | None]) -> tuple[bytes, int] | None:
    """Parse a TXT record strictly; ``None`` for anything that is not a v2 QRP2P record."""
    try:
        version = properties.get(b"v")
        id_hex = properties.get(b"id")
        pf_hex = properties.get(b"pf")
        if version != TXT_VERSION.encode() or id_hex is None or pf_hex is None:
            return None
        if len(id_hex) != 2 * ID_HINT_LEN or not 1 <= len(pf_hex) <= 2:  # noqa: PLR2004
            return None
        return bytes.fromhex(id_hex.decode("ascii")), int(pf_hex.decode("ascii"), 16)
    except ValueError:
        return None


def local_addresses() -> list[str]:
    """Addresses to announce: IPv4 and routable IPv6, no loopback or link-local."""
    found: list[str] = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            address = _parse(ip.ip if isinstance(ip.ip, str) else ip.ip[0])
            if address is None or address.is_loopback or address.is_link_local:
                continue
            if address.is_multicast or str(address) in found:
                continue
            found.append(str(address))
    return found


@dataclass(frozen=True, slots=True)
class LocalInterfaces:
    """This machine's addresses, and the subnets it is on (loopback and link-local left out)."""

    addresses: frozenset[_Address]
    networks: tuple[_Network, ...]


def local_interfaces() -> LocalInterfaces:
    """Read the interfaces now: they change as networks come and go."""
    addresses: set[_Address] = set()
    networks: list[_Network] = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            address = _parse(ip.ip if isinstance(ip.ip, str) else ip.ip[0])
            if address is None:
                continue
            addresses.add(address)
            if address.is_loopback or address.is_link_local:
                continue
            network = ipaddress.ip_network((address, ip.network_prefix), strict=False)
            if network not in networks:
                networks.append(network)
    return LocalInterfaces(frozenset(addresses), tuple(networks))


def rank_addresses(
    addresses: Iterable[str], port: int, local: LocalInterfaces, own_port: int | None
) -> list[str]:
    """A peer's announced addresses in the order to dial them (DESIGN §6.2).

    A peer announces every interface, including Docker bridges and VPNs that a dialler cannot
    reach; each such address would cost a connect timeout. Addresses on a subnet we share come
    first, then the rest, then our own addresses, each group in the order announced. Our own
    addresses at our own port can only reach ourselves (Docker gives many machines the same
    ``172.17.0.1``) and are dropped; at another port they may be a second node on this machine.
    Loopback, unspecified and multicast addresses are dropped too.
    """
    near: list[str] = []
    far: list[str] = []
    own: list[str] = []
    for text in addresses:
        address = _parse(text)
        if address is None or address.is_loopback or address.is_unspecified:
            continue
        if address.is_multicast or (port == own_port and address in local.addresses):
            continue
        if address in local.addresses:
            own.append(text)
        elif any(address in network for network in local.networks):
            near.append(text)
        else:
            far.append(text)
    return near + far + own


def mdns_interfaces() -> list[str | int]:
    """Where zeroconf listens: IPv4 addresses and IPv6 interface indexes, no loopback.

    zeroconf's own "all interfaces" includes IPv6 loopback, where sending fails at every start.
    """
    chosen: list[str | int] = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            address = _parse(ip.ip if isinstance(ip.ip, str) else ip.ip[0])
            if address is None or address.is_loopback:
                continue
            if isinstance(address, ipaddress.IPv4Address):
                if str(address) not in chosen:
                    chosen.append(str(address))
            elif adapter.index is not None and adapter.index not in chosen:
                chosen.append(adapter.index)
    return chosen


def _parse(text: str) -> _Address | None:
    """An address without its IPv6 scope, or ``None`` if it is not one."""
    try:
        return ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None


class Discovery:
    """Announce this node and track the peers announced on the LAN.

    Args:
        on_change: Called on the event loop whenever the set of nearby peers changes.
        own_id_hint: Our ``peer_id[0:8]``, so our own announcement is not listed.
        interfaces: Passed to zeroconf; by default every interface but loopback (tests use
            loopback only).
    """

    def __init__(
        self,
        *,
        on_change: Callable[[], None],
        own_id_hint: bytes,
        interfaces: list[str] | None = None,
    ) -> None:
        self._on_change = on_change
        self._own = own_id_hint
        self._interfaces = interfaces
        self._zc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._info: AsyncServiceInfo | None = None
        self._peers: dict[str, NearbyPeer] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._port: int | None = None

    @property
    def running(self) -> bool:
        """Whether discovery is active."""
        return self._zc is not None

    def peers(self) -> list[NearbyPeer]:
        """The peers currently announced, sorted by label."""
        return sorted(self._peers.values(), key=lambda p: p.label.casefold())

    async def start(
        self,
        *,
        instance: str,
        port: int,
        peer_id: bytes,
        profiles: int,
        addresses: list[str] | None = None,
    ) -> None:
        """Announce ``instance`` on ``port`` and start browsing.

        Raises:
            OSError: mDNS sockets could not be opened (the app still works by address).
        """
        if self._zc is not None:
            return
        interfaces = self._interfaces if self._interfaces is not None else mdns_interfaces()
        if not interfaces:
            raise OSError(errno.ENETDOWN, "no network interface for mDNS")
        zc = AsyncZeroconf(interfaces=interfaces, ip_version=IPVersion.All)
        self._zc = zc
        self._port = port
        announced = addresses if addresses is not None else local_addresses()
        if announced:
            info = AsyncServiceInfo(
                SERVICE_TYPE,
                f"{instance}.{SERVICE_TYPE}",
                port=port,
                properties=txt_properties(peer_id, profiles),
                server=f"qrp2p-{peer_id[:ID_HINT_LEN].hex()}.local.",
                parsed_addresses=announced,
            )
            # zeroconf returns a second awaitable that completes when the announcement is out.
            register = cast("_TwoStep", zc.async_register_service)  # pyright: ignore[reportUnknownMemberType]
            await (await register(info, allow_name_change=True))
            self._info = info
        else:
            _log.warning("no LAN address to announce; peers can still connect by address")
        self._browser = AsyncServiceBrowser(
            zc.zeroconf, [SERVICE_TYPE], handlers=[self._state_changed]
        )

    async def stop(self) -> None:
        """Stop announcing and browsing; forget every peer."""
        zc, self._zc = self._zc, None
        if zc is None:
            return
        for task in list(self._tasks):
            task.cancel()
        browser, self._browser = self._browser, None
        if browser is not None:
            await browser.async_cancel()
        info, self._info = self._info, None
        if info is not None:
            with contextlib.suppress(OSError, NotRunningException):  # the network may be gone
                unregister = cast("_TwoStep", zc.async_unregister_service)  # pyright: ignore[reportUnknownMemberType]
                await (await unregister(info))
        await zc.async_close()
        if self._peers:
            self._peers.clear()
            self._on_change()

    def _state_changed(
        self,
        zeroconf: Zeroconf,  # noqa: ARG002
        service_type: str,
        name: str,
        state_change: ServiceStateChange,
    ) -> None:
        if service_type != SERVICE_TYPE:
            return
        if state_change is ServiceStateChange.Removed:
            if self._peers.pop(name, None) is not None:
                self._on_change()
            return
        task = asyncio.get_running_loop().create_task(self._resolve(name))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _resolve(self, name: str) -> None:
        zc = self._zc
        if zc is None:
            return
        info = AsyncServiceInfo(SERVICE_TYPE, name)
        if not await info.async_request(zc.zeroconf, RESOLVE_TIMEOUT_MS):
            return
        peer = self.peer_from_info(name, info)
        if peer is None or self._zc is None:
            return
        if self._peers.get(name) != peer:
            self._peers[name] = peer
            self._on_change()

    def peer_from_info(self, name: str, info: AsyncServiceInfo) -> NearbyPeer | None:
        """Validate a resolved service; ``None`` for ours or anything malformed."""
        parsed = parse_txt(info.properties)
        port = info.port
        if parsed is None or port is None or not 0 < port < 65536:  # noqa: PLR2004
            return None
        id_hint, profiles = parsed
        if id_hint == self._own:
            return None
        announced = info.parsed_scoped_addresses(IPVersion.All)
        ranked = rank_addresses(announced, port, local_interfaces(), self._port)
        addresses = tuple(ranked[:MAX_ADDRESSES])
        if not addresses:
            return None
        label = name.removesuffix("." + SERVICE_TYPE)
        return NearbyPeer(
            instance=name,
            label=display_text(label, limit=MAX_LABEL_BYTES),
            id_hint=id_hint,
            profiles=profiles,
            addresses=addresses,
            port=port,
        )
