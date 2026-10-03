"""Requests the desktop app makes of the node: each builds an operation for the services thread.

An operation (:data:`~qrp2p.ui.host.Op`) runs on the services thread with the
:class:`~qrp2p.ui.host.Services` (the node, its Inspector taps and the solo lab) and returns a
snapshot or a primitive, never a live object (UI_DESIGN §11.2). View models build them here and
submit them through the bridge; they never call the node themselves. Arguments come from QML, so
each operation checks them when it runs: an invalid one raises ``ValueError``, which reaches the
user as the request's error, like any other failure.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Final

from qrp2p.services.models import TEXT_SCALES, Appearance, Retention, TrustState
from qrp2p.services.node import NodeError, profile_by_name
from qrp2p.services.recordings import RecordingInfo
from qrp2p.ui.host import Op, Services, network_snap
from qrp2p.ui.labhost import LabSnap
from qrp2p.ui.snapshots import (
    ID_HEX_LEN,
    ActivitySnap,
    RecordingSnap,
    SafetySnap,
    message_snap,
    settings_snap,
)
from qrp2p.ui.text import display_text, fingerprint

HISTORY_PAGE: Final = 300
"""History entries a conversation loads at first; more on request."""
MAX_TEXT_BYTES: Final = 16_000
"""A chat message's limit in UTF-8 bytes (DESIGN §8.2)."""


def _id(hex_id: str) -> bytes:
    """A contact, file or entry ID from its hex form."""
    if len(hex_id) != ID_HEX_LEN:
        msg = "unknown ID"
        raise ValueError(msg)
    try:
        return bytes.fromhex(hex_id)
    except ValueError:
        msg = "unknown ID"
        raise ValueError(msg) from None


# -- life cycle (unscoped: valid whatever the generation) --------------------------------------------


def create_vault(password: str, display_name: str) -> Op:
    """Create the vault and identity, then go online."""

    async def op(services: Services) -> None:
        await services.node.create(password, display_name=display_name.strip())

    return op


def unlock(password: str) -> Op:
    """Unlock with the password."""

    async def op(services: Services) -> None:
        await services.node.unlock(password)

    return op


def unlock_with_device() -> Op:
    """Unlock with the device key from the OS keychain."""

    async def op(services: Services) -> None:
        await services.node.unlock_with_device()

    return op


def device_unlock_available() -> Op:
    """Whether "Remember on this device" is set up (answerable while locked)."""

    async def op(services: Services) -> bool:
        return await services.node.device_unlock_available()

    return op


def lock() -> Op:
    """Lock now."""

    async def op(services: Services) -> None:
        await services.node.lock()

    return op


def touch() -> Op:
    """The user is active: postpone auto-lock."""

    async def op(services: Services) -> None:  # an Op is a coroutine function
        services.node.touch()

    return op


# -- conversations ------------------------------------------------------------------------------------


def history(contact_id: str, limit: int = HISTORY_PAGE) -> Op:
    """The newest ``limit`` entries of a conversation, oldest first."""

    async def op(services: Services) -> tuple[object, ...]:
        entries = await services.node.history(_id(contact_id), max(limit, 1))
        return tuple(message_snap(e) for e in entries)

    return op


def recent_activity() -> Op:
    """When each conversation last had an entry (or the contact was added, if never)."""

    async def op(services: Services) -> ActivitySnap:
        times: list[tuple[str, float]] = []
        for contact in services.node.contacts():
            last = await services.node.history(contact.contact_id, 1)
            times.append((contact.contact_id.hex(), last[-1].time if last else contact.created))
        return ActivitySnap(tuple(times))

    return op


def send_chat(contact_id: str, text: str) -> Op:
    """Send a chat message; its entry arrives as an update."""

    async def op(services: Services) -> None:
        if not text.strip():
            msg = "the message is empty"
            raise ValueError(msg)
        if len(text.encode()) > MAX_TEXT_BYTES:
            msg = "the message is longer than 16,000 bytes"
            raise ValueError(msg)
        await services.node.send_chat(_id(contact_id), text)

    return op


def send_file(contact_id: str, path: str) -> Op:
    """Offer a file; it is sent once the peer accepts."""

    async def op(services: Services) -> None:
        await services.node.send_file(_id(contact_id), Path(path))

    return op


def send_file_data(contact_id: str, name: str, data: bytes) -> Op:
    """Offer ``data`` (a pasted image) as a file called ``name``."""

    async def op(services: Services) -> None:
        await services.node.send_file_data(_id(contact_id), name, data)

    return op


def accept_file(file_id: str, directory: str = "") -> Op:
    """Accept an offered file into ``directory`` (empty: the downloads folder)."""

    async def op(services: Services) -> None:
        await services.node.accept_file(_id(file_id), Path(directory) if directory else None)

    return op


def decline_file(file_id: str) -> Op:
    """Decline an offered file."""

    async def op(services: Services) -> None:
        await services.node.decline_file(_id(file_id))

    return op


def cancel_file(file_id: str) -> Op:
    """Cancel a transfer in either direction."""

    async def op(services: Services) -> None:
        await services.node.cancel_file(_id(file_id))

    return op


# -- connecting ----------------------------------------------------------------------------------------


def connect_contact(contact_id: str, *, glass_box: bool) -> Op:
    """Connect to a contact; returns once the session is open."""

    async def op(services: Services) -> None:
        await services.node.connect_contact(_id(contact_id), glass_box=glass_box)

    return op


def connect_address(host: str, port: int, name: str, profile: str) -> Op:
    """Connect to ``host:port`` as a first contact; returns the contact's ID."""

    async def op(services: Services) -> str:
        bare = host.strip().removeprefix("[").removesuffix("]")
        if not bare:
            msg = "enter an address"
            raise ValueError(msg)
        chosen = profile_by_name(profile) if profile else None
        contact_id = await services.node.connect_address(
            bare, _port(port), profile=chosen, name=name.strip()
        )
        return contact_id.hex()

    return op


def connect_nearby(key: str) -> Op:
    """Connect to an announced peer; returns the contact's ID."""

    async def op(services: Services) -> str:
        peer = next((p for p in services.node.nearby() if p.instance == key), None)
        if peer is None:
            msg = "that peer is no longer announced"
            raise NodeError(msg)
        return (await services.node.connect_nearby(peer)).hex()

    return op


def disconnect(contact_id: str) -> Op:
    """Close the session with a contact."""

    async def op(services: Services) -> None:
        await services.node.disconnect(_id(contact_id))

    return op


def rekey(contact_id: str) -> Op:
    """Start a post-quantum rekey now."""

    async def op(services: Services) -> None:
        await services.node.rekey(_id(contact_id))

    return op


def network() -> Op:
    """Where we listen now (addresses can change while the app runs)."""

    async def op(services: Services) -> object:
        return network_snap(services.node)

    return op


# -- prompts -------------------------------------------------------------------------------------------


def answer_prompt(prompt_id: int, *, accept: bool, name: str = "") -> Op:
    """Answer a contact or glass-box request; returns the actual outcome."""

    async def op(services: Services) -> str:
        outcome = await services.node.answer_prompt(prompt_id, accept=accept, name=name.strip())
        return outcome.value

    return op


def resolve_mismatch(mismatch_id: int, *, repin: bool) -> Op:
    """Cancel, or re-pin the contact to the identity that answered."""

    async def op(services: Services) -> None:
        await services.node.resolve_mismatch(mismatch_id, repin=repin)

    return op


# -- contacts ------------------------------------------------------------------------------------------


def safety_number(contact_id: str) -> Op:
    """The 60-digit safety number with a contact, bound to the identity it belongs to."""

    async def op(services: Services) -> SafetySnap:  # an Op is a coroutine function
        peer_id, groups = services.node.safety_number_of(_id(contact_id))
        contact = services.node.contact(_id(contact_id))
        return SafetySnap(
            peer_id=peer_id.hex(),
            fingerprint=fingerprint(peer_id),
            short_id=contact.short_id,
            groups=groups,
        )

    return op


def set_trust(contact_id: str, trust: str, compared_peer_id: str = "") -> Op:
    """Mark verified, back to pinned, or blocked.

    Verifying names the peer ID whose safety number the user compared; the node refuses if the
    contact is pinned to another identity by then.
    """

    async def op(services: Services) -> None:
        compared = bytes.fromhex(compared_peer_id) if compared_peer_id else None
        await services.node.set_trust(_id(contact_id), TrustState(trust), compared_peer_id=compared)

    return op


def rename_contact(contact_id: str, name: str) -> Op:
    """Rename a contact (local only; the peer never sees it)."""

    async def op(services: Services) -> None:
        if not name.strip():
            msg = "the name is empty"
            raise ValueError(msg)
        await services.node.update_contact(_id(contact_id), name=name.strip())

    return op


def set_contact_profile(contact_id: str, profile: str) -> Op:
    """The profile sessions with the contact use (both sides must agree)."""

    async def op(services: Services) -> None:
        await services.node.update_contact(_id(contact_id), profile_id=profile_by_name(profile).id)

    return op


def set_retention(contact_id: str, retention: str) -> Op:
    """How long the conversation is kept."""

    async def op(services: Services) -> None:
        await services.node.update_contact(_id(contact_id), retention=Retention(retention))

    return op


def set_auto_accept(contact_id: str, *, enabled: bool, limit: int) -> Op:
    """File auto-accept up to ``limit`` bytes (verified contacts only)."""

    async def op(services: Services) -> None:
        if enabled and limit <= 0:
            msg = "choose a size limit"
            raise ValueError(msg)
        await services.node.update_contact(
            _id(contact_id), auto_accept_files=enabled, auto_accept_limit=max(limit, 0)
        )

    return op


def delete_conversation(contact_id: str) -> Op:
    """Delete a conversation's history and key."""

    async def op(services: Services) -> None:
        await services.node.delete_conversation(_id(contact_id))

    return op


def delete_contact(contact_id: str) -> Op:
    """Delete a contact and its history."""

    async def op(services: Services) -> None:
        await services.node.delete_contact(_id(contact_id))

    return op


# -- settings ------------------------------------------------------------------------------------------


def _whole(value: object) -> int:
    """A whole number from QML, where every number is a double (``5.0``, ``4294967296.0``)."""
    if isinstance(value, bool):
        msg = "a number is needed"
        raise ValueError(msg)  # noqa: TRY004  # reaches the user as a ValueError like the rest
    if isinstance(value, float):
        if not value.is_integer():
            msg = "a whole number is needed"
            raise ValueError(msg)
        return int(value)
    return int(str(value))


def _flag(value: object) -> bool:
    if not isinstance(value, bool):
        msg = "on or off is needed"
        raise ValueError(msg)  # noqa: TRY004
    return value


def _non_negative(value: object) -> int:
    number = _whole(value)
    if number < 0:
        msg = "the value cannot be negative"
        raise ValueError(msg)
    return number


def _port(value: object) -> int:
    number = _whole(value)
    if not 0 < number < 65536:  # noqa: PLR2004
        msg = "the port must be between 1 and 65535"
        raise ValueError(msg)
    return number


def _text_scale(value: object) -> int:
    number = _whole(value)
    if number not in TEXT_SCALES:
        msg = "unsupported text size"
        raise ValueError(msg)
    return number


def _folder(value: object) -> str:
    text = str(value)
    if text and not Path(text).is_absolute():
        msg = "choose a full folder path"
        raise ValueError(msg)
    return text


def _positive(value: object) -> int:
    number = _whole(value)
    if number <= 0:
        msg = "the size must be positive"
        raise ValueError(msg)
    return number


_SETTINGS: Final[dict[str, Callable[[object], object]]] = {
    "display_name": lambda v: str(v).strip(),
    "announce_name": _flag,
    "default_profile": lambda v: profile_by_name(str(v)).id,
    "default_retention": lambda v: Retention(str(v)),
    "auto_lock_minutes": _non_negative,
    "port": _port,
    "downloads_dir": _folder,
    "max_file_size": _positive,
    "appearance": lambda v: Appearance(str(v)),
    "reduced_motion": _flag,
    "text_scale": _text_scale,
}
"""Settings the app may change, each with its parser (QML hands over plain values)."""


def update_setting(name: str, value: object) -> Op:
    """Change one setting (unknown or invalid: ``ValueError``); returns the settings in use."""

    async def op(services: Services) -> object:
        parse = _SETTINGS.get(name)
        if parse is None:
            msg = "unknown setting"
            raise ValueError(msg)
        settings = await services.node.update_settings(**{name: parse(value)})
        return settings_snap(services.node, settings)

    return op


def device_unlock_enabled() -> Op:
    """Whether "Remember on this device" is on."""

    async def op(services: Services) -> bool:
        return await services.node.device_unlock_enabled()

    return op


def set_device_unlock(*, enabled: bool) -> Op:
    """Turn "Remember on this device" on or off."""

    async def op(services: Services) -> None:
        await services.node.set_device_unlock(enabled=enabled)

    return op


def change_password(old: str, new: str) -> Op:
    """Re-key the vault under a new password."""

    async def op(services: Services) -> None:
        await services.node.change_password(old, new)

    return op


# -- the Inspector (the services thread's trace tap) ------------------------------------------------


def inspect_sessions(source: str = "node") -> Op:
    """Every retained session of ``source``; their descriptor changes follow as updates."""

    async def op(services: Services) -> object:
        return services.tap(source).sessions()

    return op


def inspect(session_id: int, after: int = -1, source: str = "node") -> Op:
    """A session's retained events after ``after``; its new events follow as updates."""
    if session_id < 0 or after < -1:
        msg = "unknown session"
        raise ValueError(msg)

    async def op(services: Services) -> object:
        return services.tap(source).inspect(session_id, after)

    return op


def inspect_pause(source: str = "node") -> Op:
    """Stop forwarding the inspected session's events."""

    async def op(services: Services) -> None:
        services.tap(source).pause()

    return op


def inspect_close(source: str = "node") -> Op:
    """The Inspector closed: forward nothing more."""

    async def op(services: Services) -> None:
        services.tap(source).close()

    return op


# -- the solo lab (each returns a LabSnap) -------------------------------------------------------


def lab_state() -> Op:
    """Where the lab is."""

    async def op(services: Services) -> LabSnap:
        return services.lab.snapshot()

    return op


def lab_new(profile: str) -> Op:
    """A fresh lab run with new identities (also Reset)."""

    async def op(services: Services) -> LabSnap:
        return services.lab.new(profile)

    return op


def lab_step() -> Op:
    """The default step: deliver the oldest frame in flight, admit, or start."""

    async def op(services: Services) -> LabSnap:
        return services.lab.step()

    return op


def lab_run() -> Op:
    """Default steps until nothing is in flight or waiting for a decision."""

    async def op(services: Services) -> LabSnap:
        return services.lab.run()

    return op


def lab_take(kind: str, side: str, text: str = "") -> Op:
    """A chosen step: a chat, a KeyUpdate, a rekey, a close, a wait, an admission decision."""

    async def op(services: Services) -> LabSnap:
        return services.lab.take(kind, side, text)

    return op


def lab_fork(upto: int) -> Op:
    """Replace the run with a fork after step ``upto`` (replayed to there, then live)."""

    async def op(services: Services) -> LabSnap:
        return services.lab.fork(upto)

    return op


def lab_close() -> Op:
    """Leave the lab: its run and values are dropped."""

    async def op(services: Services) -> None:
        services.lab.close()

    return op


def lab_save(title: str) -> Op:
    """Save the lab's current run as a recording."""

    async def op(services: Services) -> RecordingSnap:
        return recording_snap(await services.lab.save(_title(title)))

    return op


def lab_open(file_id: str) -> Op:
    """Open a saved recording in the lab (a lab run replays; a glass-box one is shown)."""

    async def op(services: Services) -> LabSnap:
        return await services.lab.open(file_id)

    return op


# -- recordings ----------------------------------------------------------------------------------------


def recording_snap(info: RecordingInfo) -> RecordingSnap:
    """A saved recording as the Learn list shows it."""
    return RecordingSnap(
        info.file_id,
        display_text(info.title),
        info.kind,
        info.profile,
        info.created,
        info.size,
        info.problem,
    )


def _title(title: str) -> str:
    cleaned = " ".join(title.split())
    if not cleaned:
        msg = "a recording needs a title"
        raise ValueError(msg)
    return cleaned


def recordings() -> Op:
    """The saved recordings, newest first."""

    async def op(services: Services) -> tuple[RecordingSnap, ...]:
        return tuple(recording_snap(r) for r in await services.node.recordings())

    return op


def save_session_recording(session_id: int, title: str) -> Op:
    """Save what this side retained of a glass-box session (refused for a normal one)."""

    async def op(services: Services) -> RecordingSnap:
        return recording_snap(await services.node.save_session_recording(session_id, _title(title)))

    return op


def delete_recording(file_id: str) -> Op:
    """Delete a saved recording."""

    async def op(services: Services) -> None:
        await services.node.delete_recording(file_id)

    return op
