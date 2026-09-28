"""The vault: encrypted local storage (DESIGN §10).

```text
password ──Argon2id(salt[16], t, m, p)──▶ KEK                 floor t=3, m=256 MiB, p=4; calibrated up
KEK      ──AEAD, aad = header ‖ "dek"──▶ DEK[32]             wrapped in vault.json
DEK      ──Expand-Label(SHA-256, "vault <name>")──▶ k_identity · k_settings · k_contacts · k_convkeys · k_lab
k_convkeys ──AEAD──▶ CK_c[32]  (one random key per conversation) ──▶ message rows
row value  = nonce[12] ‖ ChaCha20-Poly1305(key, nonce, pad64(plaintext), aad)
aad        = u16(len) ‖ "qrp2p2 vault" ‖ u16(schema_version) ‖ u16(len) ‖ table ‖ row_uid[16] ‖ u16(len) ‖ column
```

Row plaintexts are MessagePack structs (msgspec). They are encrypted, never hashed or signed, so
a non-canonical encoding is harmless; the associated data has the fixed layout above.

:class:`Vault` is synchronous and not thread-safe: the node runs every call on one worker thread,
so the event loop never waits for Argon2id or the disk. One process at a time may use a data
directory (an OS file lock, released by the OS if the process dies).
"""

import contextlib
import logging
import math
import os
import sqlite3
import time
import unicodedata
from collections.abc import Callable, Generator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, Protocol

import msgspec
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from filelock import FileLock, Timeout

from qrp2p.core.crypto.identity import IdentityBundle, IdentityKeyPair
from qrp2p.core.crypto.kdf import SHA256, expand_label
from qrp2p.core.crypto.secret import Secret
from qrp2p.core.errors import ProtocolError
from qrp2p.services.models import (
    ID_LEN,
    RETENTION_SECONDS,
    Contact,
    Direction,
    FileInfo,
    FileStatus,
    HistoryEntry,
    MessageKind,
    MessageStatus,
    Retention,
    Settings,
    TrustState,
)
from qrp2p.services.paths import ensure_private_dir, write_private_file

FORMAT_VERSION: Final = 1
SCHEMA_VERSION: Final = 1
VAULT_FILE: Final = "vault.json"
VAULT_FILE_NEW: Final = "vault.json.new"
DB_FILE: Final = "data.sqlite3"
LOCK_FILE: Final = "qrp2p.lock"

KEY_LEN: Final = 32
NONCE_LEN: Final = 12
SALT_LEN: Final = 16
PAD_BLOCK: Final = 64
_PAD_MARK: Final = 0x80
_HEADER_LABEL: Final = b"qrp2p2 vault header"
_AAD_LABEL: Final = b"qrp2p2 vault"
_ARGON2ID: Final = 1
_SUBKEYS: Final = ("identity", "settings", "contacts", "convkeys", "lab")

_log = logging.getLogger(__name__)


# --- errors -------------------------------------------------------------------------------------


class VaultError(Exception):
    """A vault operation failed. Messages are fixed strings, never data or keys."""


class NoVaultError(VaultError):
    """There is no vault in the data directory yet."""


class VaultExistsError(VaultError):
    """A vault already exists in the data directory."""


class WrongPasswordError(VaultError):
    """The password (or the device key) does not open the vault."""


class VaultLockedError(VaultError):
    """The vault is locked."""


class VaultInUseError(VaultError):
    """Another process has this data directory open."""


class VaultCorruptError(VaultError):
    """A file or row failed to parse or authenticate."""


# --- key derivation -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KdfParams:
    """Argon2id parameters: iterations ``t``, memory ``m_kib`` in KiB, lanes ``p``."""

    t: int
    m_kib: int
    p: int

    def check(self) -> None:
        """Refuse parameters that are not sane (a damaged or hostile ``vault.json``).

        Raises:
            VaultCorruptError: A parameter is out of range.
        """
        if not (1 <= self.t <= _MAX_T and 1 <= self.p <= _MAX_P and 8 * self.p <= self.m_kib):
            msg = "KDF parameters out of range"
            raise VaultCorruptError(msg)
        if self.m_kib > _MAX_M_KIB:
            msg = "KDF parameters out of range"
            raise VaultCorruptError(msg)


_MAX_T: Final = 1000
_MAX_P: Final = 64
_MAX_M_KIB: Final = 4 * 2**20  # 4 GiB

KDF_FLOOR: Final = KdfParams(t=3, m_kib=256 * 1024, p=4)
"""DESIGN §10.2: never less than this when a vault is created or its password changes."""


@dataclass(frozen=True, slots=True)
class KdfPolicy:
    """How new KEKs are derived: start at ``floor``, raise ``t`` until about ``target_seconds``."""

    floor: KdfParams = KDF_FLOOR
    target_seconds: float = 1.0
    max_t: int = 64


DEFAULT_KDF: Final = KdfPolicy()


def _password_bytes(password: str) -> bytes:
    if not password:
        msg = "the password must not be empty"
        raise ValueError(msg)
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_kek(password: str, salt: bytes, params: KdfParams) -> Secret:
    """``KEK = Argon2id(NFC(password) as UTF-8, salt, t, m, p)``, 32 bytes."""
    kdf = Argon2id(
        salt=salt, length=KEY_LEN, iterations=params.t, lanes=params.p, memory_cost=params.m_kib
    )
    return Secret(kdf.derive(_password_bytes(password)), "vault.kek")


def calibrated_kek(
    password: str,
    salt: bytes,
    policy: KdfPolicy,
    timer: Callable[[], float] = time.perf_counter,
) -> tuple[KdfParams, Secret]:
    """Derive a KEK at the floor, then again with more iterations if that was much too fast.

    Calibration only ever raises the cost (DESIGN §10.2).
    """
    params = policy.floor
    start = timer()
    kek = derive_kek(password, salt, params)
    elapsed = timer() - start
    if policy.target_seconds <= 0 or elapsed >= policy.target_seconds / 2:
        return params, kek
    scale = policy.target_seconds / max(elapsed, 1e-3)
    t = min(policy.max_t, max(params.t, math.ceil(params.t * scale)))
    if t == params.t:
        return params, kek
    params = replace(params, t=t)
    return params, derive_kek(password, salt, params)


# --- vault.json ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VaultHeader:
    """What the wrapped keys are bound to."""

    vault_id: bytes
    kdf: KdfParams
    salt: bytes

    def encode(self) -> bytes:
        """The canonical header, used as associated data.

        ``u16(len) ‖ "qrp2p2 vault header" ‖ u16(format_version) ‖ vault_id[16] ‖ u8(kdf = 1)
        ‖ u32(t) ‖ u32(m_KiB) ‖ u32(p) ‖ salt[16]``
        """
        return (
            len(_HEADER_LABEL).to_bytes(2, "big")
            + _HEADER_LABEL
            + FORMAT_VERSION.to_bytes(2, "big")
            + self.vault_id
            + bytes([_ARGON2ID])
            + self.kdf.t.to_bytes(4, "big")
            + self.kdf.m_kib.to_bytes(4, "big")
            + self.kdf.p.to_bytes(4, "big")
            + self.salt
        )


class _KdfJson(msgspec.Struct, forbid_unknown_fields=True):
    algorithm: str
    t: int
    m_kib: int
    p: int


class _VaultJson(msgspec.Struct, forbid_unknown_fields=True):
    format: str
    format_version: int
    vault_id: str
    kdf: _KdfJson
    salt: str
    wrapped_dek: str
    device_kek: str | None = None


_FORMAT_NAME: Final = "qrp2p-vault"


@dataclass(frozen=True, slots=True)
class VaultFile:
    """The contents of ``vault.json``."""

    header: VaultHeader
    wrapped_dek: bytes
    device_kek: bytes | None = None

    def to_json(self) -> bytes:
        """Serialise, hex-encoding the binary fields."""
        header = self.header
        doc = _VaultJson(
            format=_FORMAT_NAME,
            format_version=FORMAT_VERSION,
            vault_id=header.vault_id.hex(),
            kdf=_KdfJson("argon2id", header.kdf.t, header.kdf.m_kib, header.kdf.p),
            salt=header.salt.hex(),
            wrapped_dek=self.wrapped_dek.hex(),
            device_kek=self.device_kek.hex() if self.device_kek is not None else None,
        )
        return msgspec.json.format(msgspec.json.encode(doc), indent=2) + b"\n"

    @classmethod
    def from_json(cls, data: bytes) -> VaultFile:
        """Parse strictly.

        Raises:
            VaultCorruptError: Not a vault file of a known version, or a field is malformed.
        """
        try:
            doc = msgspec.json.decode(data, type=_VaultJson)
            header = VaultHeader(
                vault_id=bytes.fromhex(doc.vault_id),
                kdf=KdfParams(doc.kdf.t, doc.kdf.m_kib, doc.kdf.p),
                salt=bytes.fromhex(doc.salt),
            )
            wrapped = bytes.fromhex(doc.wrapped_dek)
            device = bytes.fromhex(doc.device_kek) if doc.device_kek is not None else None
        except msgspec.DecodeError, ValueError:
            msg = "vault.json is malformed"
            raise VaultCorruptError(msg) from None
        if doc.format != _FORMAT_NAME or doc.format_version != FORMAT_VERSION:
            msg = "vault.json has an unknown format or version"
            raise VaultCorruptError(msg)
        if doc.kdf.algorithm != "argon2id":
            msg = "vault.json names an unknown KDF"
            raise VaultCorruptError(msg)
        if len(header.vault_id) != ID_LEN or len(header.salt) != SALT_LEN:
            msg = "vault.json has a malformed ID or salt"
            raise VaultCorruptError(msg)
        header.kdf.check()
        return cls(header, wrapped, device)


# --- row encryption -----------------------------------------------------------------------------


def pad(data: bytes) -> bytes:
    """``data ‖ 0x80 ‖ 0^k`` with the least ``k`` that makes the length a multiple of 64."""
    padded = data + bytes([_PAD_MARK])
    return padded + bytes(-len(padded) % PAD_BLOCK)


def unpad(data: bytes) -> bytes:
    """Invert :func:`pad`.

    Raises:
        VaultCorruptError: The padding is malformed.
    """
    if not data or len(data) % PAD_BLOCK:
        msg = "row padding is malformed"
        raise VaultCorruptError(msg)
    stripped = data.rstrip(b"\x00")
    if not stripped or stripped[-1] != _PAD_MARK or len(data) - len(stripped) >= PAD_BLOCK:
        msg = "row padding is malformed"
        raise VaultCorruptError(msg)
    return stripped[:-1]


def associated_data(table: str, row_uid: bytes, column: str) -> bytes:
    """DESIGN §10.3: binds a value to its table, row and column (never to SQLite's rowid)."""
    if len(row_uid) != ID_LEN:
        msg = "row_uid must be 16 bytes"
        raise ValueError(msg)
    t, c = table.encode("ascii"), column.encode("ascii")
    return (
        len(_AAD_LABEL).to_bytes(2, "big")
        + _AAD_LABEL
        + SCHEMA_VERSION.to_bytes(2, "big")
        + len(t).to_bytes(2, "big")
        + t
        + row_uid
        + len(c).to_bytes(2, "big")
        + c
    )


def _seal(key: Secret, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return nonce + ChaCha20Poly1305(key.reveal()).encrypt(nonce, plaintext, aad)


def _open(key: Secret, value: bytes, aad: bytes) -> bytes | None:
    if len(value) < NONCE_LEN + 16:
        return None
    try:
        return ChaCha20Poly1305(key.reveal()).decrypt(value[:NONCE_LEN], value[NONCE_LEN:], aad)
    except InvalidTag:
        return None


# --- row schemas --------------------------------------------------------------------------------


class _IdentityRow(msgspec.Struct, forbid_unknown_fields=True):
    ed25519: bytes
    mldsa65: bytes
    mldsa87: bytes


class _SettingsRow(msgspec.Struct):  # unknown fields ignored: a newer version may add some
    display_name: str = ""
    announce_name: bool = True
    default_profile: int = 1
    default_retention: str = "forever"
    auto_lock_minutes: int = 15
    port: int = 47470
    downloads_dir: str = ""
    max_file_size: int = 4 * 2**30


class _ContactRow(msgspec.Struct):
    bundle: bytes
    name: str
    trust: str
    profile: int
    retention: str
    auto_accept_files: bool = False
    auto_accept_limit: int = 0
    address_host: str | None = None
    address_port: int | None = None
    created: float = 0.0


class _FileRow(msgspec.Struct):
    file_id: bytes
    name: str
    size: int
    media_type: str
    status: str
    sha256: bytes = b""
    path: str = ""
    reason: str = ""


class _EntryRow(msgspec.Struct):
    kind: str
    direction: str
    time: float
    message_id: bytes = b""
    status: str = "received"
    text: str = ""
    file: _FileRow | None = None
    glass_box: bool = False


def _decode[T](data: bytes, kind: type[T]) -> T:
    try:
        return msgspec.msgpack.decode(data, type=kind)
    except msgspec.DecodeError:
        msg = "a row does not match its schema"
        raise VaultCorruptError(msg) from None


_SCHEMA: Final = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE identity (
    row_uid BLOB PRIMARY KEY CHECK (length(row_uid) = 16), seeds BLOB NOT NULL
) STRICT, WITHOUT ROWID;
CREATE TABLE settings (
    row_uid BLOB PRIMARY KEY CHECK (length(row_uid) = 16), data BLOB NOT NULL
) STRICT, WITHOUT ROWID;
CREATE TABLE contacts (
    row_uid BLOB PRIMARY KEY CHECK (length(row_uid) = 16),
    conv_id BLOB NOT NULL UNIQUE CHECK (length(conv_id) = 16),
    data BLOB NOT NULL
) STRICT, WITHOUT ROWID;
CREATE TABLE conv_keys (
    conv_id BLOB PRIMARY KEY CHECK (length(conv_id) = 16), ck BLOB NOT NULL
) STRICT, WITHOUT ROWID;
CREATE TABLE messages (
    row_uid BLOB PRIMARY KEY CHECK (length(row_uid) = 16),
    conv_id BLOB NOT NULL CHECK (length(conv_id) = 16),
    ord INTEGER NOT NULL,
    data BLOB NOT NULL,
    UNIQUE (conv_id, ord)
) STRICT, WITHOUT ROWID;
"""


# --- keychain -----------------------------------------------------------------------------------


class Keychain(Protocol):
    """Where the optional device key lives (DESIGN §10.4, "Remember on this device")."""

    def get(self, vault_id: bytes) -> bytes | None:
        """The device key for this vault, if stored."""
        ...

    def set(self, vault_id: bytes, key: bytes) -> None:
        """Store the device key."""
        ...

    def delete(self, vault_id: bytes) -> None:
        """Remove the device key; no error if absent."""
        ...


# --- the vault ----------------------------------------------------------------------------------


@dataclass(slots=True)
class _Open:
    """Keys and the database of an unlocked vault."""

    file: VaultFile
    kek: Secret
    keys: dict[str, Secret]
    db: sqlite3.Connection
    conv_keys: dict[bytes, Secret]


class Vault:
    """The encrypted store of one data directory.

    Args:
        directory: The data directory (created with owner-only permissions).
        random_bytes: Randomness for keys, IDs and nonces.
        kdf: How new KEKs are derived. Tests pass a cheap policy; the app uses the default.
    """

    def __init__(
        self,
        directory: Path,
        *,
        random_bytes: Callable[[int], bytes] = os.urandom,
        kdf: KdfPolicy = DEFAULT_KDF,
    ) -> None:
        self._dir = directory
        self._random = random_bytes
        self._kdf = kdf
        self._lock: FileLock | None = None
        self._open: _Open | None = None

    # -- files and the instance lock --------------------------------------------------------------

    @property
    def directory(self) -> Path:
        """The data directory."""
        return self._dir

    @property
    def exists(self) -> bool:
        """Whether a vault has been created here."""
        return (self._dir / VAULT_FILE).exists() or (self._dir / VAULT_FILE_NEW).exists()

    @property
    def is_unlocked(self) -> bool:
        """Whether keys are loaded."""
        return self._open is not None

    def acquire(self) -> None:
        """Take the single-instance lock (DESIGN §10.1).

        The lock is an OS lock on ``qrp2p.lock``: a lock file left behind by a crashed process
        does not block (v1 regression 5).

        Raises:
            VaultInUseError: Another process holds it.
        """
        if self._lock is not None:
            return
        ensure_private_dir(self._dir)
        lock = FileLock(
            self._dir / LOCK_FILE, timeout=0, thread_local=False, fallback_to_soft=False
        )
        try:
            lock.acquire()
        except Timeout:
            msg = "another QRP2P process is using this data directory"
            raise VaultInUseError(msg) from None
        self._lock = lock

    def close(self) -> None:
        """Lock, then release the single-instance lock."""
        self.lock()
        if self._lock is not None:
            self._lock.release()
            self._lock = None

    def _state(self) -> _Open:
        if self._open is None:
            msg = "the vault is locked"
            raise VaultLockedError(msg)
        return self._open

    # -- create, unlock, lock -------------------------------------------------------------------

    def create(self, password: str, settings: Settings | None = None) -> IdentityKeyPair:
        """Create the vault with a new identity.

        Raises:
            VaultExistsError: A vault exists already.
            ValueError: The password is empty.
        """
        self.acquire()
        if self.exists:
            msg = "a vault already exists here"
            raise VaultExistsError(msg)
        _password_bytes(password)
        self._remove_orphan_database()
        salt = self._random(SALT_LEN)
        params, kek = calibrated_kek(password, salt, self._kdf)
        header = VaultHeader(self._random(ID_LEN), params, salt)
        dek = Secret(self._random(KEY_LEN), "vault.dek")
        file = VaultFile(header, self._wrap(kek, header, dek, b"dek"))
        identity = IdentityKeyPair.generate(self._random)
        db = self._connect(create=True)
        state = _Open(file, kek, _subkeys(dek), db, {})
        self._open = state
        try:
            with self._transaction():
                db.executescript(_SCHEMA)
                db.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                    (str(SCHEMA_VERSION),),
                )
                self._put_identity(identity)
                self._put_settings(settings or Settings())
            write_private_file(self._dir / VAULT_FILE, file.to_json())
        except BaseException:
            self._open = None
            db.close()
            (self._dir / DB_FILE).unlink(missing_ok=True)
            raise
        _log.info("vault created (Argon2id t=%d, m=%d KiB, p=%d)", params.t, params.m_kib, params.p)
        return identity

    def _remove_orphan_database(self) -> None:
        """Delete a database without ``vault.json``: a creation that crashed. Its DEK is lost."""
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = self._dir / (DB_FILE + suffix)
            if path.exists():
                _log.warning("removing %s left by an interrupted vault creation", path.name)
                path.unlink()

    def unlock(self, password: str) -> IdentityKeyPair:
        """Open the vault with the password.

        After an interrupted password change both ``vault.json`` and ``vault.json.new`` exist;
        whichever the password opens and matches the database wins.

        Raises:
            NoVaultError: No vault here.
            WrongPasswordError: The password is wrong.
            VaultCorruptError: A file failed to parse or authenticate.
        """
        self.acquire()
        candidates = self._vault_files()
        for path, file in candidates:
            kek = derive_kek(password, file.header.salt, file.header.kdf)
            identity = self._try_open(file, kek)
            if identity is not None:
                self._settle(path, file)
                return identity
        msg = "wrong password"
        raise WrongPasswordError(msg)

    def unlock_with_device(self, keychain: Keychain) -> IdentityKeyPair:
        """Open the vault with the device key from the OS keychain (opt-in).

        Raises:
            WrongPasswordError: No device key is stored, or it does not open the vault.
        """
        self.acquire()
        for path, file in self._vault_files():
            if file.device_kek is None:
                continue
            device_key = keychain.get(file.header.vault_id)
            if device_key is None or len(device_key) != KEY_LEN:
                continue
            kek_bytes = _open(
                Secret(device_key, "vault.device_key"),
                file.device_kek,
                file.header.encode() + b"device",
            )
            if kek_bytes is None:
                continue
            identity = self._try_open(file, Secret(kek_bytes, "vault.kek"))
            if identity is not None:
                self._settle(path, file)
                return identity
        msg = "the device key does not open this vault"
        raise WrongPasswordError(msg)

    def _vault_files(self) -> list[tuple[Path, VaultFile]]:
        found: list[tuple[Path, VaultFile]] = []
        for name in (VAULT_FILE, VAULT_FILE_NEW):
            path = self._dir / name
            with contextlib.suppress(FileNotFoundError):
                found.append((path, VaultFile.from_json(path.read_bytes())))
        if not found:
            msg = "no vault in this data directory"
            raise NoVaultError(msg)
        return found

    def _try_open(self, file: VaultFile, kek: Secret) -> IdentityKeyPair | None:
        """Unwrap the DEK and check it against the database; ``None`` if it does not match."""
        dek_bytes = _open(kek, file.wrapped_dek, file.header.encode() + b"dek")
        if dek_bytes is None or len(dek_bytes) != KEY_LEN:
            return None
        if self._open is not None:
            self.lock()
        db = self._connect(create=False)
        state = _Open(file, kek, _subkeys(Secret(dek_bytes, "vault.dek")), db, {})
        self._open = state
        try:
            self._check_schema()
            return self.identity()
        except VaultCorruptError:
            self._open = None
            db.close()
            return None

    def _settle(self, path: Path, file: VaultFile) -> None:
        """Make the file that opened the vault the only ``vault.json``."""
        if path.name == VAULT_FILE_NEW:
            write_private_file(self._dir / VAULT_FILE, file.to_json())
        (self._dir / VAULT_FILE_NEW).unlink(missing_ok=True)

    def lock(self) -> None:
        """Checkpoint the WAL, close the database and drop every key reference (DESIGN §10.4).

        Session-only conversations are purged first. Locking never fails (v1 regression 6): a
        purge or checkpoint that fails on a damaged database is logged and the keys still go.
        """
        state = self._open
        if state is None:
            return
        try:
            self.purge_session_only()
            state.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except VaultError, sqlite3.Error:
            _log.warning("could not purge or checkpoint while locking; locking anyway")
        finally:
            state.db.close()
            state.conv_keys.clear()
            state.keys.clear()
            self._open = None

    # -- password and device key ----------------------------------------------------------------

    def change_password(self, old: str, new: str, keychain: Keychain | None = None) -> None:
        """Re-key everything under a new DEK and new conversation keys (DESIGN §10.4).

        Afterwards the old ``vault.json`` and the old password open nothing in this database.
        Device unlock stays enabled only if ``keychain`` still holds the device key.

        The steps are ordered so that a crash at any point leaves a vault that opens with the
        old or the new password: ``vault.json.new`` is written first, the database is re-encrypted
        in one transaction, then ``vault.json`` is replaced (see :meth:`unlock`).

        Raises:
            WrongPasswordError: ``old`` is not the current password.
            ValueError: ``new`` is empty.
        """
        state = self._state()
        header = state.file.header
        if derive_kek(old, header.salt, header.kdf) != state.kek:
            msg = "wrong password"
            raise WrongPasswordError(msg)
        _password_bytes(new)
        salt = self._random(SALT_LEN)
        params, kek = calibrated_kek(new, salt, self._kdf)
        new_header = VaultHeader(header.vault_id, params, salt)
        dek = Secret(self._random(KEY_LEN), "vault.dek")
        device_kek = None
        if state.file.device_kek is not None and keychain is not None:
            device_key = keychain.get(header.vault_id)
            if device_key is not None and len(device_key) == KEY_LEN:
                device_kek = self._wrap(
                    Secret(device_key, "vault.device_key"), new_header, kek, b"device"
                )
        file = VaultFile(new_header, self._wrap(kek, new_header, dek, b"dek"), device_kek)
        pending = self._dir / VAULT_FILE_NEW
        write_private_file(pending, file.to_json())
        try:
            self._rekey_database(_subkeys(dek))
        except BaseException:
            pending.unlink(missing_ok=True)
            raise
        state.file = file
        state.kek = kek
        write_private_file(self._dir / VAULT_FILE, file.to_json())
        pending.unlink(missing_ok=True)
        _log.info(
            "vault re-keyed (Argon2id t=%d, m=%d KiB, p=%d)", params.t, params.m_kib, params.p
        )

    def _rekey_database(self, keys: dict[str, Secret]) -> None:
        """Decrypt everything, then re-insert it under ``keys`` in one transaction."""
        state = self._state()
        db = state.db
        identity = self.identity()
        settings = self.settings()
        contacts = self.contacts()
        histories = {c.conv_id: self._entries(c.conv_id) for c in contacts}
        old_keys, old_conv_keys = state.keys, state.conv_keys
        state.keys, state.conv_keys = keys, {}
        try:
            with self._transaction():
                for table in ("identity", "settings", "contacts", "conv_keys", "messages"):
                    db.execute(f"DELETE FROM {table}")  # noqa: S608  # fixed table names
                self._put_identity(identity)
                self._put_settings(settings)
                for contact in contacts:
                    self._insert_contact(contact)  # a new CK_c for each conversation
                    for entry in histories[contact.conv_id]:
                        self._insert_entry(contact.conv_id, entry)
        except BaseException:
            state.keys, state.conv_keys = old_keys, old_conv_keys
            raise
        db.execute("VACUUM")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    @property
    def device_unlock_configured(self) -> bool:
        """Whether a ``vault.json`` holds a device-wrapped KEK; readable while locked."""
        try:
            return any(file.device_kek is not None for _, file in self._vault_files())
        except VaultError:
            return False

    @property
    def device_unlock_enabled(self) -> bool:
        """Whether ``vault.json`` holds a device-wrapped KEK."""
        return self._state().file.device_kek is not None

    def enable_device_unlock(self, keychain: Keychain) -> None:
        """Store a random device key in the OS keychain and a copy of the KEK wrapped by it."""
        state = self._state()
        device_key = self._random(KEY_LEN)
        header = state.file.header
        wrapped = self._wrap(Secret(device_key, "vault.device_key"), header, state.kek, b"device")
        keychain.set(header.vault_id, device_key)
        state.file = replace(state.file, device_kek=wrapped)
        write_private_file(self._dir / VAULT_FILE, state.file.to_json())

    def disable_device_unlock(self, keychain: Keychain) -> None:
        """Remove the device-wrapped KEK and the keychain entry."""
        state = self._state()
        state.file = replace(state.file, device_kek=None)
        write_private_file(self._dir / VAULT_FILE, state.file.to_json())
        keychain.delete(state.file.header.vault_id)

    def _wrap(self, key: Secret, header: VaultHeader, value: Secret, purpose: bytes) -> bytes:
        """``nonce ‖ AEAD(key, nonce, value, aad = header ‖ purpose)``."""
        return _seal(key, self._random(NONCE_LEN), value.reveal(), header.encode() + purpose)

    # -- database -------------------------------------------------------------------------------

    def _connect(self, *, create: bool) -> sqlite3.Connection:
        path = self._dir / DB_FILE
        if create:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        elif not path.exists():
            msg = "the database file is missing"
            raise VaultCorruptError(msg)
        db = sqlite3.connect(path, autocommit=True)
        db.execute("PRAGMA secure_delete = ON")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = FULL")
        db.execute("PRAGMA trusted_schema = OFF")
        return db

    @contextlib.contextmanager
    def _transaction(self) -> Generator[None]:
        db = self._state().db
        db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            db.execute("ROLLBACK")
            raise
        db.execute("COMMIT")

    def _check_schema(self) -> None:
        try:
            row = (
                self._state()
                .db.execute("SELECT value FROM meta WHERE key = 'schema_version'")
                .fetchone()
            )
        except sqlite3.DatabaseError:
            msg = "the database is unreadable"
            raise VaultCorruptError(msg) from None
        if row is None or row[0] != str(SCHEMA_VERSION):
            msg = "the database has an unknown schema version"
            raise VaultCorruptError(msg)

    def _seal_row(
        self, key: Secret, table: str, row_uid: bytes, column: str, value: bytes
    ) -> bytes:
        aad = associated_data(table, row_uid, column)
        return _seal(key, self._random(NONCE_LEN), pad(value), aad)

    @staticmethod
    def _open_row(key: Secret, table: str, row_uid: bytes, column: str, value: bytes) -> bytes:
        plaintext = _open(key, value, associated_data(table, row_uid, column))
        if plaintext is None:
            msg = "a row failed to authenticate"
            raise VaultCorruptError(msg)
        return unpad(plaintext)

    def _key(self, name: str) -> Secret:
        return self._state().keys[name]

    # -- identity and settings ------------------------------------------------------------------

    def _put_identity(self, identity: IdentityKeyPair) -> None:
        ed, m65, m87 = identity.seeds
        row = _IdentityRow(ed.reveal(), m65.reveal(), m87.reveal())
        uid = self._random(ID_LEN)
        value = self._seal_row(
            self._key("identity"), "identity", uid, "seeds", msgspec.msgpack.encode(row)
        )
        self._state().db.execute(
            "INSERT INTO identity (row_uid, seeds) VALUES (?, ?)", (uid, value)
        )

    def identity(self) -> IdentityKeyPair:
        """Our identity key pair.

        Raises:
            VaultLockedError: Locked.
            VaultCorruptError: The row is missing or fails to authenticate.
        """
        found = self._state().db.execute("SELECT row_uid, seeds FROM identity").fetchall()
        if len(found) != 1:
            msg = "the identity row is missing"
            raise VaultCorruptError(msg)
        uid, value = found[0]
        plaintext = self._open_row(self._key("identity"), "identity", uid, "seeds", value)
        row = _decode(plaintext, _IdentityRow)
        try:
            return IdentityKeyPair(
                Secret(row.ed25519, "identity.ed25519"),
                Secret(row.mldsa65, "identity.mldsa65"),
                Secret(row.mldsa87, "identity.mldsa87"),
            )
        except ValueError:
            msg = "the identity seeds are malformed"
            raise VaultCorruptError(msg) from None

    def _put_settings(self, settings: Settings) -> None:
        row = _SettingsRow(
            display_name=settings.display_name,
            announce_name=settings.announce_name,
            default_profile=settings.default_profile,
            default_retention=settings.default_retention.value,
            auto_lock_minutes=settings.auto_lock_minutes,
            port=settings.port,
            downloads_dir=settings.downloads_dir,
            max_file_size=settings.max_file_size,
        )
        db = self._state().db
        found = db.execute("SELECT row_uid FROM settings").fetchone()
        uid = found[0] if found else self._random(ID_LEN)
        value = self._seal_row(
            self._key("settings"), "settings", uid, "data", msgspec.msgpack.encode(row)
        )
        db.execute("INSERT OR REPLACE INTO settings (row_uid, data) VALUES (?, ?)", (uid, value))

    def settings(self) -> Settings:
        """The user's settings."""
        found = self._state().db.execute("SELECT row_uid, data FROM settings").fetchone()
        if found is None:
            return Settings()
        uid, value = found
        row = _decode(
            self._open_row(self._key("settings"), "settings", uid, "data", value), _SettingsRow
        )
        try:
            retention = Retention(row.default_retention)
        except ValueError:
            msg = "settings are malformed"
            raise VaultCorruptError(msg) from None
        return Settings(
            display_name=row.display_name,
            announce_name=row.announce_name,
            default_profile=row.default_profile,
            default_retention=retention,
            auto_lock_minutes=row.auto_lock_minutes,
            port=row.port,
            downloads_dir=row.downloads_dir,
            max_file_size=row.max_file_size,
        )

    def save_settings(self, settings: Settings) -> None:
        """Replace the settings."""
        with self._transaction():
            self._put_settings(settings)

    # -- contacts -------------------------------------------------------------------------------

    def contacts(self) -> list[Contact]:
        """Every contact, in no particular order."""
        rows = self._state().db.execute("SELECT row_uid, conv_id, data FROM contacts").fetchall()
        return [self._contact(uid, conv_id, value) for uid, conv_id, value in rows]

    def _contact(self, uid: bytes, conv_id: bytes, value: bytes) -> Contact:
        row = _decode(
            self._open_row(self._key("contacts"), "contacts", uid, "data", value), _ContactRow
        )
        try:
            address = (
                (row.address_host, row.address_port)
                if row.address_host is not None and row.address_port is not None
                else None
            )
            return Contact(
                contact_id=uid,
                conv_id=conv_id,
                bundle=IdentityBundle.decode(row.bundle),
                name=row.name,
                trust=TrustState(row.trust),
                profile_id=row.profile,
                retention=Retention(row.retention),
                auto_accept_files=row.auto_accept_files,
                auto_accept_limit=row.auto_accept_limit,
                address=address,
                created=row.created,
            )
        except ValueError, ProtocolError:
            msg = "a contact row is malformed"
            raise VaultCorruptError(msg) from None

    def new_contact_ids(self) -> tuple[bytes, bytes]:
        """Fresh random ``(contact_id, conv_id)``."""
        return self._random(ID_LEN), self._random(ID_LEN)

    def save_contact(self, contact: Contact) -> None:
        """Insert or update a contact; a new conversation gets its key."""
        with self._transaction():
            self._insert_contact(contact)

    def _insert_contact(self, contact: Contact) -> None:
        host, port = contact.address if contact.address is not None else (None, None)
        row = _ContactRow(
            bundle=contact.bundle.encode(),
            name=contact.name,
            trust=contact.trust.value,
            profile=contact.profile_id,
            retention=contact.retention.value,
            auto_accept_files=contact.auto_accept_files,
            auto_accept_limit=contact.auto_accept_limit,
            address_host=host,
            address_port=port,
            created=contact.created,
        )
        uid = contact.contact_id
        value = self._seal_row(
            self._key("contacts"), "contacts", uid, "data", msgspec.msgpack.encode(row)
        )
        db = self._state().db
        db.execute(
            "INSERT OR REPLACE INTO contacts (row_uid, conv_id, data) VALUES (?, ?, ?)",
            (uid, contact.conv_id, value),
        )
        if (
            db.execute("SELECT 1 FROM conv_keys WHERE conv_id = ?", (contact.conv_id,)).fetchone()
            is None
        ):
            ck = Secret(self._random(KEY_LEN), "vault.ck")
            wrapped = self._seal_row(
                self._key("convkeys"), "conv_keys", contact.conv_id, "ck", ck.reveal()
            )
            db.execute(
                "INSERT INTO conv_keys (conv_id, ck) VALUES (?, ?)", (contact.conv_id, wrapped)
            )
            self._state().conv_keys[contact.conv_id] = ck

    def delete_contact(self, contact: Contact) -> None:
        """Delete a contact and its conversation, then ``VACUUM``."""
        db = self._state().db
        with self._transaction():
            db.execute("DELETE FROM contacts WHERE row_uid = ?", (contact.contact_id,))
            self._drop_conversation(contact.conv_id)
        db.execute("VACUUM")

    def delete_conversation(self, contact: Contact) -> Contact:
        """Delete a conversation's messages and key, then ``VACUUM`` (DESIGN §10.4).

        Remnants in free pages or the WAL are unreadable once ``CK_c`` is gone. The contact gets
        a fresh conversation ID and key.
        """
        conv_id = self._random(ID_LEN)
        updated = replace(contact, conv_id=conv_id)
        db = self._state().db
        with self._transaction():
            self._drop_conversation(contact.conv_id)
            self._insert_contact(updated)
        db.execute("VACUUM")
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return updated

    def _drop_conversation(self, conv_id: bytes) -> None:
        db = self._state().db
        db.execute("DELETE FROM conv_keys WHERE conv_id = ?", (conv_id,))
        db.execute("DELETE FROM messages WHERE conv_id = ?", (conv_id,))
        self._state().conv_keys.pop(conv_id, None)

    # -- history --------------------------------------------------------------------------------

    def _conv_key(self, conv_id: bytes) -> Secret:
        state = self._state()
        key = state.conv_keys.get(conv_id)
        if key is not None:
            return key
        found = state.db.execute(
            "SELECT ck FROM conv_keys WHERE conv_id = ?", (conv_id,)
        ).fetchone()
        if found is None:
            msg = "a conversation key is missing"
            raise VaultCorruptError(msg)
        plaintext = self._open_row(self._key("convkeys"), "conv_keys", conv_id, "ck", found[0])
        if len(plaintext) != KEY_LEN:
            msg = "a conversation key is malformed"
            raise VaultCorruptError(msg)
        key = state.conv_keys[conv_id] = Secret(plaintext, "vault.ck")
        return key

    def new_entry_id(self) -> bytes:
        """A fresh random ``row_uid`` for a history entry."""
        return self._random(ID_LEN)

    def add_entry(self, conv_id: bytes, entry: HistoryEntry) -> None:
        """Append an entry to a conversation."""
        with self._transaction():
            self._insert_entry(conv_id, entry)

    def _insert_entry(self, conv_id: bytes, entry: HistoryEntry) -> None:
        db = self._state().db
        (last,) = db.execute(
            "SELECT coalesce(max(ord), -1) FROM messages WHERE conv_id = ?", (conv_id,)
        ).fetchone()
        value = self._entry_value(conv_id, entry)
        db.execute(
            "INSERT INTO messages (row_uid, conv_id, ord, data) VALUES (?, ?, ?, ?)",
            (entry.entry_id, conv_id, int(last) + 1, value),
        )

    def update_entry(self, conv_id: bytes, entry: HistoryEntry) -> None:
        """Replace an entry's contents (status changes); a no-op if it was deleted."""
        value = self._entry_value(conv_id, entry)
        with self._transaction():
            self._state().db.execute(
                "UPDATE messages SET data = ? WHERE row_uid = ? AND conv_id = ?",
                (value, entry.entry_id, conv_id),
            )

    def _entry_value(self, conv_id: bytes, entry: HistoryEntry) -> bytes:
        file = entry.file
        row = _EntryRow(
            kind=entry.kind.value,
            direction=entry.direction.value,
            time=entry.time,
            message_id=entry.message_id,
            status=entry.status.value,
            text=entry.text,
            file=(
                _FileRow(
                    file_id=file.file_id,
                    name=file.name,
                    size=file.size,
                    media_type=file.media_type,
                    status=file.status.value,
                    sha256=file.sha256,
                    path=file.path,
                    reason=file.reason,
                )
                if file is not None
                else None
            ),
            glass_box=entry.glass_box,
        )
        return self._seal_row(
            self._conv_key(conv_id), "messages", entry.entry_id, "data", msgspec.msgpack.encode(row)
        )

    def history(self, conv_id: bytes, limit: int | None = None) -> list[HistoryEntry]:
        """A conversation's entries, oldest first; the newest ``limit`` if given."""
        return self._entries(conv_id, limit)

    def _entries(self, conv_id: bytes, limit: int | None = None) -> list[HistoryEntry]:
        db = self._state().db
        query = "SELECT row_uid, data FROM messages WHERE conv_id = ? ORDER BY ord DESC"
        params: tuple[object, ...] = (conv_id,)
        if limit is not None:
            query += " LIMIT ?"
            params = (conv_id, limit)
        rows = db.execute(query, params).fetchall()
        key = self._conv_key(conv_id) if rows else None
        entries = [self._entry(key, uid, value) for uid, value in rows if key is not None]
        entries.reverse()
        return entries

    def _entry(self, key: Secret, uid: bytes, value: bytes) -> HistoryEntry:
        row = _decode(self._open_row(key, "messages", uid, "data", value), _EntryRow)
        try:
            file = (
                FileInfo(
                    file_id=row.file.file_id,
                    name=row.file.name,
                    size=row.file.size,
                    media_type=row.file.media_type,
                    status=FileStatus(row.file.status),
                    sha256=row.file.sha256,
                    path=row.file.path,
                    reason=row.file.reason,
                )
                if row.file is not None
                else None
            )
            return HistoryEntry(
                entry_id=uid,
                kind=MessageKind(row.kind),
                direction=Direction(row.direction),
                time=row.time,
                message_id=row.message_id,
                status=MessageStatus(row.status),
                text=row.text,
                file=file,
                glass_box=row.glass_box,
            )
        except ValueError:
            msg = "a history row is malformed"
            raise VaultCorruptError(msg) from None

    # -- retention ------------------------------------------------------------------------------

    def purge_expired(self, now: float) -> int:
        """Delete entries older than their contact's retention allows; return how many."""
        removed = 0
        for contact in self.contacts():
            limit = RETENTION_SECONDS.get(contact.retention)
            if limit is None:
                continue
            old = [e.entry_id for e in self._entries(contact.conv_id) if e.time < now - limit]
            removed += self._delete_entries(old)
        return removed

    def purge_session_only(self) -> int:
        """Delete the history of session-only conversations (at lock, exit and unlock)."""
        removed = 0
        db = self._state().db
        for contact in self.contacts():
            if contact.retention is Retention.SESSION:
                with self._transaction():
                    cursor = db.execute(
                        "DELETE FROM messages WHERE conv_id = ?", (contact.conv_id,)
                    )
                removed += cursor.rowcount
        return removed

    def _delete_entries(self, entry_ids: list[bytes]) -> int:
        if not entry_ids:
            return 0
        with self._transaction():
            self._state().db.executemany(
                "DELETE FROM messages WHERE row_uid = ?", [(uid,) for uid in entry_ids]
            )
        return len(entry_ids)


def _subkeys(dek: Secret) -> dict[str, Secret]:
    """``k_name = Expand-Label(SHA-256, DEK, "vault " ‖ name, "", 32)``."""
    return {
        name: expand_label(SHA256, dek, f"vault {name}", b"", KEY_LEN, name=f"vault.k_{name}")
        for name in _SUBKEYS
    }
