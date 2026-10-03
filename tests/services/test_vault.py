"""The vault (DESIGN §10): key hierarchy, rows, deletion, password change, lock."""

import json
import sqlite3
import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import msgspec
import pytest

from qrp2p.core.crypto.profiles import ProfileId
from qrp2p.services import vault as vault_module
from qrp2p.services.models import (
    Appearance,
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
from qrp2p.services.vault import (
    DB_FILE,
    KDF_FLOOR,
    LOCK_FILE,
    PAD_BLOCK,
    VAULT_FILE,
    VAULT_FILE_NEW,
    KdfParams,
    KdfPolicy,
    NoVaultError,
    PasswordChangeCleanupError,
    Vault,
    VaultCorruptError,
    VaultExistsError,
    VaultFile,
    VaultHeader,
    VaultInUseError,
    VaultLockedError,
    WrongPasswordError,
    associated_data,
    calibrated_kek,
    pad,
    unpad,
)
from tests.support import identity_from_label

CHEAP = KdfPolicy(floor=KdfParams(t=1, m_kib=64, p=1), target_seconds=0)
"""Argon2id parameters far below the floor, so tests stay fast. Never used by the app."""


@pytest.fixture(autouse=True)
def close_vaults(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every vault a test opened, so no database connection outlives its test."""
    opened: list[Vault] = []
    original = Vault.__init__

    def tracking_init(self: Vault, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(Vault, "__init__", tracking_init)
    yield
    for vault in opened:
        if vault._open is not None:
            vault._open.db.close()
            vault._open = None
        vault.close()


class MemoryKeychain:
    def __init__(self) -> None:
        self.items: dict[bytes, bytes] = {}

    def get(self, vault_id: bytes) -> bytes | None:
        return self.items.get(vault_id)

    def set(self, vault_id: bytes, key: bytes) -> None:
        self.items[vault_id] = key

    def delete(self, vault_id: bytes) -> None:
        self.items.pop(vault_id, None)


def make_vault(tmp_path: Path, password: str = "correct horse") -> Vault:
    vault = Vault(tmp_path / "data", kdf=CHEAP)
    vault.create(password, Settings(display_name="Alice"))
    return vault


def reopen(vault: Vault, password: str = "correct horse") -> Vault:
    vault.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock(password)
    return fresh


def attempt(directory: Path, password: str) -> None:
    """Unlock in a fresh vault object, then release the directory whatever happens."""
    fresh = Vault(directory, kdf=CHEAP)
    try:
        fresh.unlock(password)
    finally:
        fresh.close()


def contact(vault: Vault, label: str = "bob", **changes: object) -> Contact:
    contact_id, conv_id = vault.new_contact_ids()
    base = Contact(
        contact_id=contact_id,
        conv_id=conv_id,
        bundle=identity_from_label(label).bundle,
        name=label.title(),
        created=1000.0,
    )
    return replace(base, **changes)


def chat_entry(vault: Vault, text: str, time: float = 2000.0) -> HistoryEntry:
    return HistoryEntry(
        entry_id=vault.new_entry_id(),
        kind=MessageKind.CHAT,
        direction=Direction.OUT,
        time=time,
        message_id=b"m" * 16,
        status=MessageStatus.SENDING,
        text=text,
    )


# --- files and keys -------------------------------------------------------------------------------


def test_create_and_unlock(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    identity = vault.identity()
    again = reopen(vault)
    assert again.identity().bundle == identity.bundle
    assert again.settings().display_name == "Alice"


def test_wrong_password(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.close()
    with pytest.raises(WrongPasswordError):
        attempt(vault.directory, "wrong")


def test_unlock_without_vault(tmp_path: Path) -> None:
    with pytest.raises(NoVaultError):
        Vault(tmp_path, kdf=CHEAP).unlock("x")


def test_create_twice_is_refused(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    with pytest.raises(VaultExistsError):
        vault.create("again")


def test_empty_password_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="empty"):
        Vault(tmp_path, kdf=CHEAP).create("")


def test_password_is_nfc_normalised(tmp_path: Path) -> None:
    vault = make_vault(tmp_path, password="caf\u00e9")
    vault.close()
    attempt(vault.directory, "cafe\u0301")  # the same text, decomposed


def test_orphan_database_from_a_crashed_creation_is_replaced(tmp_path: Path) -> None:
    directory = tmp_path / "data"
    directory.mkdir()
    (directory / DB_FILE).write_bytes(b"left over")
    Vault(directory, kdf=CHEAP).create("pw")


def test_kdf_floor_is_the_designed_one() -> None:
    assert KdfParams(t=3, m_kib=256 * 1024, p=4) == KDF_FLOOR
    assert vault_module.DEFAULT_KDF.floor == KDF_FLOOR


def test_calibration_only_raises_the_cost() -> None:
    ticks = iter([0.0, 0.1, 0.2, 0.3])
    params, _ = calibrated_kek("pw", bytes(16), KdfPolicy(CHEAP.floor, 1.0), lambda: next(ticks))
    assert params.t == 10  # 0.1 s at t=1: scale to about 1 s
    assert params.m_kib == CHEAP.floor.m_kib
    slow = iter([0.0, 5.0])
    params, _ = calibrated_kek("pw", bytes(16), KdfPolicy(CHEAP.floor, 1.0), lambda: next(slow))
    assert params == CHEAP.floor


def test_vault_json_holds_no_key_material(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    doc = json.loads((vault.directory / VAULT_FILE).read_text())
    assert set(doc) == {
        "format",
        "format_version",
        "vault_id",
        "kdf",
        "salt",
        "wrapped_dek",
        "device_kek",
    }
    assert doc["kdf"] == {"algorithm": "argon2id", "t": 1, "m_kib": 64, "p": 1}
    assert len(bytes.fromhex(doc["wrapped_dek"])) == 12 + 32 + 16


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("vault_id", "00" * 16),
        ("salt", "11" * 16),
        ("kdf", {"algorithm": "argon2id", "t": 2, "m_kib": 64, "p": 1}),
    ],
)
def test_wrapped_dek_is_bound_to_the_header(tmp_path: Path, field: str, value: object) -> None:
    vault = make_vault(tmp_path)
    vault.close()
    path = vault.directory / VAULT_FILE
    doc = json.loads(path.read_text())
    doc[field] = value
    path.write_text(json.dumps(doc))
    with pytest.raises(WrongPasswordError):
        attempt(vault.directory, "correct horse")


@pytest.mark.parametrize(
    "kdf",
    [
        {"algorithm": "argon2id", "t": 3, "m_kib": 2**40, "p": 4},
        {"algorithm": "argon2id", "t": 0, "m_kib": 64, "p": 1},
        {"algorithm": "scrypt", "t": 3, "m_kib": 64, "p": 1},
    ],
)
def test_hostile_kdf_parameters_are_refused(tmp_path: Path, kdf: dict[str, object]) -> None:
    vault = make_vault(tmp_path)
    vault.close()
    path = vault.directory / VAULT_FILE
    doc = json.loads(path.read_text())
    doc["kdf"] = kdf
    path.write_text(json.dumps(doc))
    with pytest.raises(VaultCorruptError):
        attempt(vault.directory, "correct horse")


def test_vault_json_rejects_unknown_fields() -> None:
    with pytest.raises(VaultCorruptError):
        VaultFile.from_json(b'{"format": "qrp2p-vault", "extra": 1}')


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_files_are_private(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    assert vault.directory.stat().st_mode & 0o777 == 0o700
    for name in (VAULT_FILE, DB_FILE, LOCK_FILE):
        assert (vault.directory / name).stat().st_mode & 0o777 == 0o600


# --- rows -----------------------------------------------------------------------------------------


def test_associated_data_layout() -> None:
    uid = bytes(range(16))
    assert associated_data("contacts", uid, "data") == (
        b"\x00\x0c" + b"qrp2p2 vault" + b"\x00\x01" + b"\x00\x08contacts" + uid + b"\x00\x04data"
    )


@pytest.mark.parametrize("n", [0, 1, 62, 63, 64, 65, 127, 128, 200])
def test_padding_round_trips_to_64_byte_buckets(n: int) -> None:
    data = bytes([0]) * n  # zeros at the end must survive
    padded = pad(data)
    assert len(padded) % PAD_BLOCK == 0
    assert len(padded) - n <= PAD_BLOCK
    assert unpad(padded) == data


@pytest.mark.parametrize(
    "bad",
    [
        b"",
        bytes(64),
        b"\x80" + bytes(127),
        b"x" * 63 + b"\x81",
        b"x" * 65,
        b"a" * 63 + b"\x80\x00",  # well formed, but not a whole number of blocks
    ],
)
def test_malformed_padding_is_refused(bad: bytes) -> None:
    with pytest.raises(VaultCorruptError):
        unpad(bad)


def test_contacts_round_trip(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault, trust=TrustState.VERIFIED, address=("192.0.2.1", 47470))
    vault.save_contact(bob)
    carol = contact(vault, "carol", profile_id=ProfileId.PQ_CNSA_1)
    vault.save_contact(carol)
    vault.save_contact(replace(carol, name="Carol C."))
    again = reopen(vault)
    found = {c.contact_id: c for c in again.contacts()}
    assert found[bob.contact_id] == bob
    assert found[carol.contact_id] == replace(carol, name="Carol C.")
    again.delete_contact(bob)
    assert [c.contact_id for c in again.contacts()] == [carol.contact_id]


def test_swapped_rows_fail_to_authenticate(tmp_path: Path) -> None:
    """A value is bound to its row: moving it to another row_uid is detected."""
    vault = make_vault(tmp_path)
    bob, carol = contact(vault), contact(vault, "carol")
    vault.save_contact(bob)
    vault.save_contact(carol)
    vault.close()
    db = sqlite3.connect(vault.directory / DB_FILE)
    rows = dict(db.execute("SELECT row_uid, data FROM contacts").fetchall())
    db.execute(
        "UPDATE contacts SET data = ? WHERE row_uid = ?", (rows[carol.contact_id], bob.contact_id)
    )
    db.commit()
    db.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock("correct horse")
    with pytest.raises(VaultCorruptError):
        fresh.contacts()


def test_value_moved_to_another_table_fails(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.close()
    db = sqlite3.connect(vault.directory / DB_FILE)
    (settings_uid, settings_value) = db.execute("SELECT row_uid, data FROM settings").fetchone()
    db.execute(
        "INSERT INTO contacts (row_uid, conv_id, data) VALUES (?, ?, ?)",
        (settings_uid, bytes(16), settings_value),
    )
    db.commit()
    db.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock("correct horse")
    with pytest.raises(VaultCorruptError):
        fresh.contacts()


def test_history_round_trip_and_status_update(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    first = chat_entry(vault, "one")
    second = chat_entry(vault, "two")
    file_entry = HistoryEntry(
        entry_id=vault.new_entry_id(),
        kind=MessageKind.FILE,
        direction=Direction.IN,
        time=3000.0,
        file=FileInfo(
            file_id=b"f" * 16,
            name="report.pdf",
            size=1234,
            media_type="application/pdf",
            status=FileStatus.COMPLETE,
            sha256=bytes(32),
            path="/tmp/report.pdf",  # noqa: S108
        ),
    )
    for entry in (first, second, file_entry):
        vault.add_entry(bob.conv_id, entry)
    vault.update_entry(bob.conv_id, replace(first, status=MessageStatus.DELIVERED))
    again = reopen(vault)
    history = again.history(bob.conv_id)
    assert [e.text for e in history] == ["one", "two", ""]
    assert history[0].status is MessageStatus.DELIVERED
    assert history[2] == file_entry
    assert [e.text for e in again.history(bob.conv_id, limit=2)] == ["two", ""]


def test_rows_survive_vacuum(tmp_path: Path) -> None:
    """Associated data uses row_uid, never SQLite's rowid, which VACUUM renumbers."""
    vault = make_vault(tmp_path)
    contacts = [contact(vault, f"peer{n}") for n in range(6)]
    for c in contacts:
        vault.save_contact(c)
        for n in range(5):
            vault.add_entry(c.conv_id, chat_entry(vault, f"{c.name} {n}"))
    for c in contacts[:3]:
        vault.delete_contact(c)  # deletes rows and runs VACUUM
    again = reopen(vault)
    assert {c.contact_id for c in again.contacts()} == {c.contact_id for c in contacts[3:]}
    for c in contacts[3:]:
        assert [e.text for e in again.history(c.conv_id)] == [f"{c.name} {n}" for n in range(5)]


def test_deleted_conversation_leaves_no_ciphertext(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    for n in range(20):
        vault.add_entry(bob.conv_id, chat_entry(vault, f"secret message {n}" * 20))
    db = sqlite3.connect(vault.directory / DB_FILE)
    ciphertexts = [row[0] for row in db.execute("SELECT data FROM messages").fetchall()]
    (wrapped_ck,) = db.execute("SELECT ck FROM conv_keys").fetchone()
    db.close()
    updated = vault.delete_conversation(bob)
    assert updated.conv_id != bob.conv_id
    assert vault.history(updated.conv_id) == []
    on_disk = b"".join(
        path.read_bytes() for path in vault.directory.iterdir() if path.name.startswith(DB_FILE)
    )
    assert wrapped_ck not in on_disk
    assert not any(c[12:44] in on_disk for c in ciphertexts)
    vault.add_entry(updated.conv_id, chat_entry(vault, "after"))
    assert [e.text for e in reopen(vault).history(updated.conv_id)] == ["after"]


def test_corrupted_row_is_reported(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    vault.close()
    db = sqlite3.connect(vault.directory / DB_FILE)
    (value,) = db.execute("SELECT data FROM contacts").fetchone()
    flipped = value[:-1] + bytes([value[-1] ^ 1])
    db.execute("UPDATE contacts SET data = ?", (flipped,))
    db.commit()
    db.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock("correct horse")
    with pytest.raises(VaultCorruptError):
        fresh.contacts()


# --- password change and device unlock ------------------------------------------------------------


def test_change_password(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    vault.add_entry(bob.conv_id, chat_entry(vault, "kept"))
    old_json = (vault.directory / VAULT_FILE).read_bytes()
    with pytest.raises(WrongPasswordError):
        vault.change_password("wrong", "new password")
    vault.change_password("correct horse", "new password")
    again = reopen(vault, "new password")
    assert [e.text for e in again.history(bob.conv_id)] == ["kept"]
    again.close()
    with pytest.raises(WrongPasswordError):
        attempt(vault.directory, "correct horse")
    # An old vault.json with the old password opens nothing in the current database.
    (vault.directory / VAULT_FILE).write_bytes(old_json)
    with pytest.raises(WrongPasswordError):
        attempt(vault.directory, "correct horse")


def test_password_change_interrupted_after_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Crash after the database was re-encrypted, before vault.json was replaced."""
    vault = make_vault(tmp_path)
    real_write = vault_module.write_private_file

    def crash_on_vault_json(path: Path, data: bytes) -> None:
        if path.name == VAULT_FILE:
            raise KeyboardInterrupt  # the process dies here
        real_write(path, data)

    monkeypatch.setattr(vault_module, "write_private_file", crash_on_vault_json)
    with pytest.raises(KeyboardInterrupt):
        vault.change_password("correct horse", "new password")
    monkeypatch.undo()
    assert vault._open is not None
    vault._open.db.close()  # the crashed process's state is gone
    vault._open = None
    vault.close()
    assert (vault.directory / VAULT_FILE_NEW).exists()
    fresh = Vault(vault.directory, kdf=CHEAP)
    with pytest.raises(WrongPasswordError):
        fresh.unlock("correct horse")
    fresh.unlock("new password")
    assert not (vault.directory / VAULT_FILE_NEW).exists()
    fresh.close()
    attempt(vault.directory, "new password")


def test_password_change_interrupted_before_commit(tmp_path: Path) -> None:
    """Crash after vault.json.new was written, before the database commit."""
    vault = make_vault(tmp_path)
    vault.close()
    other = Vault(tmp_path / "other", kdf=CHEAP)
    other.create("new password")
    other.close()
    (vault.directory / VAULT_FILE_NEW).write_bytes((other.directory / VAULT_FILE).read_bytes())
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock("correct horse")
    assert not (vault.directory / VAULT_FILE_NEW).exists()


def test_device_unlock(tmp_path: Path) -> None:
    keychain = MemoryKeychain()
    vault = make_vault(tmp_path)
    identity = vault.identity().bundle
    vault.enable_device_unlock(keychain)
    assert vault.device_unlock_enabled
    vault.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    assert fresh.unlock_with_device(keychain).bundle == identity
    fresh.change_password("correct horse", "new", keychain)
    fresh.close()
    again = Vault(vault.directory, kdf=CHEAP)
    again.unlock_with_device(keychain)
    again.disable_device_unlock(keychain)
    assert keychain.items == {}
    again.close()
    with pytest.raises(WrongPasswordError):
        Vault(vault.directory, kdf=CHEAP).unlock_with_device(keychain)


def test_password_change_without_keychain_drops_device_unlock(tmp_path: Path) -> None:
    keychain = MemoryKeychain()
    vault = make_vault(tmp_path)
    vault.enable_device_unlock(keychain)
    vault.change_password("correct horse", "new")
    assert not vault.device_unlock_enabled
    vault.close()
    with pytest.raises(WrongPasswordError):
        Vault(vault.directory, kdf=CHEAP).unlock_with_device(keychain)


def test_wrong_device_key_is_refused(tmp_path: Path) -> None:
    keychain = MemoryKeychain()
    vault = make_vault(tmp_path)
    vault.enable_device_unlock(keychain)
    vault.close()
    for vault_id in keychain.items:
        keychain.items[vault_id] = bytes(32)
    with pytest.raises(WrongPasswordError):
        Vault(vault.directory, kdf=CHEAP).unlock_with_device(keychain)


# --- lock, instance lock, retention ---------------------------------------------------------------


def test_lock_drops_keys_and_truncates_the_wal(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.save_contact(contact(vault))
    vault.lock()
    assert not vault.is_unlocked
    with pytest.raises(VaultLockedError):
        vault.contacts()
    wal = vault.directory / (DB_FILE + "-wal")
    assert not wal.exists() or wal.stat().st_size == 0
    vault.lock()  # a second lock is harmless (v1 regression 6: locking never raises)
    vault.unlock("correct horse")
    assert len(vault.contacts()) == 1


def test_lock_succeeds_on_a_damaged_database(tmp_path: Path) -> None:
    """Locking never fails (v1 regression 6), even when the purge before it cannot read."""
    vault = make_vault(tmp_path)
    vault.save_contact(contact(vault))
    state = vault._open
    assert state is not None
    state.db.execute("UPDATE contacts SET data = x'00'")
    vault.lock()
    assert not vault.is_unlocked


def test_second_process_is_refused(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    with pytest.raises(VaultInUseError):
        attempt(vault.directory, "correct horse")
    vault.close()
    attempt(vault.directory, "correct horse")


def test_stale_lock_file_does_not_block(tmp_path: Path) -> None:
    """v1 regression 5: a lock file left by a crashed process must not block the vault."""
    vault = make_vault(tmp_path)
    vault.close()
    lock_file = vault.directory / LOCK_FILE
    lock_file.write_text("12345")  # what a dead process might leave behind
    attempt(vault.directory, "correct horse")


def test_retention(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    monthly = contact(vault, "monthly", retention=Retention.DAYS_30)
    ephemeral = contact(vault, "ephemeral", retention=Retention.SESSION)
    forever = contact(vault, "forever")
    day = 86_400.0
    now = 100 * day
    for c in (monthly, ephemeral, forever):
        vault.save_contact(c)
        vault.add_entry(c.conv_id, chat_entry(vault, "old", time=now - 31 * day))
        vault.add_entry(c.conv_id, chat_entry(vault, "new", time=now - 1 * day))
    assert vault.purge_expired(now) == 1
    assert [e.text for e in vault.history(monthly.conv_id)] == ["new"]
    assert len(vault.history(forever.conv_id)) == 2
    vault.lock()
    vault.unlock("correct horse")
    assert vault.history(ephemeral.conv_id) == []
    assert len(vault.history(forever.conv_id)) == 2


# --- found by mutation testing of the services ----------------------------------------------------


def test_header_layout_matches_the_design() -> None:
    """Known answer for DESIGN §10.2: every field, width and byte order."""
    header = VaultHeader(bytes(range(16)), KdfParams(t=3, m_kib=262_144, p=4), bytes(range(16, 32)))
    expected = (
        b"\x00\x13qrp2p2 vault header"
        b"\x00\x01"  # format_version
        + bytes(range(16))  # vault_id
        + b"\x01"  # Argon2id
        + b"\x00\x00\x00\x03"
        + b"\x00\x04\x00\x00"
        + b"\x00\x00\x00\x04"
        + bytes(range(16, 32))
    )
    assert header.encode() == expected


@pytest.mark.parametrize(
    ("params", "ok"),
    [
        (KdfParams(t=1000, m_kib=64, p=1), True),
        (KdfParams(t=1001, m_kib=64, p=1), False),
        (KdfParams(t=1, m_kib=512, p=64), True),
        (KdfParams(t=1, m_kib=520, p=65), False),
        (KdfParams(t=1, m_kib=32, p=4), True),  # m = 8p exactly
        (KdfParams(t=1, m_kib=31, p=4), False),
        (KdfParams(t=1, m_kib=4 * 2**20, p=1), True),
        (KdfParams(t=1, m_kib=4 * 2**20 + 1, p=1), False),
    ],
)
def test_kdf_parameter_bounds(params: KdfParams, ok: bool) -> None:
    if ok:
        params.check()
    else:
        with pytest.raises(VaultCorruptError):
            params.check()


@pytest.mark.parametrize(
    ("elapsed", "expected_t"),
    [
        (0.5, 1),  # half the target: good enough
        (0.6, 1),
        (0.4, 3),  # too fast: scale t up to reach about 1 s
        (0.125, 8),
    ],
)
def test_calibration_thresholds(elapsed: float, expected_t: int) -> None:
    ticks = iter([100.0, 100.0 + elapsed, 200.0, 201.0])
    policy = KdfPolicy(CHEAP.floor, target_seconds=1.0)
    params, _ = calibrated_kek("pw", bytes(16), policy, lambda: next(ticks))
    assert params.t == expected_t


@pytest.mark.parametrize(
    ("field", "value"),
    [("format", "qrp2p-vaultz"), ("vault_id", "00" * 15), ("salt", "00" * 15)],
)
def test_vault_json_fields_are_each_checked(tmp_path: Path, field: str, value: str) -> None:
    vault = make_vault(tmp_path)
    doc = json.loads((vault.directory / VAULT_FILE).read_text())
    doc[field] = value
    with pytest.raises(VaultCorruptError):
        VaultFile.from_json(json.dumps(doc).encode())


def test_padding_with_a_whole_block_of_zeros_is_not_canonical() -> None:
    with pytest.raises(VaultCorruptError):
        unpad(b"a" * 63 + b"\x80" + bytes(64))


def test_second_process_is_refused_at_once(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    started = time.monotonic()
    with pytest.raises(VaultInUseError):
        Vault(vault.directory, kdf=CHEAP).acquire()
    assert time.monotonic() - started < 0.5


def test_device_unlock_after_an_interrupted_password_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keychain = MemoryKeychain()
    vault = make_vault(tmp_path)
    vault.enable_device_unlock(keychain)
    real_write = vault_module.write_private_file

    def crash_on_vault_json(path: Path, data: bytes) -> None:
        if path.name == VAULT_FILE:
            raise KeyboardInterrupt
        real_write(path, data)

    monkeypatch.setattr(vault_module, "write_private_file", crash_on_vault_json)
    with pytest.raises(KeyboardInterrupt):
        vault.change_password("correct horse", "new", keychain)
    monkeypatch.undo()
    assert vault._open is not None
    vault._open.db.close()
    vault._open = None
    vault.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock_with_device(keychain)  # the old vault.json does not match; .new does
    assert not (vault.directory / VAULT_FILE_NEW).exists()
    fresh.close()
    attempt(vault.directory, "new")


def test_a_device_key_of_the_wrong_length_is_refused(tmp_path: Path) -> None:
    keychain = MemoryKeychain()
    vault = make_vault(tmp_path)
    vault.enable_device_unlock(keychain)
    for vault_id in keychain.items:
        keychain.items[vault_id] = b"short"
    vault.change_password("correct horse", "new", keychain)
    assert not vault.device_unlock_enabled  # the key could not wrap the new KEK
    vault.close()
    with pytest.raises(WrongPasswordError):
        Vault(vault.directory, kdf=CHEAP).unlock_with_device(keychain)


def test_password_can_change_twice(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.change_password("correct horse", "second")
    vault.change_password("second", "third")
    attempt(reopen_path(vault), "third")


def reopen_path(vault: Vault) -> Path:
    vault.close()
    return vault.directory


def test_a_failed_rekey_leaves_the_vault_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    vault.add_entry(bob.conv_id, chat_entry(vault, "kept"))

    def broken(*_: object) -> None:
        msg = "disk I/O error"
        raise sqlite3.OperationalError(msg)

    monkeypatch.setattr(vault, "_put_identity", broken)
    with pytest.raises(sqlite3.OperationalError):
        vault.change_password("correct horse", "new")
    monkeypatch.undo()
    assert [e.text for e in vault.history(bob.conv_id)] == ["kept"]  # old keys still work
    assert (vault.directory / VAULT_FILE_NEW).exists()
    path = reopen_path(vault)
    attempt(path, "correct horse")
    assert not (path / VAULT_FILE_NEW).exists()


@pytest.mark.parametrize("statement", ["VACUUM", "PRAGMA wal_checkpoint(TRUNCATE)"])
def test_password_change_cleanup_failure_preserves_committed_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, statement: str
) -> None:
    real_connect = sqlite3.connect
    fail = False

    class CleanupFailure(sqlite3.Connection):
        def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:  # noqa: ANN401
            if fail and sql == statement:
                msg = "injected cleanup failure"
                raise sqlite3.OperationalError(msg)
            return super().execute(sql, parameters)

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:  # noqa: ANN401
        return real_connect(*args, **kwargs, factory=CleanupFailure)

    monkeypatch.setattr(vault_module.sqlite3, "connect", connect)
    vault = make_vault(tmp_path)
    identity = vault.identity().bundle
    bob = contact(vault)
    vault.save_contact(bob)
    vault.add_entry(bob.conv_id, chat_entry(vault, "kept"))
    fail = True
    with pytest.raises(PasswordChangeCleanupError, match="password changed"):
        vault.change_password("correct horse", "new")
    fail = False
    assert vault.identity().bundle == identity
    assert [e.text for e in vault.history(bob.conv_id)] == ["kept"]
    fresh = reopen(vault, "new")
    assert fresh.identity().bundle == identity
    assert [e.text for e in fresh.history(bob.conv_id)] == ["kept"]
    fresh.close()
    with pytest.raises(WrongPasswordError):
        attempt(vault.directory, "correct horse")


def test_retry_after_failed_header_promotion_preserves_current_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = make_vault(tmp_path)
    real_write = vault_module.write_private_file

    def fail_promotion(path: Path, data: bytes) -> None:
        if path.name == VAULT_FILE:
            msg = "injected header failure"
            raise OSError(msg)
        real_write(path, data)

    monkeypatch.setattr(vault_module, "write_private_file", fail_promotion)
    with pytest.raises(OSError, match="injected header failure"):
        vault.change_password("correct horse", "second")
    monkeypatch.setattr(vault_module, "write_private_file", real_write)

    def fail_rekey(*_: object) -> None:
        msg = "injected rekey failure"
        raise sqlite3.OperationalError(msg)

    monkeypatch.setattr(vault, "_put_identity", fail_rekey)
    with pytest.raises(sqlite3.OperationalError, match="injected rekey failure"):
        vault.change_password("second", "third")
    monkeypatch.undo()
    attempt(reopen_path(vault), "second")


@pytest.mark.parametrize("committed", [False, True])
def test_rotation_commit_error_closes_vault_and_recovers_matching_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, committed: bool
) -> None:
    real_connect = sqlite3.connect
    fail = False

    class CommitFailure(sqlite3.Connection):
        def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:  # noqa: ANN401
            if fail and sql == "COMMIT":
                if committed:
                    super().execute(sql, parameters)
                msg = "injected commit failure"
                raise sqlite3.OperationalError(msg)
            return super().execute(sql, parameters)

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:  # noqa: ANN401
        return real_connect(*args, **kwargs, factory=CommitFailure)

    monkeypatch.setattr(vault_module.sqlite3, "connect", connect)
    vault = make_vault(tmp_path)
    identity = vault.identity().bundle
    bob = contact(vault)
    vault.save_contact(bob)
    vault.add_entry(bob.conv_id, chat_entry(vault, "kept"))
    fail = True
    with pytest.raises(sqlite3.OperationalError, match="injected commit failure"):
        vault.change_password("correct horse", "new")
    fail = False
    assert not vault.is_unlocked
    assert (vault.directory / VAULT_FILE_NEW).exists()
    with pytest.raises(VaultLockedError):
        vault.change_password("correct horse", "third")
    vault.close()
    fresh = Vault(vault.directory, kdf=CHEAP)
    fresh.unlock("new" if committed else "correct horse")
    assert fresh.identity().bundle == identity
    assert [e.text for e in fresh.history(bob.conv_id)] == ["kept"]


def test_unlocking_again_closes_the_previous_database(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    assert vault._open is not None
    first = vault._open.db
    vault.unlock("correct horse")
    with pytest.raises(sqlite3.ProgrammingError):
        first.execute("SELECT 1")


@pytest.mark.parametrize("change", ["DELETE FROM meta", "UPDATE meta SET value = '2'"])
def test_a_database_of_another_schema_does_not_open(tmp_path: Path, change: str) -> None:
    vault = make_vault(tmp_path)
    vault.close()
    db = sqlite3.connect(vault.directory / DB_FILE)
    db.execute(change)
    db.commit()
    db.close()
    with pytest.raises(WrongPasswordError):
        attempt(vault.directory, "correct horse")


def test_every_setting_round_trips_in_one_row(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    settings = Settings(
        display_name="Zed",
        announce_name=False,
        default_profile=ProfileId.PQ_CNSA_1,
        default_retention=Retention.DAYS_30,
        auto_lock_minutes=3,
        port=40000,
        downloads_dir="/somewhere",
        max_file_size=123,
        appearance=Appearance.DARK,
        reduced_motion=True,
        text_scale=130,
    )
    vault.save_settings(Settings())
    vault.save_settings(settings)
    again = reopen(vault)
    assert again.settings() == settings
    assert again._state().db.execute("SELECT count(*) FROM settings").fetchone() == (1,)


def test_settings_of_a_newer_version_fall_back_to_defaults(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    vault.save_settings(Settings(display_name="Zed"))
    uid = vault._state().db.execute("SELECT row_uid FROM settings").fetchone()[0]
    row = msgspec.msgpack.encode(
        {"display_name": "Zed", "appearance": "sepia", "text_scale": 999, "future_field": 1}
    )
    sealed = vault._seal_row(vault._key("settings"), "settings", uid, "data", row)
    with vault._transaction():
        vault._state().db.execute("UPDATE settings SET data = ?", (sealed,))
    settings = reopen(vault).settings()
    assert settings.display_name == "Zed"
    assert settings.appearance is Appearance.SYSTEM
    assert settings.text_scale == 100


def test_every_contact_field_round_trips(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    full = contact(
        vault,
        trust=TrustState.VERIFIED,
        profile_id=ProfileId.PQ_CNSA_1,
        retention=Retention.DAYS_30,
        auto_accept_files=True,
        auto_accept_limit=4096,
        address=("fe80::1%eth0", 1234),
        created=42.5,
    )
    vault.save_contact(full)
    assert reopen(vault).contacts() == [full]


def test_every_history_field_round_trips(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    entry = HistoryEntry(
        entry_id=vault.new_entry_id(),
        kind=MessageKind.FILE,
        direction=Direction.OUT,
        time=7.25,
        message_id=b"i" * 16,
        status=MessageStatus.FAILED,
        text="note",
        file=FileInfo(
            file_id=b"f" * 16,
            name="x.bin",
            size=9,
            media_type="a/b",
            status=FileStatus.CANCELLED,
            sha256=b"h" * 32,
            path="p",
            reason="hash_mismatch",
        ),
        glass_box=True,
    )
    vault.add_entry(bob.conv_id, entry)
    assert reopen(vault).history(bob.conv_id) == [entry]


def test_deleting_a_contact_deletes_its_conversation(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    vault.add_entry(bob.conv_id, chat_entry(vault, "gone"))
    vault.delete_contact(bob)
    db = vault._state().db
    assert db.execute("SELECT count(*) FROM messages").fetchone() == (0,)
    assert db.execute("SELECT count(*) FROM conv_keys").fetchone() == (0,)
    assert bob.conv_id not in vault._state().conv_keys  # the key is gone from memory too


def test_deleting_a_conversation_forgets_its_key(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob = contact(vault)
    vault.save_contact(bob)
    vault.add_entry(bob.conv_id, chat_entry(vault, "gone"))
    vault.delete_conversation(bob)
    assert bob.conv_id not in vault._state().conv_keys


def test_retention_boundaries_and_counts(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    day = 86_400.0
    now = 100 * day
    keepers = [contact(vault, f"keeper{n}") for n in range(5)]  # forever, in any row order
    monthly = [contact(vault, f"monthly{n}", retention=Retention.DAYS_30) for n in range(2)]
    ephemeral = [contact(vault, f"eph{n}", retention=Retention.SESSION) for n in range(2)]
    for c in (*keepers, *monthly, *ephemeral):
        vault.save_contact(c)
        vault.add_entry(c.conv_id, chat_entry(vault, "old", time=now - 31 * day))
        vault.add_entry(c.conv_id, chat_entry(vault, "edge", time=now - 30 * day))
    assert vault.purge_expired(now) == 2  # one per monthly contact; the edge is kept
    for c in monthly:
        assert [e.text for e in vault.history(c.conv_id)] == ["edge"]
    assert vault.purge_expired(now) == 0
    assert vault.purge_session_only() == 4
    assert vault.purge_session_only() == 0


def test_device_unlock_with_an_emptied_keychain(tmp_path: Path) -> None:
    keychain = MemoryKeychain()
    vault = make_vault(tmp_path)
    vault.enable_device_unlock(keychain)
    vault.close()
    keychain.items.clear()  # the user removed the entry from the OS keychain
    with pytest.raises(WrongPasswordError):
        Vault(vault.directory, kdf=CHEAP).unlock_with_device(keychain)


# --- found on the LAN test --------------------------------------------------------------------------


def file_entry(
    vault: Vault, status: FileStatus, direction: Direction = Direction.IN, path: str = ""
) -> HistoryEntry:
    return HistoryEntry(
        entry_id=vault.new_entry_id(),
        kind=MessageKind.FILE,
        direction=direction,
        time=3000.0,
        file=FileInfo(
            file_id=vault.new_entry_id(),
            name="big.bin",
            size=1 << 30,
            media_type="application/octet-stream",
            status=status,
            path=path,
        ),
    )


def test_a_crash_leaves_nothing_in_flight(tmp_path: Path) -> None:
    vault = make_vault(tmp_path)
    bob, carol = contact(vault), contact(vault, "carol")
    vault.save_contact(bob)
    vault.save_contact(carol)
    sending = chat_entry(vault, "never left")
    delivered = replace(chat_entry(vault, "arrived"), status=MessageStatus.DELIVERED)
    downloading = file_entry(vault, FileStatus.TRANSFERRING, path="/dl/big.bin")
    accepted = file_entry(vault, FileStatus.ACCEPTED, path="/dl/other.bin")
    offered_in = file_entry(vault, FileStatus.OFFERED)
    uploading = file_entry(vault, FileStatus.TRANSFERRING, Direction.OUT, path="/src/up.bin")
    complete = file_entry(vault, FileStatus.COMPLETE, path="/dl/done.bin")
    for entry in (sending, delivered, downloading, offered_in, complete):
        vault.add_entry(bob.conv_id, entry)
    for entry in (accepted, uploading):
        vault.add_entry(carol.conv_id, entry)

    assert sorted(vault.fail_interrupted()) == ["/dl/big.bin", "/dl/other.bin"]  # downloads only

    again = reopen(vault)
    at_bob = {e.entry_id: e for e in again.history(bob.conv_id)}
    at_carol = {e.entry_id: e for e in again.history(carol.conv_id)}
    assert at_bob[sending.entry_id].status is MessageStatus.FAILED
    assert at_bob[delivered.entry_id] == delivered
    assert at_bob[complete.entry_id] == complete
    for entry in (at_bob[downloading.entry_id], at_bob[offered_in.entry_id]):
        assert entry.file is not None
        assert entry.file.status is FileStatus.FAILED
    for entry in at_carol.values():
        assert entry.file is not None
        assert entry.file.status is FileStatus.FAILED
    assert downloading.file is not None
    assert at_bob[downloading.entry_id].file == replace(
        downloading.file, status=FileStatus.FAILED
    )  # nothing else changed
    assert again.fail_interrupted() == []  # once is enough
