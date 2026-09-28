"""The vault (DESIGN §10): key hierarchy, rows, deletion, password change, lock."""

import json
import sqlite3
import sys
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from qrp2p.core.crypto.profiles import ProfileId
from qrp2p.services import vault as vault_module
from qrp2p.services.models import (
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
    Vault,
    VaultCorruptError,
    VaultExistsError,
    VaultFile,
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
    for name in (VAULT_FILE, DB_FILE):
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
    "bad", [b"", bytes(64), b"\x80" + bytes(127), b"x" * 63 + b"\x81", b"x" * 65]
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
