"""Only OS keychains may hold the device key (DESIGN §10.4)."""

from types import SimpleNamespace
from typing import cast

import pytest
from keyring.backend import KeyringBackend
from keyring.backends.fail import Keyring as FailKeyring
from keyring.errors import PasswordSetError

from qrp2p.services.keychain import (
    SERVICE,
    KeychainUnavailableError,
    OsKeychain,
    backend_is_allowed,
)


class MemoryBackend(KeyringBackend):
    """A keyring backend kept in memory; registered under an allowed OS backend's name."""

    priority = 1  # pyright: ignore[reportAssignmentType]

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}
        self.refuse = False

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        if self.refuse:
            raise PasswordSetError
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        del self.store[(service, username)]


MemoryBackend.__module__ = "keyring.backends.SecretService"
MemoryBackend.__qualname__ = "Keyring"


def test_os_backends_are_allowed_and_others_refused() -> None:
    assert backend_is_allowed(MemoryBackend())
    assert not backend_is_allowed(FailKeyring())
    with pytest.raises(KeychainUnavailableError):
        OsKeychain(FailKeyring())


def test_a_chainer_is_allowed_only_if_every_member_is() -> None:
    def chainer(*members: KeyringBackend) -> KeyringBackend:
        fake = SimpleNamespace(backends=list(members))  # what ChainerBackend exposes
        return cast("KeyringBackend", fake)

    assert backend_is_allowed(chainer(MemoryBackend()))
    assert not backend_is_allowed(chainer(MemoryBackend(), FailKeyring()))
    assert not backend_is_allowed(chainer())


def test_store_read_and_delete() -> None:
    backend = MemoryBackend()
    keychain = OsKeychain(backend)
    vault_id, key = b"\x01" * 16, b"\x02" * 32
    assert keychain.get(vault_id) is None
    keychain.set(vault_id, key)
    assert keychain.get(vault_id) == key
    assert (SERVICE, vault_id.hex()) in backend.store
    keychain.delete(vault_id)
    keychain.delete(vault_id)  # absent: no error
    assert keychain.get(vault_id) is None


def test_garbage_in_the_keychain_reads_as_absent() -> None:
    backend = MemoryBackend()
    backend.store[(SERVICE, "01" * 16)] = "not base64!"
    assert OsKeychain(backend).get(b"\x01" * 16) is None


def test_a_refusing_keychain_is_reported() -> None:
    backend = MemoryBackend()
    backend.refuse = True
    with pytest.raises(KeychainUnavailableError):
        OsKeychain(backend).set(b"\x01" * 16, b"k" * 32)
