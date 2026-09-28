"""The OS keychain for "Remember on this device" (DESIGN §10.4).

Only the operating system's own stores are accepted: macOS Keychain, Windows Credential Locker
and the freedesktop Secret Service. ``keyring`` would otherwise fall back to backends that keep
the key in a plain file, or to a "fail" backend; those are refused, so opting in never silently
stores the device key somewhere weaker than the password it replaces.
"""

import base64
import binascii
from typing import Final

import keyring
import keyring.backend
import keyring.errors

SERVICE: Final = "qrp2p"
ALLOWED_BACKENDS: Final = frozenset(
    {
        "keyring.backends.macOS.Keyring",
        "keyring.backends.Windows.WinVaultKeyring",
        "keyring.backends.SecretService.Keyring",
    }
)


class KeychainUnavailableError(Exception):
    """No acceptable OS keychain is available."""


def _name(backend: keyring.backend.KeyringBackend) -> str:
    cls = type(backend)
    return f"{cls.__module__}.{cls.__qualname__}"


def backend_is_allowed(backend: keyring.backend.KeyringBackend) -> bool:
    """Whether ``backend`` (or every backend of a chainer) is an OS store."""
    backends = getattr(backend, "backends", None)
    if isinstance(backends, list | tuple):
        members: list[keyring.backend.KeyringBackend] = list(backends)  # pyright: ignore[reportUnknownArgumentType]
        return bool(members) and all(_name(b) in ALLOWED_BACKENDS for b in members)
    return _name(backend) in ALLOWED_BACKENDS


class OsKeychain:
    """A :class:`~qrp2p.services.vault.Keychain` on the OS keychain.

    Args:
        backend: The ``keyring`` backend; defaults to the active one.

    Raises:
        KeychainUnavailableError: The backend is not an OS store.
    """

    __slots__ = ("_backend",)

    def __init__(self, backend: keyring.backend.KeyringBackend | None = None) -> None:
        backend = backend if backend is not None else keyring.get_keyring()
        if not backend_is_allowed(backend):
            msg = "no OS keychain is available (macOS Keychain, Windows, or Secret Service)"
            raise KeychainUnavailableError(msg)
        self._backend = backend

    def get(self, vault_id: bytes) -> bytes | None:
        """See :class:`~qrp2p.services.vault.Keychain`."""
        try:
            value = self._backend.get_password(SERVICE, vault_id.hex())
        except keyring.errors.KeyringError:
            return None
        if value is None:
            return None
        try:
            return base64.b64decode(value, validate=True)
        except binascii.Error:
            return None

    def set(self, vault_id: bytes, key: bytes) -> None:
        """See :class:`~qrp2p.services.vault.Keychain`.

        Raises:
            KeychainUnavailableError: The keychain refused to store the key.
        """
        try:
            encoded = base64.b64encode(key).decode("ascii")
            # keyring wraps set_password in an untyped decorator
            self._backend.set_password(SERVICE, vault_id.hex(), encoded)  # pyright: ignore[reportUnknownMemberType]
        except keyring.errors.KeyringError:
            msg = "the OS keychain refused to store the device key"
            raise KeychainUnavailableError(msg) from None

    def delete(self, vault_id: bytes) -> None:
        """See :class:`~qrp2p.services.vault.Keychain`."""
        if self._backend.get_password(SERVICE, vault_id.hex()) is None:
            return
        try:
            self._backend.delete_password(SERVICE, vault_id.hex())
        except keyring.errors.KeyringError:
            msg = "the OS keychain refused to delete the device key"
            raise KeychainUnavailableError(msg) from None
