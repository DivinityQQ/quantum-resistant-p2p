"""
Secure storage for cryptographic keys with full metadata encryption.
"""

import os
import logging
import base64
import hmac
import hashlib
import json
import time
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path

# Use cryptography library for security primitives
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import our secure file utilities
from ..utils.secure_file import SecureFile

logger = logging.getLogger(__name__)


class KeyStorage:
    """Secure storage for cryptographic keys with full metadata encryption.
    
    This class provides complete encryption of all data and metadata, with no
    information leakage in the stored file. It uses Argon2id for key derivation
    and AES-GCM for encryption.
    """
    
    # Storage format version (for future extensions)
    FORMAT_VERSION = 1
    
    def __init__(self, storage_path: Optional[str] = None):
        """Initialize a new key storage instance.
        
        Args:
            storage_path: Path to the key storage file. If None, uses
                         ~/.quantum_resistant_p2p/keys.json.
        """
        if storage_path is None:
            # Use default path in user's home directory
            home_dir = Path.home()
            storage_dir = home_dir / ".quantum_resistant_p2p"
            storage_dir.mkdir(exist_ok=True, parents=True)
            self.storage_path = storage_dir / "keys.json"
        else:
            self.storage_path = Path(storage_path)
            # Make sure parent directory exists
            self.storage_path.parent.mkdir(exist_ok=True, parents=True)
        
        # In-memory key storage
        self.keys: Dict[str, Dict[str, Any]] = {}
        
        # Cryptographic keys - all None until unlocked
        self.master_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        self.hmac_key: Optional[bytes] = None
        
        # Create the secure file handler
        self.secure_file = SecureFile(self.storage_path)
        
        logger.info(f"Key storage initialized at {self.storage_path}")
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive a key from a password using Argon2id.
        
        Args:
            password: The user's password
            salt: Optional salt, generated randomly if None
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
        
        # Use Argon2id with OWASP-recommended parameters
        kdf = Argon2id(
            salt=salt,               # Salt value
            length=32,               # Output key length (256 bits)
            iterations=3,            # Iterations (time cost)
            lanes=4,                 # Parallelism parameter 
            memory_cost=102400,      # Memory cost (100 MiB)
        )
        
        derived_key = kdf.derive(password.encode())
        
        return derived_key, salt
    
    def _derive_encryption_keys(self) -> None:
        """Derive all encryption keys from the master key.
        
        This derives separate keys for different purposes to maintain
        proper cryptographic domain separation.
        """
        if self.master_key is None:
            raise ValueError("Cannot derive keys, storage not unlocked")
        
        # HMAC key for entry IDs
        self.hmac_key = hmac.new(
            key=self.master_key,
            msg=b"key_storage_hmac_key_v1",
            digestmod=hashlib.sha256
        ).digest()
    
    def _compute_entry_id(self, key_id: str) -> str:
        """Compute a deterministic but opaque entry ID for a key.
        
        Args:
            key_id: The original key ID
            
        Returns:
            An opaque entry ID for storage
        """
        if self.hmac_key is None:
            raise ValueError("HMAC key not available, storage not unlocked")
        
        # Create a keyed hash of the key ID using HMAC
        # This ensures the mapping is deterministic but only known to those with the key
        digest = hmac.new(
            key=self.hmac_key,
            msg=key_id.encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        
        return digest
    
    def _secure_zero(self, data: bytes) -> None:
        """Securely overwrite data in memory.
        
        Args:
            data: The data to overwrite
        """
        if isinstance(data, bytes) and hasattr(data, '__len__'):
            # Create a writable view of the bytes
            view = memoryview(data).cast('B')
            # Overwrite with zeroes
            for i in range(len(view)):
                view[i] = 0
    
    def unlock(self, password: str) -> bool:
        """Unlock the key storage with the given password.
        
        Args:
            password: The user's password
            
        Returns:
            True if unlock successful, False otherwise
        """
        try:
            # Read the storage file using SecureFile
            data = self.secure_file.read_json()
            
            if data is None:
                # First time use, create a new storage file
                self.salt = os.urandom(16)
                self.master_key, _ = self._derive_key(password, self.salt)
                self._derive_encryption_keys()
                return self._save_storage()
            
            # Check format version
            format_version = data.get('format_version', 0)
            if format_version != self.FORMAT_VERSION:
                logger.error(f"Unsupported storage format version: {format_version}")
                return False
            
            if 'salt' not in data:
                logger.error("Invalid key storage file, missing salt")
                return False
            
            # Derive the master key from the password
            salt = base64.b64decode(data['salt'])
            derived_key, _ = self._derive_key(password, salt)
            
            # Verify the password using the test value
            if 'test_nonce' in data and 'test_ciphertext' in data:
                try:
                    nonce = base64.b64decode(data['test_nonce'])
                    ciphertext = base64.b64decode(data['test_ciphertext'])
                    
                    aesgcm = AESGCM(derived_key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    if plaintext.decode() != "test_value":
                        logger.error("Password verification failed")
                        return False
                except Exception as e:
                    logger.error(f"Failed to decrypt test value, wrong password? {e}")
                    return False
            else:
                logger.error("Invalid key storage file, missing verification data")
                return False
            
            # Password verified, set the keys
            self.master_key = derived_key
            self.salt = salt
            self._derive_encryption_keys()
            
            # Load the encrypted keys
            if 'keys' not in data:
                logger.warning("No keys found in storage")
                return True
                
            aesgcm = AESGCM(self.master_key)
            
            for entry_id, encrypted_key_data in data['keys'].items():
                try:
                    # Decrypt the key data
                    nonce = base64.b64decode(encrypted_key_data['nonce'])
                    ciphertext = base64.b64decode(encrypted_key_data['ciphertext'])
                    
                    key_data_json = aesgcm.decrypt(nonce, ciphertext, None)
                    key_data = json.loads(key_data_json.decode())
                    
                    # Extract the original key_id from the decrypted data
                    if '__key_id' not in key_data:
                        logger.error(f"Missing key_id in entry {entry_id}, skipping")
                        continue
                        
                    key_id = key_data.pop('__key_id')  # Remove the special marker
                    self.keys[key_id] = key_data
                        
                except Exception as e:
                    logger.error(f"Failed to decrypt key {entry_id}: {e}")
            
            logger.info(f"Unlocked key storage with {len(self.keys)} keys")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unlock key storage: {e}")
            return False
    
    def derive_purpose_key(self, purpose: str) -> bytes:
        """Derive a special-purpose key from the master key.
        
        Args:
            purpose: A string identifier for the key's purpose
            
        Returns:
            A derived key for the specified purpose
        """
        if self.master_key is None:
            logger.error("Cannot derive purpose key, storage not unlocked")
            return None
        
        # Derive a purpose-specific key using HMAC
        purpose_key = hmac.new(
            key=self.master_key,
            msg=purpose.encode(),
            digestmod=hashlib.sha256
        ).digest()
        
        logger.debug(f"Derived purpose key for: {purpose}")
        return purpose_key

    def get_or_create_persistent_key(self, purpose: str, key_size: int = 32) -> Optional[bytes]:
        """Get or create a persistent purpose-specific key that survives password changes.
        
        Unlike `derive_purpose_key` which derives a key from the master key (and thus
        changes when the password changes), this method creates a persistent random key
        that is stored in the key storage and survives password changes.
        
        Args:
            purpose: A string identifier for the key's purpose (used as key_id)
            key_size: The size of the key to generate if needed, in bytes
            
        Returns:
            The persistent key, or None if storage is not unlocked or an error occurred
        """
        if self.master_key is None:
            logger.error("Cannot get or create persistent key, storage not unlocked")
            return None
            
        # Create a deterministic key_id based on the purpose
        key_id = f"system_persistent_key_{purpose}"
        
        try:
            # Try to get an existing key
            key_data = self.get_key(key_id)
            
            if key_data is None or "key" not in key_data:
                # No existing key found or invalid format, generate a new one
                logger.info(f"No valid persistent key found for purpose '{purpose}', generating new key")
                
                # Generate a random key of the specified size
                import os
                new_key = os.urandom(key_size)
                
                # Store the key with metadata
                key_stored = self.store_key(key_id, {
                    "key": new_key,
                    "purpose": purpose,
                    "created_at": time.time(),
                    "key_size": key_size,
                    "description": f"Persistent key for {purpose}"
                })
                
                if not key_stored:
                    logger.error(f"Failed to store persistent key for purpose '{purpose}'")
                    return None
                    
                logger.info(f"Generated and stored new persistent key for purpose '{purpose}'")
                return new_key
            else:
                # Use existing key
                stored_key = key_data.get("key")
                if not isinstance(stored_key, bytes) or len(stored_key) < 16:
                    # Invalid key format, generate a new one
                    logger.warning(f"Invalid persistent key format for purpose '{purpose}', regenerating")
                    
                    # Generate a new random key
                    import os
                    new_key = os.urandom(key_size)
                    
                    # Store the new key
                    key_stored = self.store_key(key_id, {
                        "key": new_key,
                        "purpose": purpose,
                        "created_at": time.time(),
                        "key_size": key_size,
                        "description": f"Persistent key for {purpose} (regenerated)"
                    })
                    
                    if not key_stored:
                        logger.error(f"Failed to store regenerated persistent key for purpose '{purpose}'")
                        return None
                        
                    logger.info(f"Regenerated persistent key for purpose '{purpose}'")
                    return new_key
                else:
                    logger.debug(f"Using existing persistent key for purpose '{purpose}'")
                    return stored_key
                    
        except Exception as e:
            logger.error(f"Error managing persistent key for purpose '{purpose}': {e}", exc_info=True)
            return None
            
    def _save_storage(self) -> bool:
        """Save the key storage to disk with full encryption.
        
        Returns:
            True if save successful, False otherwise
        """
        if self.master_key is None or self.salt is None or self.hmac_key is None:
            logger.error("Cannot save storage, not unlocked")
            return False
        
        try:
            # Create a test value to verify the password
            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, b"test_value", None)
            
            # Prepare the data to save
            data = {
                'format_version': self.FORMAT_VERSION,
                'salt': base64.b64encode(self.salt).decode(),
                'kdf': 'argon2id',
                'test_nonce': base64.b64encode(nonce).decode(),
                'test_ciphertext': base64.b64encode(ciphertext).decode(),
                'created_at': time.time(),
                'keys': {}
            }
            
            # Encrypt each key with its metadata
            for key_id, key_data in self.keys.items():
                # Include the key_id inside the encrypted data
                key_data_with_meta = key_data.copy()
                key_data_with_meta['__key_id'] = key_id  # Special marker
                
                # Convert binary data to base64 strings for JSON serialization
                serialized_data = {}
                for k, v in key_data_with_meta.items():
                    if isinstance(v, bytes):
                        serialized_data[k] = base64.b64encode(v).decode('utf-8')
                    else:
                        serialized_data[k] = v
                
                # Serialize, encrypt and store with HMAC-based entry ID
                key_data_json = json.dumps(serialized_data).encode()
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, key_data_json, None)
                
                # Create an opaque but deterministic entry ID
                entry_id = self._compute_entry_id(key_id)
                
                data['keys'][entry_id] = {
                    'nonce': base64.b64encode(nonce).decode(),
                    'ciphertext': base64.b64encode(ciphertext).decode()
                }
            
            # Write using our secure file handler
            success = self.secure_file.write_json(data)
            
            if success:
                logger.info(f"Saved key storage with {len(self.keys)} keys")
            else:
                logger.error("Failed to save key storage")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to save key storage: {e}")
            return False
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change the password for the key storage.
        
        Args:
            old_password: The current password
            new_password: The new password
            
        Returns:
            True if password change successful, False otherwise
        """
        # First unlock with the old password
        if not self.unlock(old_password):
            logger.error("Failed to unlock storage with old password")
            return False
        
        # Generate a new master key with the new password
        self.master_key, self.salt = self._derive_key(new_password)
        self._derive_encryption_keys()
        
        # Save the storage with the new master key
        return self._save_storage()

    def reset_storage(self, new_password: str, create_backup: bool = False) -> bool:
        """Reset the key storage with a new password, deleting all existing keys and logs.

        This is a destructive operation that erases all keys, logs, and creates a fresh
        key storage with the new password. Use only when the original password
        is forgotten and data loss is acceptable.

        Args:
            new_password: The new password to use
            create_backup: Whether to create a backup of the old storage (default: False)

        Returns:
            True if reset successful, False otherwise
        """
        try:
            # Create backup of existing key storage if requested
            if create_backup and self.storage_path.exists():
                backup_path = self.storage_path.with_suffix(self.storage_path.suffix + '.old')
                try:
                    import shutil
                    shutil.copy2(self.storage_path, backup_path)
                    logger.info(f"Created backup of key storage at {backup_path}")
                except Exception as e:
                    logger.error(f"Failed to create backup: {e}")

            # Delete the existing key storage files
            try:
                if self.storage_path.exists():
                    os.remove(self.storage_path)
                    logger.info(f"Deleted key storage file: {self.storage_path}")

                # Also check for lock and backup files
                lock_path = self.storage_path.with_suffix(self.storage_path.suffix + '.lock')
                if lock_path.exists():
                    os.remove(lock_path)
                    logger.info(f"Deleted lock file: {lock_path}")

                regular_backup = self.storage_path.with_suffix(self.storage_path.suffix + '.bak')
                if regular_backup.exists():
                    os.remove(regular_backup)
                    logger.info(f"Deleted regular backup file: {regular_backup}")

                # Delete any other backups
                old_backup = self.storage_path.with_suffix(self.storage_path.suffix + '.old')
                if old_backup.exists():
                    os.remove(old_backup)
                    logger.info(f"Deleted old backup file: {old_backup}")

            except Exception as e:
                logger.error(f"Error removing old storage files: {e}")
                return False

            # Delete secure logs
            try:
                # Get the logs directory (same location as key storage but in 'logs' subdirectory)
                logs_dir = self.storage_path.parent / "logs"
                if logs_dir.exists() and logs_dir.is_dir():
                    import glob
                    import shutil

                    # Delete all log files first
                    log_files = glob.glob(str(logs_dir / "*.log"))
                    for log_file in log_files:
                        try:
                            os.remove(log_file)
                            logger.info(f"Deleted log file: {log_file}")
                        except Exception as e:
                            logger.warning(f"Failed to delete log file {log_file}: {e}")

                    # Delete any encryption keys for logs
                    key_files = glob.glob(str(logs_dir.parent / "log_encryption_key*"))
                    for key_file in key_files:
                        try:
                            os.remove(key_file)
                            logger.info(f"Deleted log encryption key: {key_file}")
                        except Exception as e:
                            logger.warning(f"Failed to delete log encryption key {key_file}: {e}")

                    logger.info("Deleted secure logs")
            except Exception as e:
                logger.error(f"Error deleting secure logs: {e}")
                # Continue with reset even if log deletion fails

            # Clear any existing keys from memory
            self.keys = {}
            self.master_key = None
            self.salt = None
            self.hmac_key = None

            # Create a new key storage with the new password
            success = self.unlock(new_password)

            if success:
                logger.info("Key storage reset successfully with new password")
                return True
            else:
                logger.error("Failed to initialize new key storage")
                return False

        except Exception as e:
            logger.error(f"Failed to reset key storage: {e}")
            return False
        
    def store_key(self, key_id: str, key_data: Dict[str, Any]) -> bool:
        """Store a key in the key storage.
        
        Args:
            key_id: A unique identifier for the key
            key_data: The key data to store
            
        Returns:
            True if key stored successfully, False otherwise
        """
        if self.master_key is None:
            logger.error("Cannot store key, storage not unlocked")
            return False
        
        try:
            # Add metadata
            key_data_with_meta = key_data.copy()
            key_data_with_meta['created_at'] = time.time()
            
            # Store the key in memory
            self.keys[key_id] = key_data_with_meta
            
            # Save to disk
            return self._save_storage()
            
        except Exception as e:
            logger.error(f"Failed to store key {key_id}: {e}")
            return False
    
    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a key from the key storage.
        
        Args:
            key_id: The identifier of the key to retrieve
            
        Returns:
            The key data, or None if not found
        """
        if self.master_key is None:
            logger.error("Cannot get key, storage not unlocked")
            return None
        
        if key_id not in self.keys:
            return None
        
        # Get the key data
        key_data = self.keys[key_id].copy()
        
        # Convert base64 strings back to binary data
        decoded_data = {}
        for k, v in key_data.items():
            if isinstance(v, str) and k in ['public_key', 'private_key', 'shared_key']:
                try:
                    decoded_data[k] = base64.b64decode(v)
                except Exception:
                    # Not base64 encoded, use as is
                    decoded_data[k] = v
            else:
                decoded_data[k] = v
        
        return decoded_data
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a key from the key storage.
        
        Args:
            key_id: The identifier of the key to delete
            
        Returns:
            True if key deleted successfully, False otherwise
        """
        if self.master_key is None:
            logger.error("Cannot delete key, storage not unlocked")
            return False
        
        if key_id not in self.keys:
            logger.warning(f"Key {key_id} not found in storage")
            return False
        
        try:
            # Remove the key from memory
            del self.keys[key_id]
            
            # Save to disk to remove it from storage
            return self._save_storage()
            
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def list_keys(self) -> List[Tuple[str, Dict[str, Any]]]:
        """List all keys in the key storage.
        
        Returns:
            List of tuples (key_id, key_data)
        """
        if self.master_key is None:
            logger.error("Cannot list keys, storage not unlocked")
            return []
        
        # Create a list of (key_id, key_data) tuples
        # Convert any base64 strings to bytes in the key data
        result = []
        for key_id, key_data in self.keys.items():
            decoded_data = {}
            for k, v in key_data.items():
                if isinstance(v, str) and k in ['public_key', 'private_key', 'shared_key']:
                    try:
                        decoded_data[k] = base64.b64decode(v)
                    except Exception:
                        decoded_data[k] = v
                else:
                    decoded_data[k] = v
            result.append((key_id, decoded_data))
        
        return result
    
    def get_key_history(self, decrypt_keys=False) -> List[Dict[str, Any]]:
        """Get a list of all saved key history.

        Args:
            decrypt_keys: Whether to decrypt the key data (default: False)

        Returns:
            List of dictionaries containing key history information
        """
        if self.master_key is None:
            logger.error("Cannot get key history, storage not unlocked")
            return []

        history = []
        for key_id, key_data in self.keys.items():
            if key_id.startswith("peer_shared_key_"):
                # Extract and convert relevant information
                display_data = key_data.copy()

                # Only include encrypted_key_data for later decryption
                encrypted_data = None

                # Store the raw encrypted data for later decryption if needed
                if "shared_key" in display_data:
                    # Remember if it's already bytes or needs to be decoded from base64
                    if isinstance(display_data["shared_key"], str):
                        try:
                            encrypted_data = {"type": "base64", "data": display_data["shared_key"]}
                        except:
                            encrypted_data = {"type": "string", "data": display_data["shared_key"]}
                    else:
                        encrypted_data = {"type": "bytes", "data": display_data["shared_key"]}

                    # Generate a preview if it's going to be displayed
                    if decrypt_keys and isinstance(display_data["shared_key"], bytes):
                        display_data["shared_key_preview"] = display_data["shared_key"][:16].hex()
                    else:
                        display_data["shared_key_preview"] = "(encrypted)"

                entry = {
                    "key_id": key_id,
                    "peer_id": display_data.get("peer_id", "Unknown"),
                    "algorithm": display_data.get("algorithm", "Unknown"),
                    "symmetric_algorithm": display_data.get("symmetric_algorithm", "Unknown"),
                    "created_at": display_data.get("created_at", 0),
                    "key_preview": display_data.get("shared_key_preview", ""),
                    "encrypted_key_data": encrypted_data  # Store encrypted data instead of decrypted
                }

                # Only include full_key if explicitly requested
                if decrypt_keys and "shared_key" in display_data:
                    if isinstance(display_data["shared_key"], bytes):
                        entry["full_key"] = display_data["shared_key"]
                    elif isinstance(display_data["shared_key"], str):
                        try:
                            entry["full_key"] = base64.b64decode(display_data["shared_key"])
                        except:
                            entry["full_key"] = display_data["shared_key"].encode('utf-8')

                history.append(entry)

        # Sort by creation time, newest first
        history.sort(key=lambda x: x["created_at"], reverse=True)
        return history

    def decrypt_key(self, key_id: str) -> Optional[bytes]:
        """Decrypt a specific key by ID.

        Args:
            key_id: The ID of the key to decrypt

        Returns:
            The decrypted key as bytes, or None if not found/cannot decrypt
        """
        if self.master_key is None:
            logger.error("Cannot decrypt key, storage not unlocked")
            return None

        # Log the decryption attempt
        logger.info(f"Decrypting key {key_id} from secure storage")

        # Retrieve the encrypted key data
        key_data = self.get_key(key_id)
        if not key_data or "shared_key" not in key_data:
            logger.error(f"Key {key_id} not found or has no shared_key")
            return None

        # Return the already-decrypted data
        shared_key = key_data["shared_key"]
        if isinstance(shared_key, bytes):
            logger.info(f"Successfully decrypted key {key_id}")
            return shared_key
        elif isinstance(shared_key, str):
            # Try to decode if it's base64 encoded
            try:
                decoded_key = base64.b64decode(shared_key)
                logger.info(f"Successfully decrypted key {key_id} (from base64)")
                return decoded_key
            except:
                # Not base64, use as is
                logger.info(f"Successfully decrypted key {key_id} (from string)")
                return shared_key.encode('utf-8')

        logger.error(f"Failed to decode key {key_id} (unknown format)")
        return None

    def close(self) -> None:
        """Close the key storage and clear sensitive data from memory."""
        if hasattr(self, 'master_key') and self.master_key:
            self._secure_zero(self.master_key)
            self.master_key = None
            
        if hasattr(self, 'hmac_key') and self.hmac_key:
            self._secure_zero(self.hmac_key)
            self.hmac_key = None
            
        self.keys = {}
        self.salt = None
        
        logger.info("Key storage closed and sensitive data cleared")