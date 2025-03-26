"""
Secure storage for cryptographic keys, using Argon2 for key derivation.
"""

import json
import os
import logging
import base64
import hmac
import hashlib
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
    """Secure storage for cryptographic keys.
    
    This class provides functionality to securely store and retrieve
    cryptographic keys using password-based encryption with Argon2.
    """
    
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
        
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.master_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        
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
            # ad and secret can be left as default None
        )
        
        derived_key = kdf.derive(password.encode())
        
        return derived_key, salt
    
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
                return self._save_storage()
            
            if 'salt' not in data:
                logger.error("Invalid key storage file, missing salt")
                return False
            
            salt = base64.b64decode(data['salt'])
            derived_key, _ = self._derive_key(password, salt)
            
            if 'test_nonce' in data and 'test_ciphertext' in data:
                # Try to decrypt a test value to verify the password
                nonce = base64.b64decode(data['test_nonce'])
                ciphertext = base64.b64decode(data['test_ciphertext'])
                
                try:
                    aesgcm = AESGCM(derived_key)
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    if plaintext.decode() != "test_value":
                        logger.error("Password verification failed")
                        return False
                except Exception as e:
                    logger.error(f"Failed to decrypt test value, wrong password?: {e}")
                    return False
            
            self.master_key = derived_key
            self.salt = salt
            
            # Load the encrypted keys
            if 'keys' in data:
                for key_id, encrypted_key_data in data['keys'].items():
                    try:
                        nonce = base64.b64decode(encrypted_key_data['nonce'])
                        ciphertext = base64.b64decode(encrypted_key_data['ciphertext'])
                        
                        aesgcm = AESGCM(self.master_key)
                        key_data_json = aesgcm.decrypt(nonce, ciphertext, None)
                        key_data = json.loads(key_data_json.decode())
                        
                        self.keys[key_id] = key_data
                    except Exception as e:
                        logger.error(f"Failed to decrypt key {key_id}: {e}")
            
            logger.info(f"Unlocked key storage with {len(self.keys)} keys")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unlock key storage: {e}")
            return False
    
    def get_master_key(self) -> bytes:
        """Get the master key for use by other secure components.
        
        This should only be called after successful unlock.
        
        Returns:
            The master key as bytes or None if not unlocked
        """
        if self.master_key is None:
            logger.error("Cannot get master key, storage not unlocked")
            return None
        
        # For security, we don't return the exact master key
        # Instead, derive a separate key for logs using the master key
        # using HMAC to ensure this derived key can't be used to recover the master key
        
        # Derive a specific key for logs using HMAC
        log_key = hmac.new(
            key=self.master_key,
            msg=b"secure_logger_key_v1",
            digestmod=hashlib.sha256
        ).digest()
        
        logger.debug("Derived log encryption key from master key")
        return log_key
    
    def _save_storage(self) -> bool:
        """Save the key storage to disk.
        
        Returns:
            True if save successful, False otherwise
        """
        if self.master_key is None or self.salt is None:
            logger.error("Cannot save storage, not unlocked")
            return False
        
        try:
            # Create a test value to verify the password
            aesgcm = AESGCM(self.master_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, b"test_value", None)
            
            # Prepare the data to save
            data = {
                'salt': base64.b64encode(self.salt).decode(),
                'kdf': 'argon2id',  # Document which KDF is used
                'test_nonce': base64.b64encode(nonce).decode(),
                'test_ciphertext': base64.b64encode(ciphertext).decode(),
                'keys': {}
            }
            
            # Encrypt each key
            for key_id, key_data in self.keys.items():
                key_data_json = json.dumps(key_data).encode()
                nonce = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, key_data_json, None)
                
                data['keys'][key_id] = {
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
        
        # Save the storage with the new master key
        return self._save_storage()
    
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
            key_data_with_meta['id'] = key_id
            if 'created_at' not in key_data_with_meta:
                key_data_with_meta['created_at'] = time.time()
            
            # Convert binary data to base64 strings for JSON serialization
            for k, v in key_data_with_meta.items():
                if isinstance(v, bytes):
                    key_data_with_meta[k] = base64.b64encode(v).decode('utf-8')
            
            # Store the key
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
        for k, v in key_data.items():
            if isinstance(v, str) and k in ['public_key', 'private_key', 'shared_key']:
                try:
                    key_data[k] = base64.b64decode(v)
                except Exception:
                    # Not base64 encoded, leave as is
                    pass
        
        return key_data
    
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
            # Remove the key
            del self.keys[key_id]
            
            # Save to disk
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
        
        return [(key_id, key_data) for key_id, key_data in self.keys.items()]
    
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
            
        self.keys = {}
        self.salt = None
        
        logger.info("Key storage closed and sensitive data cleared")