"""
Secure storage for cryptographic keys.
"""

import json
import os
import logging
import base64
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class KeyStorage:
    """Secure storage for cryptographic keys.
    
    This class provides functionality to securely store and retrieve
    cryptographic keys using password-based encryption.
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
            storage_dir.mkdir(exist_ok=True)
            self.storage_path = storage_dir / "keys.json"
        else:
            self.storage_path = Path(storage_path)
            # Make sure parent directory exists
            self.storage_path.parent.mkdir(exist_ok=True)
        
        self.keys: Dict[str, Dict[str, Any]] = {}
        self.master_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None
        
        logger.info(f"Key storage initialized at {self.storage_path}")
    
    def _derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Derive a key from a password using PBKDF2.
        
        Args:
            password: The user's password
            salt: Optional salt, generated randomly if None
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
            
        # Use PBKDF2 to derive a key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        derived_key = kdf.derive(password.encode())
        
        return derived_key, salt
    
    def unlock(self, password: str) -> bool:
        """Unlock the key storage with the given password.
        
        Args:
            password: The user's password
            
        Returns:
            True if unlock successful, False otherwise
        """
        if not self.storage_path.exists():
            # First time use, create a new storage file
            self.salt = os.urandom(16)
            self.master_key, _ = self._derive_key(password, self.salt)
            return self._save_storage()
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            if 'salt' not in data:
                logger.error("Invalid key storage file, missing salt")
                return False
            
            salt = base64.b64decode(data['salt'])
            derived_key, _ = self._derive_key(password, salt)
            
            if 'test_nonce' in data and 'test_ciphertext' in data:
                # Try to decrypt a test value to verify the password
                nonce = base64.b64decode(data['test_nonce'])
                ciphertext = base64.b64decode(data['test_ciphertext'])
                
                aesgcm = AESGCM(derived_key)
                try:
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
            
            # Save to disk
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved key storage with {len(self.keys)} keys")
            return True
            
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
        
        # Generate a new master key
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
                import time
                key_data_with_meta['created_at'] = time.time()
            
            # Convert binary data to base64 strings for JSON serialization
            import base64
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
        import base64
        for k, v in key_data.items():
            if isinstance(v, str) and k in ['public_key', 'private_key']:
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
    
    def close(self) -> None:
        """Close the key storage and clear sensitive data from memory."""
        self.keys = {}
        self.master_key = None
        self.salt = None
        logger.info("Key storage closed")
