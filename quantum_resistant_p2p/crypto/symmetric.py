"""
Symmetric encryption algorithms.
"""

import abc
import logging
import os
from typing import Tuple, Optional

# Import the base class
from .algorithm_base import CryptoAlgorithm

# Standard cryptography lib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305 as ChaCha20Poly1305Cipher

logger = logging.getLogger(__name__)


class SymmetricAlgorithm(CryptoAlgorithm):
    """Abstract base class for symmetric encryption algorithms."""
    
    @property
    @abc.abstractmethod
    def key_size(self) -> int:
        """Get the key size in bytes."""
        pass
    
    @abc.abstractmethod
    def generate_key(self) -> bytes:
        """Generate a new random key.
        
        Returns:
            A new key as bytes
        """
        pass
    
    @abc.abstractmethod
    def encrypt(self, key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt data using the given key.
        
        Args:
            key: The encryption key
            plaintext: The data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            The encrypted data (including nonce/IV)
        """
        pass
    
    @abc.abstractmethod
    def decrypt(self, key: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data using the given key.
        
        Args:
            key: The encryption key
            ciphertext: The data to decrypt (including nonce/IV)
            associated_data: Optional additional authenticated data
            
        Returns:
            The decrypted data
        """
        pass


class AES256GCM(SymmetricAlgorithm):
    """AES-256 in GCM mode for authenticated encryption."""
    
    @property
    def name(self) -> str:
        """Get the name of the algorithm."""
        return "AES-256-GCM"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("AES-256 in Galois/Counter Mode (GCM) providing both encryption and "
                "authentication. It is widely used and standardized.")
    
    @property
    def key_size(self) -> int:
        """Get the key size in bytes."""
        return 32  # 256 bits = 32 bytes
    
    def generate_key(self) -> bytes:
        """Generate a new random AES-256 key.
        
        Returns:
            A new 256-bit (32-byte) key
        """
        key = os.urandom(self.key_size)
        logger.debug(f"Generated new AES-256 key ({self.key_size} bytes)")
        return key
    
    def encrypt(self, key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt data using AES-256-GCM.
        
        Args:
            key: The 256-bit AES key
            plaintext: The data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Nonce + ciphertext + tag
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes, got {len(key)}")
        
        # Generate a random 96-bit (12-byte) nonce
        nonce = os.urandom(12)
        
        # Create the AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Encrypt the data
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Return nonce + ciphertext (including tag)
        result = nonce + ciphertext
        
        logger.debug(f"AES-256-GCM encryption: {len(plaintext)} bytes plaintext -> "
                   f"{len(result)} bytes ciphertext (includes {len(nonce)} bytes nonce)")
        
        return result
    
    def decrypt(self, key: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data using AES-256-GCM.
        
        Args:
            key: The 256-bit AES key
            ciphertext: Nonce + ciphertext + tag
            associated_data: Optional additional authenticated data
            
        Returns:
            The decrypted data
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes, got {len(key)}")
        
        if len(ciphertext) < 12:  # Nonce is 12 bytes
            raise ValueError(f"Ciphertext too short: {len(ciphertext)} bytes, need at least 12 bytes for nonce")
        
        # Extract the nonce (first 12 bytes)
        nonce = ciphertext[:12]
        # Extract the actual ciphertext (including tag)
        actual_ciphertext = ciphertext[12:]
        
        # Create the AES-GCM cipher
        aesgcm = AESGCM(key)
        
        # Decrypt the data
        try:
            plaintext = aesgcm.decrypt(nonce, actual_ciphertext, associated_data)
            
            logger.debug(f"AES-256-GCM decryption: {len(ciphertext)} bytes ciphertext -> "
                       f"{len(plaintext)} bytes plaintext")
            
            return plaintext
        except Exception as e:
            logger.error(f"AES-256-GCM decryption failed: {e}")
            raise ValueError("Authentication failed or decryption error") from e


class ChaCha20Poly1305(SymmetricAlgorithm):
    """ChaCha20-Poly1305 for authenticated encryption."""
    
    @property
    def name(self) -> str:
        """Get the name of the algorithm."""
        return "ChaCha20-Poly1305"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("ChaCha20-Poly1305 is a modern authenticated encryption algorithm "
                "that combines the ChaCha20 stream cipher with the Poly1305 authenticator.")
    
    @property
    def key_size(self) -> int:
        """Get the key size in bytes."""
        return 32  # 256 bits = 32 bytes
    
    def generate_key(self) -> bytes:
        """Generate a new random ChaCha20 key.
        
        Returns:
            A new 256-bit (32-byte) key
        """
        key = os.urandom(self.key_size)
        logger.debug(f"Generated new ChaCha20 key ({self.key_size} bytes)")
        return key
    
    def encrypt(self, key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt data using ChaCha20-Poly1305.
        
        Args:
            key: The 256-bit ChaCha20 key
            plaintext: The data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Nonce + ciphertext + tag
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes, got {len(key)}")
        
        # Generate a random 96-bit (12-byte) nonce
        nonce = os.urandom(12)
        
        # Create the ChaCha20-Poly1305 cipher
        chacha = ChaCha20Poly1305Cipher(key)
        
        # Encrypt the data
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
        
        # Return nonce + ciphertext (including tag)
        result = nonce + ciphertext
        
        logger.debug(f"ChaCha20-Poly1305 encryption: {len(plaintext)} bytes plaintext -> "
                   f"{len(result)} bytes ciphertext (includes {len(nonce)} bytes nonce)")
        
        return result
    
    def decrypt(self, key: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data using ChaCha20-Poly1305.
        
        Args:
            key: The 256-bit ChaCha20 key
            ciphertext: Nonce + ciphertext + tag
            associated_data: Optional additional authenticated data
            
        Returns:
            The decrypted data
        """
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes, got {len(key)}")
        
        if len(ciphertext) < 12:  # Nonce is 12 bytes
            raise ValueError(f"Ciphertext too short: {len(ciphertext)} bytes, need at least 12 bytes for nonce")
        
        # Extract the nonce (first 12 bytes)
        nonce = ciphertext[:12]
        # Extract the actual ciphertext (including tag)
        actual_ciphertext = ciphertext[12:]
        
        # Create the ChaCha20-Poly1305 cipher
        chacha = ChaCha20Poly1305Cipher(key)
        
        # Decrypt the data
        try:
            plaintext = chacha.decrypt(nonce, actual_ciphertext, associated_data)
            
            logger.debug(f"ChaCha20-Poly1305 decryption: {len(ciphertext)} bytes ciphertext -> "
                       f"{len(plaintext)} bytes plaintext")
            
            return plaintext
        except Exception as e:
            logger.error(f"ChaCha20-Poly1305 decryption failed: {e}")
            raise ValueError("Authentication failed or decryption error") from e
