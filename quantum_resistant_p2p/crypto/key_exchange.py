"""
Post-quantum key exchange algorithms.
"""

import abc
import logging
from typing import Tuple, Dict, Any, Optional
import os

# Import the base class
from .algorithm_base import CryptoAlgorithm

# Import OQS (Open Quantum Safe)
import oqs # type: ignore

logger = logging.getLogger(__name__)


class KeyExchangeAlgorithm(CryptoAlgorithm):
    """Abstract base class for key exchange algorithms."""
    
    @abc.abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        pass
    
    @abc.abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        pass
    
    @abc.abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        pass


class MLKEMKeyExchange(KeyExchangeAlgorithm):
    """ML-KEM (previously CRYSTALS-Kyber) key exchange algorithm.
    
    ML-KEM is a post-quantum key encapsulation mechanism (KEM) based on the
    hardness of solving the learning-with-errors (LWE) problem over module lattices.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize ML-KEM with the specified security level.
        
        Args:
            security_level: Security level (1, 3, or 5)
        """
        self.security_level = security_level
        self.kem = None
        self.variant = None
        
        # Map security levels to ML-KEM variants
        ml_kem_variants = {
            1: "ML-KEM-512",
            3: "ML-KEM-768",
            5: "ML-KEM-1024"
        }
        
        # Also check for older Kyber names as a fallback
        kyber_variants = {
            1: "Kyber512",
            3: "Kyber768",
            5: "Kyber1024"
        }
        
        if security_level not in ml_kem_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
            
        # Determine available enabled KEM mechanisms
        self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            
        # Try to find an available implementation
        if ml_kem_variants[security_level] in self.enabled_kems:
            self.variant = ml_kem_variants[security_level]
        elif kyber_variants[security_level] in self.enabled_kems:
            # Use older Kyber implementation if available
            self.variant = kyber_variants[security_level]
        else:
            raise ValueError(f"No ML-KEM or Kyber variant found for security level {security_level}")
        
        # Create the KEM instance
        self.kem = oqs.KeyEncapsulation(self.variant)
        logger.info(f"Successfully initialized ML-KEM variant {self.variant}")
        
        logger.info(f"Initialized ML-KEM key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"ML-KEM (Level {self.security_level})"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"ML-KEM (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("ML-KEM is a module-lattice-based key encapsulation mechanism. "
                "It is one of the NIST post-quantum cryptography standards.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new ML-KEM keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Use actual OQS implementation
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated ML-KEM keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating ML-KEM keypair: {e}")
            raise
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        try:
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"ML-KEM encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during ML-KEM encapsulation: {e}")
            raise
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"ML-KEM decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during ML-KEM decapsulation: {e}")
            raise


class HQCKeyExchange(KeyExchangeAlgorithm):
    """HQC (Hamming Quasi-Cyclic) key exchange algorithm.
    
    HQC is a code-based post-quantum key encapsulation mechanism (KEM)
    based on the hardness of decoding problems in quasi-cyclic codes.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize HQC with the specified security level.
        
        Args:
            security_level: Security level (1 for 128-bit, 3 for 192-bit, 5 for 256-bit)
        """
        self.security_level = security_level
        self.kem = None
        self.variant = None
        
        # Map security levels to HQC variants
        hqc_variants = {
            1: "HQC-128",
            3: "HQC-192",
            5: "HQC-256"
        }
        
        if security_level not in hqc_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
            
        # Determine available enabled KEM mechanisms
        self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            
        # Try to find an available implementation
        if hqc_variants[security_level] in self.enabled_kems:
            self.variant = hqc_variants[security_level]
        else:
            raise ValueError(f"No HQC variant found for security level {security_level}")
        
        # Create the KEM instance
        self.kem = oqs.KeyEncapsulation(self.variant)
        logger.info(f"Successfully initialized HQC variant {self.variant}")
        
        logger.info(f"Initialized HQC key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"HQC (Level {self.security_level})"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"HQC (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("HQC (Hamming Quasi-Cyclic) is a code-based key encapsulation mechanism. "
                "It uses error-correcting codes and is based on the hardness of "
                "decoding problems.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new HQC keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Use actual OQS implementation
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated HQC keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating HQC keypair: {e}")
            raise
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        try:
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"HQC encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during HQC encapsulation: {e}")
            raise
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"HQC decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during HQC decapsulation: {e}")
            raise


class FrodoKEMKeyExchange(KeyExchangeAlgorithm):
    """FrodoKEM key exchange algorithm.
    
    FrodoKEM is a lattice-based key encapsulation mechanism (KEM) based on
    the standard Learning With Errors problem without any additional structure.
    """
    
    def __init__(self, security_level: int = 3, use_aes: bool = True):
        """Initialize FrodoKEM with the specified security level.
        
        Args:
            security_level: Security level (1 for 640, 3 for 976, 5 for 1344)
            use_aes: Whether to use AES (True) or SHAKE (False) for randomness
        """
        self.security_level = security_level
        self.use_aes = use_aes
        self.kem = None
        self.variant = None
        
        # Map security levels to FrodoKEM variants
        if use_aes:
            frodo_variants = {
                1: "FrodoKEM-640-AES",
                3: "FrodoKEM-976-AES",
                5: "FrodoKEM-1344-AES"
            }
        else:
            frodo_variants = {
                1: "FrodoKEM-640-SHAKE",
                3: "FrodoKEM-976-SHAKE",
                5: "FrodoKEM-1344-SHAKE"
            }
        
        if security_level not in frodo_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
            
        # Determine available enabled KEM mechanisms
        self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            
        # Try to find an available implementation
        if frodo_variants[security_level] in self.enabled_kems:
            self.variant = frodo_variants[security_level]
        else:
            # Try the other variant (AES vs SHAKE) if available
            alt_variant = frodo_variants[security_level].replace('-AES', '-SHAKE') if use_aes else frodo_variants[security_level].replace('-SHAKE', '-AES')
            if alt_variant in self.enabled_kems:
                self.variant = alt_variant
                logger.info(f"Using alternative FrodoKEM variant: {alt_variant}")
            else:
                raise ValueError(f"No FrodoKEM variant found for security level {security_level}")
        
        # Create the KEM instance
        self.kem = oqs.KeyEncapsulation(self.variant)
        logger.info(f"Successfully initialized FrodoKEM variant {self.variant}")
        
        logger.info(f"Initialized FrodoKEM key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        rand_type = "AES" if self.use_aes else "SHAKE"
        return f"FrodoKEM (Level {self.security_level}, {rand_type})"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        rand_type = "AES" if self.use_aes else "SHAKE"
        return f"FrodoKEM (Level {self.security_level}, {rand_type})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("FrodoKEM is a lattice-based key encapsulation mechanism based on "
                "the standard Learning With Errors problem. It is considered "
                "a conservative post-quantum KEM.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new FrodoKEM keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Use actual OQS implementation
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated FrodoKEM keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating FrodoKEM keypair: {e}")
            raise
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        try:
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"FrodoKEM encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during FrodoKEM encapsulation: {e}")
            raise
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"FrodoKEM decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during FrodoKEM decapsulation: {e}")
            raise