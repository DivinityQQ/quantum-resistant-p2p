"""
Post-quantum digital signature algorithms.
"""

import abc
import logging
from typing import Tuple, Optional, Dict

# Import the base class
from .algorithm_base import CryptoAlgorithm

# Import OQS (Open Quantum Safe)
import oqs # type: ignore

logger = logging.getLogger(__name__)


class SignatureAlgorithm(CryptoAlgorithm):
    """Abstract base class for digital signature algorithms."""
    
    @abc.abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        pass
    
    @abc.abstractmethod
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using the private key.
        
        Args:
            private_key: The private key for signing
            message: The message to sign
            
        Returns:
            The signature
        """
        pass
    
    @abc.abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature using the public key.
        
        Args:
            public_key: The public key for verification
            message: The message that was signed
            signature: The signature to verify
            
        Returns:
            True if the signature is valid, False otherwise
        """
        pass


class MLDSASignature(SignatureAlgorithm):
    """ML-DSA (previously CRYSTALS-Dilithium) digital signature algorithm.
    
    ML-DSA is a post-quantum signature scheme based on the
    hardness of lattice problems.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize ML-DSA with the specified security level.
        
        Args:
            security_level: Security level (2, 3, or 5)
        """
        self.security_level = security_level
        self.signer = None
        self.variant = None
        
        # Map security levels to ML-DSA variants
        ml_dsa_variants = {
            2: "ML-DSA-44",
            3: "ML-DSA-65",
            5: "ML-DSA-87"
        }
        
        # Also check older Dilithium names as fallback
        dilithium_variants = {
            2: "Dilithium2",
            3: "Dilithium3",
            5: "Dilithium5"
        }
        
        if security_level not in ml_dsa_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 2, 3, or 5.")
        
        # Get enabled signature mechanisms
        self.enabled_sigs = oqs.get_enabled_sig_mechanisms()
        
        # Try to find an available variant
        if ml_dsa_variants[security_level] in self.enabled_sigs:
            self.variant = ml_dsa_variants[security_level]
        elif dilithium_variants[security_level] in self.enabled_sigs:
            # Use older Dilithium implementation if available
            self.variant = dilithium_variants[security_level]
        else:
            raise ValueError(f"No ML-DSA or Dilithium variant found for security level {security_level}")
        
        # Create the Signature instance
        self.signer = oqs.Signature(self.variant)
        logger.info(f"Successfully initialized ML-DSA variant {self.variant}")
        
        logger.info(f"Initialized ML-DSA signature with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"ML-DSA (Level {self.security_level})"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"ML-DSA (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("ML-DSA is a lattice-based digital signature scheme. "
                "It is one of the NIST post-quantum cryptography standards.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new ML-DSA keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Use actual OQS implementation
            public_key = self.signer.generate_keypair()
            private_key = self.signer.export_secret_key()
            
            logger.debug(f"Generated ML-DSA keypair: public key {len(public_key)} bytes, "
                       f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating ML-DSA keypair: {e}")
            raise
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using ML-DSA.
        
        Args:
            private_key: The private key for signing
            message: The message to sign
            
        Returns:
            The signature
        """
        try:
            # Create a new signer with the private key
            signer = oqs.Signature(self.variant, private_key)
            signature = signer.sign(message)
            
            logger.debug(f"Created ML-DSA signature: {len(signature)} bytes")
            
            return signature
        except Exception as e:
            logger.error(f"Error signing with ML-DSA: {e}")
            raise
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a ML-DSA signature.
        
        Args:
            public_key: The public key for verification
            message: The message that was signed
            signature: The signature to verify
            
        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            # Create a new verifier
            verifier = oqs.Signature(self.variant)
            result = verifier.verify(message, signature, public_key)
            
            logger.debug(f"ML-DSA signature verification: {'success' if result else 'failure'}")
            
            return result
        except Exception as e:
            logger.error(f"Error verifying ML-DSA signature: {e}")
            return False


class SPHINCSSignature(SignatureAlgorithm):
    """SPHINCS+ digital signature algorithm.
    
    SPHINCS+ is a stateless hash-based signature scheme.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize SPHINCS+ with the specified security level.
        
        Args:
            security_level: Security level (1, 3, or 5)
        """
        self.security_level = security_level
        self.signer = None
        self.variant = None
        
        # Map security levels to SPHINCS+ variants
        sphincs_variants = {
            1: ["SPHINCS+-SHA2-128f-simple"],
            3: ["SPHINCS+-SHA2-192f-simple"],
            5: ["SPHINCS+-SHA2-256f-simple"]
        }
        
        if security_level not in sphincs_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
        
        # Get enabled signature mechanisms
        self.enabled_sigs = oqs.get_enabled_sig_mechanisms()
        
        # Try to find an available variant
        variant_found = False
        for variant in sphincs_variants[security_level]:
            if variant in self.enabled_sigs:
                self.variant = variant
                variant_found = True
                break
        
        if not variant_found:
            raise ValueError(f"No SPHINCS+ variant found for security level {security_level}")
        
        # Create the Signature instance
        self.signer = oqs.Signature(self.variant)
        logger.info(f"Successfully initialized SPHINCS+ variant {self.variant}")
        
        logger.info(f"Initialized SPHINCS+ signature with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"SPHINCS+ (Level {self.security_level})"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"SPHINCS+ (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("SPHINCS+ is a stateless hash-based digital signature scheme. "
                "Its security relies only on the security of the underlying hash functions.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new SPHINCS+ keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Use actual OQS implementation
            public_key = self.signer.generate_keypair()
            private_key = self.signer.export_secret_key()
            
            logger.debug(f"Generated SPHINCS+ keypair: public key {len(public_key)} bytes, "
                       f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating SPHINCS+ keypair: {e}")
            raise
    
    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Sign a message using SPHINCS+.
        
        Args:
            private_key: The private key for signing
            message: The message to sign
            
        Returns:
            The signature
        """
        try:
            # Create a new signer with the private key
            signer = oqs.Signature(self.variant, private_key)
            signature = signer.sign(message)
            
            logger.debug(f"Created SPHINCS+ signature: {len(signature)} bytes")
            
            return signature
        except Exception as e:
            logger.error(f"Error signing with SPHINCS+: {e}")
            raise
    
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a SPHINCS+ signature.
        
        Args:
            public_key: The public key for verification
            message: The message that was signed
            signature: The signature to verify
            
        Returns:
            True if the signature is valid, False otherwise
        """
        try:
            # Create a new verifier
            verifier = oqs.Signature(self.variant)
            result = verifier.verify(message, signature, public_key)
            
            logger.debug(f"SPHINCS+ signature verification: {'success' if result else 'failure'}")
            
            return result
        except Exception as e:
            logger.error(f"Error verifying SPHINCS+ signature: {e}")
            return False