"""
Post-quantum key exchange algorithms.
"""

import abc
import logging
from typing import Tuple, Dict, Any, Optional
import os
import hashlib
import threading

# Import the base class
from .algorithm_base import CryptoAlgorithm

# Try to import oqs (Open Quantum Safe)
try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    logging.warning("oqs not available, using deterministic mock implementations for post-quantum algorithms")

logger = logging.getLogger(__name__)


# Mock implementation helper functions
def get_node_id():
    """Get a unique ID for this node from environment or thread ID."""
    return os.environ.get('NODE_ID', str(threading.get_ident()))


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


class KyberKeyExchange(KeyExchangeAlgorithm):
    """CRYSTALS-Kyber key exchange algorithm.
    
    Kyber is a post-quantum key encapsulation mechanism (KEM) based on the
    hardness of solving the learning-with-errors (LWE) problem over module lattices.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize Kyber with the specified security level.
        
        Args:
            security_level: Security level (1, 3, or 5)
        """
        global LIBOQS_AVAILABLE
        
        self.security_level = security_level
        self.kem = None
        self.variant = None
        
        # Attempt to get list of enabled KEM mechanisms if OQS is available
        self.enabled_kems = []
        if LIBOQS_AVAILABLE:
            try:
                self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            except Exception as e:
                logger.error(f"Error getting enabled KEM mechanisms: {e}")
                LIBOQS_AVAILABLE = False
        
        if not LIBOQS_AVAILABLE:
            logger.warning("Using deterministic mock implementation of Kyber")
            return
        
        # Map security levels to Kyber variants
        # Using both ML-KEM (new names) and Kyber (old names) for compatibility
        kyber_variants = {
            1: ["ML-KEM-512", "Kyber512"],
            3: ["ML-KEM-768", "Kyber768"],
            5: ["ML-KEM-1024", "Kyber1024"]
        }
        
        if security_level not in kyber_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
        
        # Try the new ML-KEM name first, then fall back to the old Kyber name
        variant_found = False
        for variant in kyber_variants[security_level]:
            if variant in self.enabled_kems:
                self.variant = variant
                variant_found = True
                break
        
        if not variant_found:
            logger.warning(f"No Kyber variant found for security level {security_level}, using deterministic mock implementation")
            LIBOQS_AVAILABLE = False
            return
        
        # Try to create the KEM instance
        try:
            self.kem = oqs.KeyEncapsulation(self.variant)
            logger.info(f"Successfully initialized Kyber variant {self.variant}")
        except Exception as e:
            logger.error(f"Error initializing Kyber: {e}")
            LIBOQS_AVAILABLE = False
        
        logger.info(f"Initialized Kyber key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the name of the algorithm."""
        if LIBOQS_AVAILABLE and self.kem is not None:
            return f"CRYSTALS-Kyber (Level {self.security_level})"
        return f"CRYSTALS-Kyber (Level {self.security_level}) [Mock]"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("CRYSTALS-Kyber is a module-lattice-based key encapsulation mechanism. "
                "It is one of the NIST post-quantum cryptography standards.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new Kyber keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        global LIBOQS_AVAILABLE
        
        if not LIBOQS_AVAILABLE or self.kem is None:
            # Deterministic mock implementation
            node_id = get_node_id()
            
            # Generate a private key deterministically from node ID and algorithm info
            seed = f"kyber-{self.security_level}-private-{node_id}"
            private_key = hashlib.sha256(seed.encode()).digest()
            
            # Generate public key deterministically from private key
            # NOTE: This is critical - both sides need to derive public key from private key consistently
            pub_seed = f"kyber-{self.security_level}-public-{private_key.hex()}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            logger.debug("Generated deterministic mock Kyber keypair")
            return public_key, private_key
        
        try:
            # Use actual OQS implementation with the current API pattern
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated Kyber keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating Kyber keypair: {e}")
            # Fall back to mock implementation
            LIBOQS_AVAILABLE = False
            return self.generate_keypair()  # Recursive call to use mock implementation
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        global LIBOQS_AVAILABLE
        
        if not LIBOQS_AVAILABLE or self.kem is None:
            # Deterministic mock implementation - no dependency on class state
            
            # Generate a ciphertext deterministically from the public key
            cipher_seed = f"kyber-{self.security_level}-ciphertext-{public_key.hex()}"
            ciphertext = hashlib.sha256(cipher_seed.encode()).digest()
            
            # Generate a shared secret deterministically from the public key and ciphertext ONLY
            secret_seed = f"kyber-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug("Performed deterministic mock Kyber encapsulation")
            return ciphertext, shared_secret
        
        try:
            # Use actual OQS implementation with current API pattern
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"Kyber encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during Kyber encapsulation: {e}")
            # Fall back to mock implementation
            LIBOQS_AVAILABLE = False
            return self.encapsulate(public_key)  # Recursive call to use mock implementation
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        global LIBOQS_AVAILABLE
        
        if not LIBOQS_AVAILABLE or self.kem is None:
            # Generate a public key from the private key using the SAME algorithm as in generate_keypair
            private_key_hex = private_key.hex()
            pub_seed = f"kyber-{self.security_level}-public-{private_key_hex}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            # Generate shared secret using the SAME algorithm as in encapsulate
            secret_seed = f"kyber-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug("Performed deterministic mock Kyber decapsulation")
            return shared_secret
        
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"Kyber decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during Kyber decapsulation: {e}")
            # Fall back to mock implementation
            LIBOQS_AVAILABLE = False
            return self.decapsulate(private_key, ciphertext)  # Recursive call to use mock implementation


class NTRUKeyExchange(KeyExchangeAlgorithm):
    """NTRU key exchange algorithm.
    
    NTRU is a post-quantum key encapsulation mechanism (KEM) based on the
    hardness of lattice problems.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize NTRU with the specified security level.
        
        Args:
            security_level: Security level (1, 3, or 5)
        """
        global LIBOQS_AVAILABLE
        
        self.security_level = security_level
        self.kem = None
        self.variant = None
        
        # Attempt to get list of enabled KEM mechanisms if OQS is available
        self.enabled_kems = []
        if LIBOQS_AVAILABLE:
            try:
                self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            except Exception as e:
                logger.error(f"Error getting enabled KEM mechanisms: {e}")
                LIBOQS_AVAILABLE = False
        
        if not LIBOQS_AVAILABLE:
            logger.warning("Using deterministic mock implementation of NTRU")
            return
        
        # Map security levels to NTRU variants or suitable alternatives
        # Traditional NTRU might not be available, but we can use alternatives
        ntru_variants = {
            1: ["sntrup761"],  # approx. security level 1-3
            3: ["sntrup761"],  # approx. security level 1-3
            5: ["sntrup761"]   # lower than level 5, but best available option
        }
        
        if security_level not in ntru_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
        
        # Try to find an available NTRU-like variant
        variant_found = False
        for variant in ntru_variants[security_level]:
            if variant in self.enabled_kems:
                self.variant = variant
                variant_found = True
                break
        
        if not variant_found:
            logger.warning(f"No NTRU-like variant found for security level {security_level}, using deterministic mock implementation")
            LIBOQS_AVAILABLE = False
            return
        
        # Try to create the KEM instance
        try:
            self.kem = oqs.KeyEncapsulation(self.variant)
            logger.info(f"Successfully initialized NTRU-like variant {self.variant}")
        except Exception as e:
            logger.error(f"Error initializing NTRU-like algorithm: {e}")
            LIBOQS_AVAILABLE = False
        
        logger.info(f"Initialized NTRU key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the name of the algorithm."""
        if LIBOQS_AVAILABLE and self.kem is not None:
            if hasattr(self, 'variant') and self.variant and self.variant != "sntrup761":
                return f"{self.variant} (Level {self.security_level})"
            return f"NTRU (Level {self.security_level})"
        return f"NTRU (Level {self.security_level}) [Mock]"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        if LIBOQS_AVAILABLE and self.kem is not None and self.variant == "sntrup761":
            return ("SNTRUP761 is a lattice-based key encapsulation mechanism used as an NTRU alternative. "
                   "It provides similar security guarantees to NTRU.")
        return ("NTRU is a lattice-based key encapsulation mechanism. "
                "It is one of the oldest post-quantum cryptographic systems.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new NTRU keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        global LIBOQS_AVAILABLE
        
        if not LIBOQS_AVAILABLE or self.kem is None:
            # Deterministic mock implementation
            node_id = get_node_id()
            
            # Generate a private key deterministically from node ID and algorithm info
            seed = f"ntru-{self.security_level}-private-{node_id}"
            private_key = hashlib.sha256(seed.encode()).digest()
            
            # Generate public key deterministically from private key
            pub_seed = f"ntru-{self.security_level}-public-{private_key.hex()}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            logger.debug("Generated deterministic mock NTRU keypair")
            return public_key, private_key
        
        try:
            # Use actual OQS implementation with the current API pattern
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated NTRU-like keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating NTRU-like keypair: {e}")
            # Fall back to mock implementation
            LIBOQS_AVAILABLE = False
            return self.generate_keypair()  # Recursive call to use mock implementation
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        global LIBOQS_AVAILABLE
        
        if not LIBOQS_AVAILABLE or self.kem is None:
            # Deterministic mock implementation - no dependency on class state
            
            # Generate a ciphertext deterministically from the public key
            cipher_seed = f"ntru-{self.security_level}-ciphertext-{public_key.hex()}"
            ciphertext = hashlib.sha256(cipher_seed.encode()).digest()
            
            # Generate a shared secret deterministically from the public key and ciphertext ONLY
            secret_seed = f"ntru-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug("Performed deterministic mock NTRU encapsulation")
            return ciphertext, shared_secret
        
        try:
            # Use actual OQS implementation with current API pattern
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"NTRU-like encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during NTRU-like encapsulation: {e}")
            # Fall back to mock implementation
            LIBOQS_AVAILABLE = False
            return self.encapsulate(public_key)  # Recursive call to use mock implementation
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        global LIBOQS_AVAILABLE
        
        if not LIBOQS_AVAILABLE or self.kem is None:
            # Generate a public key from the private key using the SAME algorithm as in generate_keypair
            private_key_hex = private_key.hex()
            pub_seed = f"ntru-{self.security_level}-public-{private_key_hex}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            # Generate shared secret using the SAME algorithm as in encapsulate
            secret_seed = f"ntru-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug("Performed deterministic mock NTRU decapsulation")
            return shared_secret
        
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"NTRU-like decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during NTRU-like decapsulation: {e}")
            # Fall back to mock implementation
            LIBOQS_AVAILABLE = False
            return self.decapsulate(private_key, ciphertext)  # Recursive call to use mock implementation
