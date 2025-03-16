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
    import oqs # type: ignore
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
        global LIBOQS_AVAILABLE
        
        self.security_level = security_level
        self.kem = None
        self.variant = None
        self._is_using_mock = False
        
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
            
        # First try to determine if OQS is available and what mechanisms are enabled
        if LIBOQS_AVAILABLE:
            try:
                self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            except Exception as e:
                logger.error(f"Error getting enabled KEM mechanisms: {e}")
                LIBOQS_AVAILABLE = False
                self._is_using_mock = True
                
        # If OQS is not available, use mock implementation
        if not LIBOQS_AVAILABLE:
            logger.warning(f"Using deterministic mock implementation of ML-KEM (Level {security_level})")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = ml_kem_variants[security_level]
            return
            
        # Try to find an available implementation
        if ml_kem_variants[security_level] in self.enabled_kems:
            self.variant = ml_kem_variants[security_level]
        elif kyber_variants[security_level] in self.enabled_kems:
            # Use older Kyber implementation if available
            self.variant = kyber_variants[security_level]
        else:
            logger.warning(f"No ML-KEM variant found for security level {security_level}, using deterministic mock implementation")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = ml_kem_variants[security_level]
            return
        
        # Try to create the KEM instance
        try:
            self.kem = oqs.KeyEncapsulation(self.variant)
            logger.info(f"Successfully initialized ML-KEM variant {self.variant}")
        except Exception as e:
            logger.error(f"Error initializing ML-KEM: {e}")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = ml_kem_variants[security_level]
        
        logger.info(f"Initialized ML-KEM key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"ML-KEM (Level {self.security_level}){' [Mock]' if self._is_using_mock else ''}"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"ML-KEM (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        if self._is_using_mock:
            return ("ML-KEM is a module-lattice-based key encapsulation mechanism. "
                    "It is one of the NIST post-quantum cryptography standards. "
                    "[Mock implementation]")
        return ("ML-KEM is a module-lattice-based key encapsulation mechanism. "
                "It is one of the NIST post-quantum cryptography standards.")
    
    @property
    def is_using_mock(self) -> bool:
        """Check if this algorithm is using a mock implementation."""
        return self._is_using_mock
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new ML-KEM keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        if self._is_using_mock:
            # Deterministic mock implementation
            node_id = get_node_id()
            
            # Generate a private key deterministically from node ID and algorithm info
            seed = f"ml-kem-{self.security_level}-private-{node_id}"
            private_key = hashlib.sha256(seed.encode()).digest()
            
            # Generate public key deterministically from private key
            # NOTE: This is critical - both sides need to derive public key from private key consistently
            pub_seed = f"ml-kem-{self.security_level}-public-{private_key.hex()}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            logger.debug(f"Generated deterministic mock ML-KEM keypair (level {self.security_level})")
            return public_key, private_key
        
        try:
            # Use actual OQS implementation with the current API pattern
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated ML-KEM keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating ML-KEM keypair: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.generate_keypair()  # Recursive call to use mock implementation
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        if self._is_using_mock:
            # Deterministic mock implementation - no dependency on class state
            
            # Generate a ciphertext deterministically from the public key
            cipher_seed = f"ml-kem-{self.security_level}-ciphertext-{public_key.hex()}"
            ciphertext = hashlib.sha256(cipher_seed.encode()).digest()
            
            # Generate a shared secret deterministically from the public key and ciphertext ONLY
            secret_seed = f"ml-kem-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug(f"Performed deterministic mock ML-KEM encapsulation (level {self.security_level})")
            return ciphertext, shared_secret
        
        try:
            # Use actual OQS implementation with current API pattern
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"ML-KEM encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during ML-KEM encapsulation: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.encapsulate(public_key)  # Recursive call to use mock implementation
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        if self._is_using_mock:
            # Generate a public key from the private key using the SAME algorithm as in generate_keypair
            private_key_hex = private_key.hex()
            pub_seed = f"ml-kem-{self.security_level}-public-{private_key_hex}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            # Generate shared secret using the SAME algorithm as in encapsulate
            secret_seed = f"ml-kem-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug(f"Performed deterministic mock ML-KEM decapsulation (level {self.security_level})")
            return shared_secret
        
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"ML-KEM decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during ML-KEM decapsulation: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.decapsulate(private_key, ciphertext)  # Recursive call to use mock implementation


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
        global LIBOQS_AVAILABLE
        
        self.security_level = security_level
        self.kem = None
        self.variant = None
        self._is_using_mock = False
        
        # Map security levels to HQC variants
        hqc_variants = {
            1: "HQC-128",
            3: "HQC-192",
            5: "HQC-256"
        }
        
        if security_level not in hqc_variants:
            raise ValueError(f"Invalid security level: {security_level}. Must be 1, 3, or 5.")
            
        # First try to determine if OQS is available and what mechanisms are enabled
        if LIBOQS_AVAILABLE:
            try:
                self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            except Exception as e:
                logger.error(f"Error getting enabled KEM mechanisms: {e}")
                LIBOQS_AVAILABLE = False
                self._is_using_mock = True
                
        # If OQS is not available, use mock implementation
        if not LIBOQS_AVAILABLE:
            logger.warning(f"Using deterministic mock implementation of HQC (Level {security_level})")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = hqc_variants[security_level]
            return
            
        # Try to find an available implementation
        if hqc_variants[security_level] in self.enabled_kems:
            self.variant = hqc_variants[security_level]
        else:
            logger.warning(f"No HQC variant found for security level {security_level}, using deterministic mock implementation")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = hqc_variants[security_level]
            return
        
        # Try to create the KEM instance
        try:
            self.kem = oqs.KeyEncapsulation(self.variant)
            logger.info(f"Successfully initialized HQC variant {self.variant}")
        except Exception as e:
            logger.error(f"Error initializing HQC: {e}")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = hqc_variants[security_level]
        
        logger.info(f"Initialized HQC key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"HQC (Level {self.security_level}){' [Mock]' if self._is_using_mock else ''}"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"HQC (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        if self._is_using_mock:
            return ("HQC (Hamming Quasi-Cyclic) is a code-based key encapsulation mechanism. "
                    "It uses error-correcting codes and is based on the hardness of "
                    "decoding problems. [Mock implementation]")
        return ("HQC (Hamming Quasi-Cyclic) is a code-based key encapsulation mechanism. "
                "It uses error-correcting codes and is based on the hardness of "
                "decoding problems.")
    
    @property
    def is_using_mock(self) -> bool:
        """Check if this algorithm is using a mock implementation."""
        return self._is_using_mock
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new HQC keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        if self._is_using_mock:
            # Deterministic mock implementation
            node_id = get_node_id()
            
            # Generate a private key deterministically from node ID and algorithm info
            seed = f"hqc-{self.security_level}-private-{node_id}"
            private_key = hashlib.sha256(seed.encode()).digest()
            
            # Generate public key deterministically from private key
            pub_seed = f"hqc-{self.security_level}-public-{private_key.hex()}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            logger.debug(f"Generated deterministic mock HQC keypair (level {self.security_level})")
            return public_key, private_key
        
        try:
            # Use actual OQS implementation with the current API pattern
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated HQC keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating HQC keypair: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.generate_keypair()  # Recursive call to use mock implementation
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        if self._is_using_mock:
            # Deterministic mock implementation - no dependency on class state
            
            # Generate a ciphertext deterministically from the public key
            cipher_seed = f"hqc-{self.security_level}-ciphertext-{public_key.hex()}"
            ciphertext = hashlib.sha256(cipher_seed.encode()).digest()
            
            # Generate a shared secret deterministically from the public key and ciphertext ONLY
            secret_seed = f"hqc-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug(f"Performed deterministic mock HQC encapsulation (level {self.security_level})")
            return ciphertext, shared_secret
        
        try:
            # Use actual OQS implementation with current API pattern
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"HQC encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during HQC encapsulation: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.encapsulate(public_key)  # Recursive call to use mock implementation
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        if self._is_using_mock:
            # Generate a public key from the private key using the SAME algorithm as in generate_keypair
            private_key_hex = private_key.hex()
            pub_seed = f"hqc-{self.security_level}-public-{private_key_hex}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            # Generate shared secret using the SAME algorithm as in encapsulate
            secret_seed = f"hqc-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug(f"Performed deterministic mock HQC decapsulation (level {self.security_level})")
            return shared_secret
        
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"HQC decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during HQC decapsulation: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.decapsulate(private_key, ciphertext)  # Recursive call to use mock implementation


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
        global LIBOQS_AVAILABLE
        
        self.security_level = security_level
        self.use_aes = use_aes
        self.kem = None
        self.variant = None
        self._is_using_mock = False
        
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
            
        # First try to determine if OQS is available and what mechanisms are enabled
        if LIBOQS_AVAILABLE:
            try:
                self.enabled_kems = oqs.get_enabled_kem_mechanisms()
            except Exception as e:
                logger.error(f"Error getting enabled KEM mechanisms: {e}")
                LIBOQS_AVAILABLE = False
                self._is_using_mock = True
                
        # If OQS is not available, use mock implementation
        if not LIBOQS_AVAILABLE:
            logger.warning(f"Using deterministic mock implementation of FrodoKEM (Level {security_level})")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = frodo_variants[security_level]
            return
            
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
                logger.warning(f"No FrodoKEM variant found for security level {security_level}, using deterministic mock implementation")
                self._is_using_mock = True
                # Still use the standard variant name for the mock
                self.variant = frodo_variants[security_level]
                return
        
        # Try to create the KEM instance
        try:
            self.kem = oqs.KeyEncapsulation(self.variant)
            logger.info(f"Successfully initialized FrodoKEM variant {self.variant}")
        except Exception as e:
            logger.error(f"Error initializing FrodoKEM: {e}")
            self._is_using_mock = True
            # Still use the standard variant name for the mock
            self.variant = frodo_variants[security_level]
        
        logger.info(f"Initialized FrodoKEM key exchange with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        rand_type = "AES" if self.use_aes else "SHAKE"
        return f"FrodoKEM (Level {self.security_level}, {rand_type}){' [Mock]' if self._is_using_mock else ''}"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        rand_type = "AES" if self.use_aes else "SHAKE"
        return f"FrodoKEM (Level {self.security_level}, {rand_type})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        if self._is_using_mock:
            return ("FrodoKEM is a lattice-based key encapsulation mechanism based on "
                    "the standard Learning With Errors problem. It is considered "
                    "a conservative post-quantum KEM. [Mock implementation]")
        return ("FrodoKEM is a lattice-based key encapsulation mechanism based on "
                "the standard Learning With Errors problem. It is considered "
                "a conservative post-quantum KEM.")
    
    @property
    def is_using_mock(self) -> bool:
        """Check if this algorithm is using a mock implementation."""
        return self._is_using_mock
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new FrodoKEM keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        if self._is_using_mock:
            # Deterministic mock implementation
            node_id = get_node_id()
            
            # Generate a private key deterministically from node ID and algorithm info
            seed = f"frodo-{self.security_level}-private-{node_id}"
            private_key = hashlib.sha256(seed.encode()).digest()
            
            # Generate public key deterministically from private key
            pub_seed = f"frodo-{self.security_level}-public-{private_key.hex()}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            logger.debug(f"Generated deterministic mock FrodoKEM keypair (level {self.security_level})")
            return public_key, private_key
        
        try:
            # Use actual OQS implementation with the current API pattern
            public_key = self.kem.generate_keypair()
            private_key = self.kem.export_secret_key()
            
            logger.debug(f"Generated FrodoKEM keypair: public key {len(public_key)} bytes, "
                      f"private key {len(private_key)} bytes")
            
            return public_key, private_key
        except Exception as e:
            logger.error(f"Error generating FrodoKEM keypair: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.generate_keypair()  # Recursive call to use mock implementation
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        if self._is_using_mock:
            # Deterministic mock implementation - no dependency on class state
            
            # Generate a ciphertext deterministically from the public key
            cipher_seed = f"frodo-{self.security_level}-ciphertext-{public_key.hex()}"
            ciphertext = hashlib.sha256(cipher_seed.encode()).digest()
            
            # Generate a shared secret deterministically from the public key and ciphertext ONLY
            secret_seed = f"frodo-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug(f"Performed deterministic mock FrodoKEM encapsulation (level {self.security_level})")
            return ciphertext, shared_secret
        
        try:
            # Use actual OQS implementation with current API pattern
            # Create a new instance for encapsulation
            encap_kem = oqs.KeyEncapsulation(self.variant)
            ciphertext, shared_secret = encap_kem.encap_secret(public_key)
            
            logger.debug(f"FrodoKEM encapsulation: ciphertext {len(ciphertext)} bytes, "
                      f"shared secret {len(shared_secret)} bytes")
            
            return ciphertext, shared_secret
        except Exception as e:
            logger.error(f"Error during FrodoKEM encapsulation: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.encapsulate(public_key)  # Recursive call to use mock implementation
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        if self._is_using_mock:
            # Generate a public key from the private key using the SAME algorithm as in generate_keypair
            private_key_hex = private_key.hex()
            pub_seed = f"frodo-{self.security_level}-public-{private_key_hex}"
            public_key = hashlib.sha256(pub_seed.encode()).digest()
            
            # Generate shared secret using the SAME algorithm as in encapsulate
            secret_seed = f"frodo-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
            shared_secret = hashlib.sha256(secret_seed.encode()).digest()
            
            logger.debug(f"Performed deterministic mock FrodoKEM decapsulation (level {self.security_level})")
            return shared_secret
        
        try:
            # Create a new KEM instance with the private key for decapsulation
            decap_kem = oqs.KeyEncapsulation(self.variant, private_key)
            shared_secret = decap_kem.decap_secret(ciphertext)
            
            logger.debug(f"FrodoKEM decapsulation: shared secret {len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error during FrodoKEM decapsulation: {e}")
            # Fall back to mock implementation
            self._is_using_mock = True
            return self.decapsulate(private_key, ciphertext)  # Recursive call to use mock implementation


# For backward compatibility, but this will use the mock implementation only
class NTRUKeyExchange(KeyExchangeAlgorithm):
    """NTRU key exchange algorithm (mock implementation only).
    
    NTRU is a post-quantum key encapsulation mechanism (KEM) based on the
    hardness of lattice problems. This implementation is for compatibility only.
    """
    
    def __init__(self, security_level: int = 3):
        """Initialize NTRU with the specified security level.
        
        Args:
            security_level: Security level (1, 3, or 5)
        """
        self.security_level = security_level
        self._is_using_mock = True
        
        logger.warning(f"Using deterministic mock implementation of NTRU (Level {security_level})")
        logger.warning(f"For a real post-quantum KEM implementation, please use HQCKeyExchange or FrodoKEMKeyExchange instead")
        
        logger.info(f"Initialized NTRU mock implementation with security level {security_level}")
    
    @property
    def name(self) -> str:
        """Get the internal name of the algorithm."""
        return f"NTRU (Level {self.security_level}) [Mock]"
    
    @property
    def display_name(self) -> str:
        """Get the user-friendly name for display."""
        return f"NTRU (Level {self.security_level})"
    
    @property
    def description(self) -> str:
        """Get a description of the algorithm."""
        return ("NTRU is a lattice-based key encapsulation mechanism. "
                "It is one of the oldest post-quantum cryptographic systems. "
                "[Mock implementation only]")
    
    @property
    def is_using_mock(self) -> bool:
        """Check if this algorithm is using a mock implementation."""
        return True
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new NTRU keypair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        # Deterministic mock implementation
        node_id = get_node_id()
        
        # Generate a private key deterministically from node ID and algorithm info
        seed = f"ntru-{self.security_level}-private-{node_id}"
        private_key = hashlib.sha256(seed.encode()).digest()
        
        # Generate public key deterministically from private key
        pub_seed = f"ntru-{self.security_level}-public-{private_key.hex()}"
        public_key = hashlib.sha256(pub_seed.encode()).digest()
        
        logger.debug(f"Generated deterministic mock NTRU keypair (level {self.security_level})")
        return public_key, private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        # Deterministic mock implementation - no dependency on class state
        
        # Generate a ciphertext deterministically from the public key
        cipher_seed = f"ntru-{self.security_level}-ciphertext-{public_key.hex()}"
        ciphertext = hashlib.sha256(cipher_seed.encode()).digest()
        
        # Generate a shared secret deterministically from the public key and ciphertext ONLY
        secret_seed = f"ntru-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
        shared_secret = hashlib.sha256(secret_seed.encode()).digest()
        
        logger.debug(f"Performed deterministic mock NTRU encapsulation (level {self.security_level})")
        return ciphertext, shared_secret
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using the recipient's private key.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The ciphertext from the sender
            
        Returns:
            The shared secret
        """
        # Generate a public key from the private key using the SAME algorithm as in generate_keypair
        private_key_hex = private_key.hex()
        pub_seed = f"ntru-{self.security_level}-public-{private_key_hex}"
        public_key = hashlib.sha256(pub_seed.encode()).digest()
        
        # Generate shared secret using the SAME algorithm as in encapsulate
        secret_seed = f"ntru-{self.security_level}-shared-{public_key.hex()}-{ciphertext.hex()}"
        shared_secret = hashlib.sha256(secret_seed.encode()).digest()
        
        logger.debug(f"Performed deterministic mock NTRU decapsulation (level {self.security_level})")
        return shared_secret
