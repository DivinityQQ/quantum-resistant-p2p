"""
Cryptographic layer for post-quantum and symmetric cryptography.

This package provides implementations of post-quantum key exchange algorithms,
symmetric encryption, digital signatures, and secure key storage.
"""

from .key_exchange import (
    KeyExchangeAlgorithm, MLKEMKeyExchange, HQCKeyExchange, 
    FrodoKEMKeyExchange
)
from .symmetric import SymmetricAlgorithm, AES256GCM, ChaCha20Poly1305
from .signatures import SignatureAlgorithm, MLDSASignature, SPHINCSSignature
from .key_storage import KeyStorage
from .algorithm_base import CryptoAlgorithm

# For backward compatibility (will be deprecated in future)
# These aliases allow existing code to continue working
KyberKeyExchange = MLKEMKeyExchange
DilithiumSignature = MLDSASignature

# Import OQS to get the version
import oqs # type: ignore
LIBOQS_AVAILABLE = True
LIBOQS_VERSION = oqs.oqs_version()

__all__ = [
    'KeyExchangeAlgorithm',
    'MLKEMKeyExchange', 'HQCKeyExchange', 'FrodoKEMKeyExchange',
    'KyberKeyExchange',  # Backward compatibility
    'SymmetricAlgorithm', 'AES256GCM', 'ChaCha20Poly1305',
    'SignatureAlgorithm', 'MLDSASignature', 'SPHINCSSignature', 'DilithiumSignature',
    'KeyStorage', 'CryptoAlgorithm',
    'LIBOQS_AVAILABLE', 'LIBOQS_VERSION'
]