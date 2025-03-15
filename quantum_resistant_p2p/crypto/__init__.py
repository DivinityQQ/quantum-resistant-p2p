"""
Cryptographic layer for post-quantum and symmetric cryptography.

This package provides implementations of post-quantum key exchange algorithms,
symmetric encryption, digital signatures, and secure key storage.
"""

from .key_exchange import KeyExchangeAlgorithm, KyberKeyExchange, NTRUKeyExchange
from .symmetric import SymmetricAlgorithm, AES256GCM, ChaCha20Poly1305
from .signatures import SignatureAlgorithm, DilithiumSignature, SPHINCSSignature
from .key_storage import KeyStorage
from .algorithm_base import CryptoAlgorithm

# Try to import OQS to check if it's available
try:
    import oqs
    LIBOQS_AVAILABLE = True
    LIBOQS_VERSION = oqs.oqs_version()
except ImportError:
    LIBOQS_AVAILABLE = False
    LIBOQS_VERSION = None

__all__ = [
    'KeyExchangeAlgorithm', 'KyberKeyExchange', 'NTRUKeyExchange',
    'SymmetricAlgorithm', 'AES256GCM', 'ChaCha20Poly1305',
    'SignatureAlgorithm', 'DilithiumSignature', 'SPHINCSSignature',
    'KeyStorage', 'CryptoAlgorithm',
    'LIBOQS_AVAILABLE', 'LIBOQS_VERSION'
]
