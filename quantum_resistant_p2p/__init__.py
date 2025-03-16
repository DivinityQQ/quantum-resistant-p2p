"""
Quantum Resistant P2P Application.

This package provides a secure peer-to-peer application with post-quantum cryptography.
"""

# Initialize LIBOQS_AVAILABLE flag to False by default
LIBOQS_AVAILABLE = False
LIBOQS_VERSION = None

# Initialize the vendored OQS module - this sets up paths but won't install anything
from . import vendor  # type: ignore # noqa: F401

# Try to import OQS to check if it's available
try:
    import oqs  # type: ignore
    
    # Try to access a function to verify it works
    try:
        LIBOQS_VERSION = oqs.oqs_version()
        LIBOQS_AVAILABLE = True
        
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Successfully loaded OQS version {LIBOQS_VERSION}")
        
        # Basic verification of functionality
        try:
            kems = oqs.get_enabled_kem_mechanisms()
            sigs = oqs.get_enabled_sig_mechanisms()
            logger.info(f"Enabled KEM mechanisms: {len(kems)}")
            logger.info(f"Enabled signature mechanisms: {len(sigs)}")
        except Exception as e:
            logger.warning(f"OQS imported but functionality check failed: {e}")
            LIBOQS_AVAILABLE = False
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"OQS imported but version check failed: {e}")
        LIBOQS_AVAILABLE = False
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to import OQS: {e}")
    logger.warning("Using mock implementations for post-quantum algorithms")

# Package version
__version__ = "0.1.0"