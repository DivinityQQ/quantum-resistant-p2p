"""
Quantum Resistant P2P Application.

This package provides a secure peer-to-peer application with post-quantum cryptography.
"""

# Set LIBOQS_AVAILABLE to True since we're using a vendored version
LIBOQS_AVAILABLE = True

# Initialize the vendored OQS module
from . import vendor  # type: ignore # noqa: F401

# Import OQS
import oqs  # type: ignore

# Get OQS version
LIBOQS_VERSION = oqs.oqs_version()

# Log OQS initialization
import logging
logger = logging.getLogger(__name__)
logger.info(f"Successfully loaded OQS version {LIBOQS_VERSION}")

# Log available mechanisms (as info)
try:
    kems = oqs.get_enabled_kem_mechanisms()
    sigs = oqs.get_enabled_sig_mechanisms()
    logger.info(f"Enabled KEM mechanisms: {len(kems)}")
    logger.info(f"Enabled signature mechanisms: {len(sigs)}")
except Exception as e:
    logger.error(f"Error checking OQS mechanisms: {e}")

# Package version
__version__ = "0.2.0"