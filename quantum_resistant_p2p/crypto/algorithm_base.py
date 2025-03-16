"""
Base classes for cryptographic algorithms.
"""

import abc
from typing import Optional

# Check if OQS is available
try:
    import oqs # type: ignore
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False


class CryptoAlgorithm(abc.ABC):
    """Abstract base class for all cryptographic algorithms."""
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Get the internal name of the algorithm (may include implementation details)."""
        pass
    
    @property
    def display_name(self) -> str:
        """Get a user-friendly name of the algorithm for display in UI."""
        # By default, remove any "[Mock]" suffix for UI display
        return self.name.split(" [Mock]")[0]
    
    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Get a description of the algorithm."""
        pass
    
    @property
    def is_using_mock(self) -> bool:
        """Check if this algorithm is using a mock implementation."""
        return "[Mock]" in self.name
    
    @property
    def actual_variant(self) -> Optional[str]:
        """Get the actual OQS variant being used, if applicable."""
        if hasattr(self, 'variant') and getattr(self, 'variant') is not None:
            return getattr(self, 'variant')
        return None
    
    def get_security_info(self) -> dict:
        """Get detailed security information about this algorithm."""
        info = {
            "name": self.display_name,
            "mock_implementation": self.is_using_mock,
            "description": self.description
        }
        
        # Add variant information if available
        if self.actual_variant:
            info["actual_variant"] = self.actual_variant
        
        # Add security level if available
        if hasattr(self, 'security_level'):
            info["security_level"] = getattr(self, 'security_level')
        
        return info
