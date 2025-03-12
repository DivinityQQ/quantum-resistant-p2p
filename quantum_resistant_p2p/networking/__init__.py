"""
Networking layer for P2P communication.

This package provides functionality for peer discovery, direct communication
between nodes, and handling of network connections.
"""

from .p2p_node import P2PNode
from .discovery import NodeDiscovery

__all__ = ['P2PNode', 'NodeDiscovery']
