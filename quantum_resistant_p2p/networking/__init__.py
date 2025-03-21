"""
Networking layer for P2P communication.

This package provides functionality for peer discovery, direct communication
between nodes, and handling of network connections.
"""

from .p2p_node import P2PNode
from .discovery import NodeDiscovery
from .node_identity import load_or_generate_node_id, save_node_id, get_app_data_dir

__all__ = ['P2PNode', 'NodeDiscovery', 'load_or_generate_node_id', 'save_node_id', 'get_app_data_dir']
