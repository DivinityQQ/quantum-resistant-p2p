"""
Widget for displaying and managing the list of peers.
"""

import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel, 
    QPushButton, QHBoxLayout, QInputDialog, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot

from ..networking import P2PNode, NodeDiscovery

logger = logging.getLogger(__name__)


class PeerListWidget(QWidget):
    """Widget for displaying and interacting with the list of peers."""
    
    # Signal emitted when a peer is selected
    peer_selected = pyqtSignal(str)
    
    def __init__(self, node: P2PNode, discovery: NodeDiscovery, parent=None):
        """Initialize the peer list widget.
        
        Args:
            node: The P2P node
            discovery: The node discovery service
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.node = node
        self.discovery = discovery
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Available Peers")
        header_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(header_label)
        
        # Peer list
        self.peer_list = QListWidget()
        self.peer_list.itemClicked.connect(self._on_peer_clicked)
        layout.addWidget(self.peer_list)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._on_refresh_clicked)
        button_layout.addWidget(self.refresh_button)
        
        # Add peer button
        self.add_peer_button = QPushButton("Add Peer")
        self.add_peer_button.clicked.connect(self._on_add_peer_clicked)
        button_layout.addWidget(self.add_peer_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Set a reasonable minimum width
        self.setMinimumWidth(200)
        
        logger.debug("Peer list widget initialized")
    
    def update_peers(self, discovered: list, connected: list):
        """Update the list of peers.
        
        Args:
            discovered: List of discovered peers (node_id, host, port)
            connected: List of connected peer IDs
        """
        self.peer_list.clear()
        
        # Add discovered peers
        for node_id, host, port in discovered:
            item = QListWidgetItem(f"{node_id[:8]}... ({host}:{port})")
            item.setData(Qt.UserRole, node_id)
            
            # Highlight connected peers
            if node_id in connected:
                item.setForeground(Qt.green)
            
            self.peer_list.addItem(item)
        
        logger.debug(f"Updated peer list with {len(discovered)} peers")
    
    def _on_peer_clicked(self, item):
        """Handle clicking on a peer in the list.
        
        Args:
            item: The clicked list item
        """
        # Get the peer ID from the item
        peer_id = item.data(Qt.UserRole)
        
        # Emit the signal
        self.peer_selected.emit(peer_id)
        
        logger.debug(f"Selected peer {peer_id}")
    
    def _on_refresh_clicked(self):
        """Handle clicking the refresh button."""
        # Get discovered and connected peers
        discovered = self.discovery.get_discovered_nodes()
        connected = self.node.get_peers()
        
        # Update the list
        self.update_peers(discovered, connected)
        
        logger.debug("Manually refreshed peer list")
    
    def _on_add_peer_clicked(self):
        """Handle clicking the add peer button."""
        # Show input dialog for host and port
        host, ok = QInputDialog.getText(
            self, "Add Peer", "Enter peer host:"
        )
        
        if not ok or not host:
            return
        
        port, ok = QInputDialog.getInt(
            self, "Add Peer", "Enter peer port:", 8000, 1, 65535
        )
        
        if not ok:
            return
        
        # Add the peer to discovery
        node_id = f"manual_{host}_{port}"
        self.discovery.add_known_node(node_id, host, port)
        
        # Update the list
        discovered = self.discovery.get_discovered_nodes()
        connected = self.node.get_peers()
        self.update_peers(discovered, connected)
        
        logger.info(f"Manually added peer {host}:{port}")
        
        # Try to connect to the peer
        import asyncio
        asyncio.create_task(self._connect_to_peer(host, port))
    
    async def _connect_to_peer(self, host: str, port: int):
        """Asynchronously connect to a peer.
        
        Args:
            host: The peer host
            port: The peer port
        """
        try:
            # Try to connect
            success = await self.node.connect_to_peer(host, port)
            
            if success:
                logger.info(f"Connected to peer {host}:{port}")
            else:
                logger.error(f"Failed to connect to peer {host}:{port}")
                
        except Exception as e:
            logger.error(f"Error connecting to peer {host}:{port}: {e}")
