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
    # Signal for running async tasks
    async_task = pyqtSignal(object)
    # Signal to indicate connection started
    connection_started = pyqtSignal(str, str, int)
    
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
        
        # Keep track of the currently selected peer
        self.current_peer_id = None
        
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
        
        # Auto-connect checkbox
        self.auto_connect_button = QPushButton("Connect")
        self.auto_connect_button.clicked.connect(self._on_connect_clicked)
        button_layout.addWidget(self.auto_connect_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Set a reasonable minimum width
        self.setMinimumWidth(200)
        
        logger.debug("Peer list widget initialized")
    
    def update_peers(self, discovered: list, connected: list):
        """Update the list of peers while preserving selection.
        
        Args:
            discovered: List of discovered peers (node_id, host, port)
            connected: List of connected peer IDs
        """
        # Remember the currently selected peer ID
        selected_items = self.peer_list.selectedItems()
        if selected_items:
            selected_peer_id = selected_items[0].data(Qt.UserRole)
        else:
            selected_peer_id = self.current_peer_id
        
        # Remember scroll position
        scrollbar_pos = self.peer_list.verticalScrollBar().value()
        
        # Clear and rebuild the list
        self.peer_list.clear()
        
        # Rebuild the list
        new_selected_item = None
        
        # Add discovered peers
        for node_id, host, port in discovered:
            item = QListWidgetItem(f"{node_id[:8]}... ({host}:{port})")
            item.setData(Qt.UserRole, node_id)
            # Store host and port as additional data
            item.setData(Qt.UserRole + 1, host)
            item.setData(Qt.UserRole + 2, port)
            
            # Highlight connected peers
            if node_id in connected:
                item.setForeground(Qt.green)
                item.setText(f"{node_id[:8]}... ({host}:{port}) [Connected]")
            
            self.peer_list.addItem(item)
            
            # If this is the currently selected peer, remember this item
            if node_id == selected_peer_id:
                new_selected_item = item
        
        # Restore selection
        if new_selected_item:
            self.peer_list.setCurrentItem(new_selected_item)
            
        # Restore scroll position
        self.peer_list.verticalScrollBar().setValue(scrollbar_pos)
        
        logger.debug(f"Updated peer list with {len(discovered)} peers")
    
    def _on_peer_clicked(self, item):
        """Handle clicking on a peer in the list.
        
        Args:
            item: The clicked list item
        """
        # Get the peer ID from the item
        peer_id = item.data(Qt.UserRole)
        host = item.data(Qt.UserRole + 1)
        port = item.data(Qt.UserRole + 2)
        
        # Store the current peer ID
        self.current_peer_id = peer_id
        
        # Emit the signal to select this peer
        self.peer_selected.emit(peer_id)
        
        # Automatically attempt to connect if not already connected
        if peer_id not in self.node.get_peers():
            logger.info(f"Auto-connecting to peer {peer_id} at {host}:{port}")
            self.connection_started.emit(peer_id, host, port)
        
        logger.debug(f"Selected peer {peer_id}")
    
    def _on_connect_clicked(self):
        """Handle clicking the connect button."""
        # Get the selected peer
        selected_items = self.peer_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer to connect to.")
            return
        
        item = selected_items[0]
        peer_id = item.data(Qt.UserRole)
        host = item.data(Qt.UserRole + 1)
        port = item.data(Qt.UserRole + 2)
        
        # Only attempt connection if not already connected
        if peer_id in self.node.get_peers():
            QMessageBox.information(self, "Already Connected", f"Already connected to {peer_id[:8]}...")
            return
        
        # Emit signal to start connection
        self.connection_started.emit(peer_id, host, port)
        
        logger.info(f"Starting connection to peer {peer_id} at {host}:{port}")
    
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
