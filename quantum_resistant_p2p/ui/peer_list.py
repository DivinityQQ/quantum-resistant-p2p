"""
Widget for displaying and managing the list of peers.
"""

import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel, 
    QPushButton, QHBoxLayout, QInputDialog, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QColor

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
    
    def __init__(self, node: P2PNode, discovery: NodeDiscovery, secure_messaging=None, parent=None):
        """Initialize the peer list widget.
        
        Args:
            node: The P2P node
            discovery: The node discovery service
            secure_messaging: The secure messaging service (optional)
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.node = node
        self.discovery = discovery
        self.secure_messaging = secure_messaging
        
        # Keep track of the currently selected peer
        self.current_peer_id = None
        
        self._init_ui()
        
        # If we have secure messaging, register for crypto changes
        if self.secure_messaging:
            self.secure_messaging.register_settings_change_listener(self._refresh_crypto_indicators)
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Header
        header_label = QLabel("Available Peers")
        header_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(header_label)
        
        # Peer list
        self.peer_list = QListWidget()
        self.peer_list.setIconSize(QSize(16, 16))  # For status icons
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
        
        # Connect button
        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self._on_connect_clicked)
        button_layout.addWidget(self.connect_button)
        
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
                
                # Add crypto status indicator if available
                status_text = " [Connected"
                
                if self.secure_messaging and node_id in self.secure_messaging.peer_crypto_settings:
                    peer_settings = self.secure_messaging.peer_crypto_settings[node_id]
                    my_settings = {
                        "key_exchange": self.secure_messaging.key_exchange.name,
                        "symmetric": self.secure_messaging.symmetric.name,
                        "signature": self.secure_messaging.signature.name
                    }
                    
                    # Check for mismatches
                    has_mismatches = any(
                        peer_settings.get(key) != my_settings[key]
                        for key in my_settings
                        if key in peer_settings
                    )
                    
                    if has_mismatches:
                        status_text += ", ⚠️ Settings differ]"
                        item.setForeground(QColor(255, 165, 0))  # Orange for warning
                    else:
                        status_text += ", ✓ Compatible]"
                else:
                    status_text += "]"
                
                item.setText(f"{node_id[:8]}... ({host}:{port}) {status_text}")
            
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
    
    def _refresh_crypto_indicators(self):
        """Refresh crypto status indicators in the peer list."""
        # Only proceed if we have secure_messaging
        if not self.secure_messaging:
            return
            
        # Get current connected peers
        connected = self.node.get_peers()
        
        # Get currently discovered peers
        discovered = self.discovery.get_discovered_nodes()
        
        # Update the list with new indicators
        self.update_peers(discovered, connected)
