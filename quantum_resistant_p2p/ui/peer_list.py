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
    
    def __init__(self, node: P2PNode, discovery: NodeDiscovery, secure_messaging=None, message_store=None, parent=None):
        """Initialize the peer list widget.
        
        Args:
            node: The P2P node
            discovery: The node discovery service
            secure_messaging: The secure messaging service (optional)
            message_store: The message store for persistent messages (optional)
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.node = node
        self.discovery = discovery
        self.secure_messaging = secure_messaging
        self.message_store = message_store
        
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
            # Basic item information
            item = QListWidgetItem(f"{node_id[:8]}... ({host}:{port})")
            item.setData(Qt.UserRole, node_id)
            item.setData(Qt.UserRole + 1, host)
            item.setData(Qt.UserRole + 2, port)
            
            # Determine state and styling
            is_connected = node_id in connected
            has_shared_key = False
            is_secure = False
            
            if self.secure_messaging:
                has_shared_key = node_id in self.secure_messaging.shared_keys
                key_exchange_state = self.secure_messaging.key_exchange_states.get(node_id, 0)
                is_secure = has_shared_key and key_exchange_state == 4  # ESTABLISHED
            
            # Set text and color based on state
            status_text = ""
            text_color = Qt.black
            
            if is_connected:
                if is_secure:
                    status_text = " [Secure]"
                    text_color = Qt.darkGreen
                else:
                    if has_shared_key:
                        # We have a key, but it's not fully established
                        status_text = " [Connected, Key Exchange Needed]"
                        text_color = QColor(255, 140, 0)  # Dark orange
                    else:
                        status_text = " [Connected]"
                        text_color = Qt.green
                    
                    # Add crypto compatibility indicator
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
                            status_text += " ⚠️ Settings Differ"
                            text_color = QColor(255, 165, 0)  # Orange for warning
            
            # Update the display text with status
            if status_text:
                item.setText(f"{node_id[:8]}... ({host}:{port}){status_text}")
            
            # Set the text color
            item.setForeground(text_color)
            
            self.peer_list.addItem(item)
            
            # If this is the currently selected peer, remember this item
            if node_id == selected_peer_id:
                new_selected_item = item
        
        # Restore selection
        if new_selected_item:
            self.peer_list.setCurrentItem(new_selected_item)
            
        # Restore scroll position
        self.peer_list.verticalScrollBar().setValue(scrollbar_pos)
        
        # Add unread message indicators 
        if self.message_store:
            for i in range(self.peer_list.count()):
                item = self.peer_list.item(i)
                peer_id = item.data(Qt.UserRole)
                
                if self.message_store.has_unread_messages(peer_id):
                    unread_count = self.message_store.get_unread_count(peer_id)
                    
                    # Add unread count to the displayed text
                    current_text = item.text()
                    # Remove existing unread indicator if present
                    if " [Unread:" in current_text:
                        current_text = current_text.split(" [Unread:")[0]
                    
                    # Add new unread indicator
                    item.setText(f"{current_text} [Unread: {unread_count}]")
                    
                    # Highlight with bold text and different color for unread
                    font = item.font()
                    font.setBold(True)
                    item.setFont(font)
                    
                    # Don't change colors for connected or secure peers
                    current_color = item.foreground().color()
                    if current_color == Qt.black:  # Only change if not already colored
                        item.setForeground(QColor(0, 120, 215))  # Blue for unread
        
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
        
        # Mark all messages from this peer as read if we have a message store
        if self.message_store:
            self.message_store.mark_all_read(peer_id)
            
            # Reset the visual appearance of this item (remove bold and color)
            current_text = item.text()
            if " [Unread:" in current_text:
                item.setText(current_text.split(" [Unread:")[0])
            font = item.font()
            font.setBold(False)
            item.setFont(font)
            item.setForeground(Qt.black)
        
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
