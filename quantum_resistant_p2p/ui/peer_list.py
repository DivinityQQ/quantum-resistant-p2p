"""
Widget for displaying and managing the list of peers.
"""

import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QListWidgetItem, QLabel, 
    QPushButton, QHBoxLayout, QInputDialog, QMessageBox, QHeaderView,
    QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSize
from PyQt5.QtGui import QColor, QFont, QIcon

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
    # Signal to indicate add peer requested
    add_peer_requested = pyqtSignal()
    
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
        
        # Use a table widget instead of list for better column control
        self.peer_table = QTableWidget()
        self.peer_table.setColumnCount(2)  # ID and Status columns
        self.peer_table.setHorizontalHeaderLabels(["Peer", "Status"])
        self.peer_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)  # ID column stretches
        self.peer_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Status fits content
        self.peer_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.peer_table.setSelectionMode(QTableWidget.SingleSelection)
        self.peer_table.setEditTriggers(QTableWidget.NoEditTriggers)  # Make table read-only
        self.peer_table.itemClicked.connect(self._on_peer_clicked)
        
        # Set row height to be a bit more compact
        self.peer_table.verticalHeader().setDefaultSectionSize(24)
        self.peer_table.verticalHeader().setVisible(False)  # Hide row numbers
        
        layout.addWidget(self.peer_table)
        
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
        selected_rows = self.peer_table.selectedItems()
        if selected_rows and selected_rows[0].column() == 0:  # Make sure we get a peer ID column
            selected_peer_id = selected_rows[0].data(Qt.UserRole)
        else:
            selected_peer_id = self.current_peer_id
        
        # Remember scroll position
        scrollbar_pos = self.peer_table.verticalScrollBar().value()
        
        # Clear and rebuild the table
        self.peer_table.setRowCount(0)  # Clear all rows
        self.peer_table.setSortingEnabled(False)  # Disable sorting while updating
        
        # Rebuild the table
        row = 0
        for node_id, host, port in discovered:
            self.peer_table.insertRow(row)
            
            # Determine state
            is_connected = node_id in connected
            has_shared_key = False
            is_secure = False
            
            if self.secure_messaging:
                has_shared_key = node_id in self.secure_messaging.shared_keys
                key_exchange_state = self.secure_messaging.key_exchange_states.get(node_id, 0)
                is_secure = has_shared_key and key_exchange_state == 4  # ESTABLISHED
            
            # ID column (short peer ID + address)
            id_item = QTableWidgetItem(f"{node_id[:8]}...")
            id_item.setData(Qt.UserRole, node_id)  # Store full ID
            id_item.setData(Qt.UserRole + 1, host)  # Store host
            id_item.setData(Qt.UserRole + 2, port)  # Store port
            
            # Set tooltip with full information
            tooltip = f"ID: {node_id}\nHost: {host}\nPort: {port}"
            if self.secure_messaging and node_id in self.secure_messaging.peer_crypto_settings:
                peer_settings = self.secure_messaging.peer_crypto_settings[node_id]
                key_exchange = peer_settings.get("key_exchange", "Unknown")
                symmetric = peer_settings.get("symmetric", "Unknown")
                signature = peer_settings.get("signature", "Unknown")
                tooltip += f"\n\nCrypto Settings:\nKey Exchange: {key_exchange}\nSymmetric: {symmetric}\nSignature: {signature}"
            id_item.setToolTip(tooltip)
            
            # Status column
            status_item = QTableWidgetItem()
            
            # Set text based on state
            if is_connected:
                if is_secure:
                    status_text = "Secure"
                else:
                    if has_shared_key:
                        status_text = "Connected, Key Issue"
                    else:
                        status_text = "Connected"
                
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
                        peer_settings.get(key, "") != my_settings[key]
                        for key in my_settings
                        if key in peer_settings
                    )
                    
                    if has_mismatches:
                        status_text += " ⚠️"
                        
            else:
                status_text = "Discovered"
            
            status_item.setText(status_text)
            
            # Add to table
            self.peer_table.setItem(row, 0, id_item)
            self.peer_table.setItem(row, 1, status_item)
            
            # Apply color based on state
            background_color = Qt.white  # Default white
            text_color = Qt.black  # Default black
            
            if is_connected:
                if is_secure:
                    background_color = QColor(230, 255, 230)  # Light green
                else:
                    background_color = QColor(240, 240, 255)  # Light blue
            
            # Apply colors to both columns
            id_item.setBackground(background_color)
            status_item.setBackground(background_color)
            id_item.setForeground(text_color)
            status_item.setForeground(text_color)
            
            # Separately handle unread messages
            if self.message_store and self.message_store.has_unread_messages(node_id):
                unread_count = self.message_store.get_unread_count(node_id)
                
                # Make text bold for unread messages
                font = id_item.font()
                font.setBold(True)
                id_item.setFont(font)
                status_item.setFont(font)
                
                # Update status text to include unread count
                status_item.setText(f"{status_text} ({unread_count} unread)")
            
            row += 1
        
        # Restore selection if possible
        if selected_peer_id:
            for r in range(self.peer_table.rowCount()):
                item = self.peer_table.item(r, 0)  # ID column
                if item and item.data(Qt.UserRole) == selected_peer_id:
                    self.peer_table.selectRow(r)
                    break
            
        # Restore scroll position
        self.peer_table.verticalScrollBar().setValue(scrollbar_pos)
        
        # Re-enable sorting
        self.peer_table.setSortingEnabled(True)
        
        logger.debug(f"Updated peer table with {len(discovered)} peers")
    
    def _on_peer_clicked(self, item):
        """Handle clicking on a peer in the list.
        
        Args:
            item: The clicked table item
        """
        # Get the row
        row = item.row()
        
        # Get the peer ID from the ID column
        id_item = self.peer_table.item(row, 0)
        peer_id = id_item.data(Qt.UserRole)
        host = id_item.data(Qt.UserRole + 1)
        port = id_item.data(Qt.UserRole + 2)
        
        # Store the current peer ID
        self.current_peer_id = peer_id
        
        # Mark all messages from this peer as read if we have a message store
        if self.message_store:
            self.message_store.mark_all_read(peer_id)
            
            # Update display to reflect read state
            self._refresh_peer_display(peer_id)
        
        # Emit the signal to select this peer
        self.peer_selected.emit(peer_id)
        
        # Automatically attempt to connect if not already connected
        if peer_id not in self.node.get_peers():
            logger.info(f"Auto-connecting to peer {peer_id} at {host}:{port}")
            self.connection_started.emit(peer_id, host, port)
        
        logger.debug(f"Selected peer {peer_id}")
    
    def _refresh_peer_display(self, peer_id):
        """Refresh the display for a specific peer.
        
        Args:
            peer_id: The ID of the peer to refresh
        """
        # Find the row with this peer ID
        for row in range(self.peer_table.rowCount()):
            id_item = self.peer_table.item(row, 0)
            if id_item and id_item.data(Qt.UserRole) == peer_id:
                # Get status item
                status_item = self.peer_table.item(row, 1)
                
                # Remove bold if this is the current peer (messages have been read)
                font = id_item.font()
                font.setBold(False)
                id_item.setFont(font)
                status_item.setFont(font)
                
                # Update status text to remove unread count
                status_text = status_item.text()
                if " (" in status_text:
                    status_text = status_text.split(" (")[0]
                    status_item.setText(status_text)
                break
    
    def _on_connect_clicked(self):
        """Handle clicking the connect button."""
        # Get the selected peer
        selected_rows = self.peer_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "No Peer Selected", "Please select a peer to connect to.")
            return
        
        # Get the peer data from the first column
        row = selected_rows[0].row()
        id_item = self.peer_table.item(row, 0)
        
        peer_id = id_item.data(Qt.UserRole)
        host = id_item.data(Qt.UserRole + 1)
        port = id_item.data(Qt.UserRole + 2)
        
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
        """Handle clicking the add peer button by delegating to MainWindow."""
        # Simply emit the signal - MainWindow will handle the rest
        self.add_peer_requested.emit()
        logger.debug("Add peer button clicked, emitting add_peer_requested signal")
        
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