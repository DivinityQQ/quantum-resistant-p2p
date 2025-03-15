"""
Widget for messaging functionality.
"""

import logging
import asyncio
import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, 
    QPushButton, QLabel, QFileDialog, QProgressBar, QSplitter,
    QGroupBox, QFormLayout, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QTimer
from PyQt5.QtGui import QFont, QColor

from ..app import SecureMessaging, Message

logger = logging.getLogger(__name__)


class MessagingWidget(QWidget):
    """Widget for securely messaging with peers."""
    
    # Signal for running async tasks
    async_task = pyqtSignal(object)
    # Signal for opening settings dialog
    open_settings_dialog = pyqtSignal()
    
    def __init__(self, secure_messaging: SecureMessaging, parent=None):
        """Initialize the messaging widget.

        Args:
            secure_messaging: The secure messaging service
            parent: The parent widget
        """
        super().__init__(parent)

        self.secure_messaging = secure_messaging
        self.current_peer = None
        self.is_connecting = False

        self._init_ui()

        # Connect async signal
        self.async_task.connect(self._run_async_task)

        # Register for crypto settings changes
        self.secure_messaging.register_settings_change_listener(self._on_crypto_settings_changed)

        # Add connection status checker timer
        self.connection_checker = QTimer(self)
        self.connection_checker.timeout.connect(self._check_connection_status)
        self.connection_checker.start(2000)  # Check every 2 seconds

        # Connect to the destroyed signal to clean up resources
        self.destroyed.connect(self._cleanup_resources)
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()

        # Header with peer info
        header_layout = QHBoxLayout()

        self.peer_label = QLabel("No peer selected")
        self.peer_label.setStyleSheet("font-weight: bold;")
        header_layout.addWidget(self.peer_label, 1)  # Stretch factor 1

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setToolTip("Refresh peer cryptography settings")
        self.refresh_button.setEnabled(False)
        self.refresh_button.clicked.connect(self._on_refresh_clicked)
        header_layout.addWidget(self.refresh_button)

        self.settings_button = QPushButton("Crypto Settings")
        self.settings_button.setEnabled(False)
        self.settings_button.clicked.connect(self._on_settings_clicked)
        header_layout.addWidget(self.settings_button)

        layout.addLayout(header_layout)

        # Crypto settings info panel (initially hidden)
        self.crypto_panel = QGroupBox("Cryptography Settings")
        self.crypto_panel.setVisible(False)

        # Use horizontal layout for local and peer settings
        crypto_main_layout = QHBoxLayout()

        # Local settings group
        local_group = QGroupBox("Local")
        local_layout = QFormLayout()
        local_layout.setVerticalSpacing(6)

        # Our settings
        self.our_key_exchange_label = QLabel("-")
        self.our_symmetric_label = QLabel("-")
        self.our_signature_label = QLabel("-")

        local_layout.addRow("Key Exchange:", self.our_key_exchange_label)
        local_layout.addRow("Symmetric:", self.our_symmetric_label)
        local_layout.addRow("Signature:", self.our_signature_label)

        local_group.setLayout(local_layout)

        # Peer settings group
        peer_group = QGroupBox("Peer")
        peer_layout = QFormLayout()
        peer_layout.setVerticalSpacing(6)

        # Peer settings
        self.peer_key_exchange_label = QLabel("-")
        self.peer_symmetric_label = QLabel("-")
        self.peer_signature_label = QLabel("-")

        peer_layout.addRow("Key Exchange:", self.peer_key_exchange_label)
        peer_layout.addRow("Symmetric:", self.peer_symmetric_label)
        peer_layout.addRow("Signature:", self.peer_signature_label)

        peer_group.setLayout(peer_layout)

        # Add both groups to the horizontal layout
        crypto_main_layout.addWidget(local_group)
        crypto_main_layout.addWidget(peer_group)

        # Add additional controls below the horizontal layout
        crypto_controls_layout = QVBoxLayout()

        # Add connection status indicator
        self.connection_status_label = QLabel("Not connected")
        self.connection_status_label.setStyleSheet("font-weight: bold; color: red;")
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        status_layout.addWidget(self.connection_status_label)
        crypto_controls_layout.addLayout(status_layout)

        # Add control buttons
        button_layout = QHBoxLayout()

        # Add adopt settings button
        self.adopt_settings_button = QPushButton("Use Peer Settings")
        self.adopt_settings_button.setEnabled(False)
        self.adopt_settings_button.clicked.connect(self._on_adopt_settings_clicked)
        button_layout.addWidget(self.adopt_settings_button)

        # Add key exchange button
        self.key_exchange_button = QPushButton("Establish Shared Key")
        self.key_exchange_button.setEnabled(False)
        self.key_exchange_button.clicked.connect(self._on_key_exchange_clicked)
        button_layout.addWidget(self.key_exchange_button)

        crypto_controls_layout.addLayout(button_layout)

        # Add all layouts to the crypto panel
        crypto_layout = QVBoxLayout()
        crypto_layout.addLayout(crypto_main_layout)
        crypto_layout.addLayout(crypto_controls_layout)

        self.crypto_panel.setLayout(crypto_layout)
        layout.addWidget(self.crypto_panel)

        # Status label
        self.status_label = QLabel("Select a peer to chat with")
        self.status_label.setStyleSheet("color: gray;")
        layout.addWidget(self.status_label)

        # Chat area
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setFont(QFont("Courier New", 10))
        layout.addWidget(self.chat_area)

        # Message input area
        input_layout = QHBoxLayout()

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setEnabled(False)  # Disabled until peer connected
        self.message_input.returnPressed.connect(self._on_send_clicked)
        input_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.setEnabled(False)  # Disabled until peer connected
        self.send_button.clicked.connect(self._on_send_clicked)
        input_layout.addWidget(self.send_button)

        self.file_button = QPushButton("Send File")
        self.file_button.setEnabled(False)  # Disabled until peer connected
        self.file_button.clicked.connect(self._on_send_file_clicked)
        input_layout.addWidget(self.file_button)

        layout.addLayout(input_layout)

        # Progress bar for file transfers
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

        logger.debug("Messaging widget initialized")
    
    def _on_crypto_settings_changed(self):
        """Handle crypto settings changes."""
        # Only update if we have a current peer
        if self.current_peer:
            self._update_crypto_display()

    def _on_refresh_clicked(self):
        """Handle clicking the refresh button."""
        if not self.current_peer:
            return

        self.status_label.setText("Refreshing peer settings...")
        self._add_system_message("Refreshing peer cryptography settings...")

        # Request crypto settings from the peer
        self.async_task.emit(
            self.secure_messaging.request_crypto_settings_from_peer(self.current_peer)
        )

        # Update the crypto settings display
        self._update_crypto_display()

    def _on_key_exchange_clicked(self):
        """Handle clicking the key exchange button."""
        if not self.current_peer:
            return

        self.status_label.setText("Initiating key exchange...")
        self._add_system_message("Manually initiating key exchange with peer...")

        # Initiate key exchange with the peer
        self.async_task.emit(
            self._initiate_key_exchange()
        )

    def _update_crypto_display(self):
        """Update the cryptography settings display."""
        # Always show the crypto panel when a peer is selected
        self.crypto_panel.setVisible(self.current_peer is not None)

        # Update our settings
        self.our_key_exchange_label.setText(self.secure_messaging.key_exchange.display_name)
        self.our_symmetric_label.setText(self.secure_messaging.symmetric.name)
        self.our_signature_label.setText(self.secure_messaging.signature.display_name)

        # Update connection status and control buttons
        if self.current_peer:
            # Check if the peer is actually connected (in the active peers list)
            connected = self.current_peer in self.secure_messaging.node.get_peers()
            has_shared_key = self.current_peer in self.secure_messaging.shared_keys

            # Enable message controls if we have shared key and are connected
            self.message_input.setEnabled(connected and has_shared_key)
            self.send_button.setEnabled(connected and has_shared_key)
            self.file_button.setEnabled(connected and has_shared_key)

            # Get peer settings to check compatibility
            peer_settings = self.secure_messaging.get_peer_crypto_settings(self.current_peer)
            settings_compatible = False

            if peer_settings:
                # Check if key exchange algorithm matches
                peer_key_exchange = peer_settings.get("key_exchange", "").split(" [Mock]")[0]
                local_key_exchange = self.secure_messaging.key_exchange.display_name
                settings_compatible = (peer_key_exchange == local_key_exchange)

            # Only enable key exchange button if:
            # 1. We're connected
            # 2. We don't already have a shared key
            # 3. The settings are compatible
            self.key_exchange_button.setEnabled(connected and not has_shared_key and settings_compatible)

            # If settings are incompatible, show a tooltip explaining why
            if not settings_compatible and connected and not has_shared_key:
                self.key_exchange_button.setToolTip(
                    "Cannot establish shared key: Cryptographic settings mismatch.\n"
                    "You must use matching key exchange algorithms."
                )
            else:
                self.key_exchange_button.setToolTip("")

            # Update connection status label
            if not connected:
                self.connection_status_label.setText("Not connected")
                self.connection_status_label.setStyleSheet("font-weight: bold; color: red;")

                # Make sure to disable all controls
                self.message_input.setEnabled(False)
                self.send_button.setEnabled(False)
                self.file_button.setEnabled(False)
                self.key_exchange_button.setEnabled(False)
            elif connected and has_shared_key:
                self.connection_status_label.setText("Connected with shared key")
                self.connection_status_label.setStyleSheet("font-weight: bold; color: green;")
            else:
                self.connection_status_label.setText("Connected, no shared key")
                self.connection_status_label.setStyleSheet("font-weight: bold; color: orange;")

            # Update peer settings if available
            if peer_settings:
                # Update peer settings
                key_exchange = peer_settings.get("key_exchange", "-")
                symmetric = peer_settings.get("symmetric", "-")
                signature = peer_settings.get("signature", "-")

                self.peer_key_exchange_label.setText(key_exchange)
                self.peer_symmetric_label.setText(symmetric)
                self.peer_signature_label.setText(signature)

                # Highlight differences
                self.peer_key_exchange_label.setStyleSheet(
                    "color: red;" if key_exchange.split(" [Mock]")[0] != self.secure_messaging.key_exchange.display_name else ""
                )
                self.peer_symmetric_label.setStyleSheet(
                    "color: red;" if symmetric != self.secure_messaging.symmetric.name else ""
                )
                self.peer_signature_label.setStyleSheet(
                    "color: red;" if signature.split(" [Mock]")[0] != self.secure_messaging.signature.display_name else ""
                )

                # Enable adopt settings button if there are differences and we're connected
                has_differences = (
                    key_exchange.split(" [Mock]")[0] != self.secure_messaging.key_exchange.display_name or
                    symmetric != self.secure_messaging.symmetric.name or
                    signature.split(" [Mock]")[0] != self.secure_messaging.signature.display_name
                )
                self.adopt_settings_button.setEnabled(connected and has_differences)

                # If there are differences, add a hint in the chat if not already notified
                if has_differences and not hasattr(self, '_mismatch_notified'):
                    self._add_system_message("Cryptographic settings differ from peer. Consider using 'Use Peer Settings' button to adopt them.", True)
                    setattr(self, '_mismatch_notified', True)
            else:
                # No peer settings available yet
                self.peer_key_exchange_label.setText("Requesting...")
                self.peer_symmetric_label.setText("Requesting...")
                self.peer_signature_label.setText("Requesting...")
                self.adopt_settings_button.setEnabled(False)

                # Request settings from peer
                if connected:
                    self.async_task.emit(
                        self.secure_messaging.request_crypto_settings_from_peer(self.current_peer)
                    )
        else:
            # Reset peer settings when no peer is selected
            self.peer_key_exchange_label.setText("-")
            self.peer_symmetric_label.setText("-")
            self.peer_signature_label.setText("-")
            self.connection_status_label.setText("Not connected")
            self.connection_status_label.setStyleSheet("font-weight: bold; color: red;")
            self.adopt_settings_button.setEnabled(False)
            self.key_exchange_button.setEnabled(False)
    
    def set_current_peer(self, peer_id: str):
        """Set the current peer for messaging.

        Args:
            peer_id: The ID of the peer
        """
        # Clear previous notification flag
        if hasattr(self, '_mismatch_notified'):
            delattr(self, '_mismatch_notified')

        self.current_peer = peer_id
        self.peer_label.setText(f"Chatting with: {peer_id[:8]}...")

        # Enable settings and refresh buttons when peer is selected
        self.settings_button.setEnabled(True)
        self.refresh_button.setEnabled(True)

        # Clear the chat area
        self.chat_area.clear()

        # Add a system message
        self._add_system_message(f"Started chat with {peer_id[:8]}...")

        # Check connection status
        connected_peers = self.secure_messaging.node.get_peers()
        is_connected = peer_id in connected_peers

        # Initialize previous connection state
        self.previous_connection_state = is_connected

        if is_connected:
            self._add_system_message("Connected to peer")
            has_shared_key = peer_id in self.secure_messaging.shared_keys

            if has_shared_key:
                self._add_system_message("Shared key established")
                self._enable_messaging()
            else:
                self._add_system_message("No shared key established.")
                self._disable_messaging()

            # Make crypto panel visible immediately with "requesting" status
            self.crypto_panel.setVisible(True)

            # Request crypto settings from the peer
            self.async_task.emit(
                self.secure_messaging.request_crypto_settings_from_peer(peer_id)
            )
        else:
            self._add_system_message("Not connected to peer. Use the Connect button in the peer list.")
            self._disable_messaging()

        # Update the crypto settings display
        self._update_crypto_display()

        logger.info(f"Set current peer to {peer_id}")
    
    def initiate_connection(self, peer_id: str, host: str, port: int):
        """Initiate connection to a peer.
        
        Args:
            peer_id: The ID of the peer
            host: The host address of the peer
            port: The port number of the peer
        """
        # Check if this is the currently selected peer
        if peer_id != self.current_peer:
            return
            
        # Check if already connecting
        if self.is_connecting:
            return
            
        self.is_connecting = True
        self.status_label.setText(f"Connecting to {host}:{port}...")
        self._add_system_message(f"Connecting to {host}:{port}...")
        
        # Start connection task
        self.async_task.emit(self._connect_to_peer(host, port))

    def _check_connection_status(self):
        """Periodically check if the current peer is still connected."""
        if not self.current_peer:
            return

        # Check if peer is still in the connected peers list
        connected_peers = self.secure_messaging.node.get_peers()
        was_connected = self.current_peer in connected_peers

        # If connection status changed, update the UI
        if not was_connected and hasattr(self, 'previous_connection_state') and self.previous_connection_state:
            # Connection lost
            self._add_system_message(f"Connection lost with peer {self.current_peer[:8]}...")
            self.connection_status_label.setText("Not connected")
            self.connection_status_label.setStyleSheet("font-weight: bold; color: red;")

            # Disable messaging controls
            self._disable_messaging()

            # Update UI
            self._update_crypto_display()

        # Store current connection state for next check
        self.previous_connection_state = was_connected   

    def _cleanup_resources(self):
        """Clean up resources when widget is destroyed."""
        logger.debug("Cleaning up MessagingWidget resources")
        if hasattr(self, 'connection_checker'):
            self.connection_checker.stop()

    async def _connect_to_peer(self, host: str, port: int):
        """Connect to a peer asynchronously.
        
        Args:
            host: The host address of the peer
            port: The port number of the peer
        """
        try:
            # Attempt to connect to the peer
            success = await self.secure_messaging.node.connect_to_peer(host, port)
            
            if success:
                self.status_label.setText("Connected")
                self._add_system_message(f"Successfully connected to {host}:{port}")
                self._enable_messaging()
                
                # Make crypto panel visible immediately
                self.crypto_panel.setVisible(True)
                
                # Request crypto settings from the peer
                await self.secure_messaging.request_crypto_settings_from_peer(self.current_peer)
                
                # Update the crypto settings display
                self._update_crypto_display()
            else:
                self.status_label.setText("Connection failed")
                self._add_system_message(f"Failed to connect to {host}:{port}")
                self._disable_messaging()
                
        except Exception as e:
            self.status_label.setText("Connection error")
            self._add_system_message(f"Error connecting to peer: {str(e)}")
            self._disable_messaging()
            logger.error(f"Error connecting to peer: {e}")
        
        finally:
            self.is_connecting = False

    async def _initiate_key_exchange(self):
        """Initiate a key exchange with the current peer."""
        if not self.current_peer:
            return

        try:
            # Check if connected
            if self.current_peer not in self.secure_messaging.node.get_peers():
                self._add_system_message("Not connected to peer. Connect first.", True)
                return

            # Initiate key exchange
            success = await self.secure_messaging.initiate_key_exchange(self.current_peer)

            if success:
                self._add_system_message("Key exchange initiated successfully")
                # Update the UI after a short delay to reflect the new state
                await asyncio.sleep(1)
                self._update_crypto_display()
            else:
                self._add_system_message("Failed to initiate key exchange. Check for algorithm compatibility.", True)
        except Exception as e:
            self._add_system_message(f"Error during key exchange: {str(e)}", True)
            logger.error(f"Error during key exchange: {e}")

    def _enable_messaging(self):
        """Enable the messaging UI."""
        self.message_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.file_button.setEnabled(True)
        self.message_input.setFocus()
    
    def _disable_messaging(self):
        """Disable the messaging UI."""
        self.message_input.setEnabled(False)
        self.send_button.setEnabled(False)
        self.file_button.setEnabled(False)
    
    def _add_message(self, message: Message, is_outgoing: bool):
        """Add a message to the chat area.
        
        Args:
            message: The message to add
            is_outgoing: Whether the message is outgoing (sent by us)
        """
        # Format the timestamp
        timestamp = datetime.fromtimestamp(message.timestamp).strftime("%H:%M:%S")
        
        # Determine the prefix
        prefix = "You" if is_outgoing else f"{message.sender_id[:8]}..."
        
        # Add the message to the chat area
        if message.is_file:
            filename = message.filename or "Unknown file"
            file_size = len(message.content)
            self.chat_area.append(
                f"[{timestamp}] {prefix} sent a file: {filename} ({file_size} bytes)"
            )
        else:
            try:
                content = message.content.decode("utf-8")
                self.chat_area.append(f"[{timestamp}] {prefix}: {content}")
            except UnicodeDecodeError:
                # Binary data, just show the size
                self.chat_area.append(
                    f"[{timestamp}] {prefix} sent binary data ({len(message.content)} bytes)"
                )
        
        # Scroll to the bottom
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )
    
    def _add_system_message(self, message: str, is_warning: bool = False):
        """Add a system message to the chat area.
        
        Args:
            message: The message to add
            is_warning: Whether this is a warning message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Set text color based on message type
        if is_warning:
            self.chat_area.append(f'<font color="red">[{timestamp}] * {message} *</font>')
        else:
            self.chat_area.append(f"[{timestamp}] * {message} *")
        
        # Scroll to the bottom
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )
    
    def _on_settings_clicked(self):
        """Handle clicking the settings button."""
        self.open_settings_dialog.emit()
    
    def _on_adopt_settings_clicked(self):
        """Handle clicking the adopt settings button."""
        if not self.current_peer:
            return
            
        # Ask for confirmation
        reply = QMessageBox.question(
            self,
            "Adopt Peer Settings",
            f"Do you want to adopt the cryptography settings of peer {self.current_peer[:8]}...?\n\n"
            "This will restart key exchanges with all connected peers.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Adopt the peer's settings
            success = self.secure_messaging.adopt_peer_settings(self.current_peer)
            if success:
                self._add_system_message(f"Adopted cryptography settings from peer {self.current_peer[:8]}...")
                # Update the display
                self._update_crypto_display()
            else:
                self._add_system_message(f"Failed to adopt settings from peer {self.current_peer[:8]}...", True)
    
    def _on_send_clicked(self):
        """Handle clicking the send button."""
        if not self.current_peer:
            logger.warning("No peer selected, cannot send message")
            return
        
        # Check if connected
        if self.current_peer not in self.secure_messaging.node.get_peers():
            self._add_system_message("Not connected to peer. Connect first.", True)
            return
        
        # Get the message
        text = self.message_input.text().strip()
        if not text:
            return
        
        # Clear the input field
        self.message_input.clear()
        
        # Create a message
        content = text.encode("utf-8")
        message = Message(
            content=content,
            sender_id=self.secure_messaging.node.node_id,
            is_file=False
        )
        
        # Add the message to the chat area
        self._add_message(message, is_outgoing=True)
        
        # Send the message asynchronously
        self.async_task.emit(
            self.secure_messaging.send_message(self.current_peer, content)
        )
    
    def _on_send_file_clicked(self):
        """Handle clicking the send file button."""
        if not self.current_peer:
            logger.warning("No peer selected, cannot send file")
            return
        
        # Check if connected
        if self.current_peer not in self.secure_messaging.node.get_peers():
            self._add_system_message("Not connected to peer. Connect first.", True)
            return
        
        # Open file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Send"
        )
        
        if not file_path:
            return
        
        # Show the progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Get file info
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        # Add a system message
        self._add_system_message(f"Sending file: {file_name} ({file_size} bytes)")
        
        # Start the file transfer
        self.async_task.emit(self._send_file(file_path))
    
    async def _send_file(self, file_path: str):
        """Send a file to the current peer.
        
        Args:
            file_path: Path to the file to send
        """
        try:
            # Get file info
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Read the file
            with open(file_path, "rb") as f:
                data = f.read()
            
            # Update progress bar
            self.progress_bar.setValue(50)
            
            # Send the file
            success = await self.secure_messaging.send_file(self.current_peer, file_path)
            
            # Update progress bar and hide it
            self.progress_bar.setValue(100)
            await asyncio.sleep(0.5)  # Short delay before hiding
            self.progress_bar.setVisible(False)
            
            if success:
                # Create a message object for the UI
                message = Message(
                    content=data,
                    sender_id=self.secure_messaging.node.node_id,
                    is_file=True,
                    filename=file_name
                )
                
                # Add the message to the chat area
                self._add_message(message, is_outgoing=True)
                
                logger.info(f"File sent successfully: {file_name} ({file_size} bytes)")
            else:
                self._add_system_message(f"Failed to send file: {file_name}", True)
                logger.error(f"Failed to send file: {file_name}")
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self._add_system_message(f"Error sending file: {str(e)}", True)
            logger.error(f"Error sending file {file_path}: {e}")
    
    @pyqtSlot(object)
    def _run_async_task(self, coro):
        """Run an asynchronous task in the event loop.
        
        Args:
            coro: The coroutine to run
        """
        asyncio.create_task(coro)
    
    def handle_message(self, message: Message):
        """Handle a received message.
        
        Args:
            message: The received message
        """
        logger.debug(f"MessagingWidget displaying message {message.message_id} from {message.sender_id}")
        
        # Special handling for system messages
        if message.is_system:
            # Display as a system message
            try:
                content = message.content.decode("utf-8")
                is_warning = "different" in content.lower() or "mismatch" in content.lower()
                self._add_system_message(content, is_warning)
                
                # If this is a crypto settings message, add more details
                if ("crypto" in content.lower() or "settings" in content.lower() or 
                    "algorithm" in content.lower() or "key exchange" in content.lower()):
                    if hasattr(message, 'key_exchange_algo') and message.key_exchange_algo:
                        self._add_system_message(f"Peer key exchange: {message.key_exchange_algo}")
                    if hasattr(message, 'symmetric_algo') and message.symmetric_algo:
                        self._add_system_message(f"Peer symmetric encryption: {message.symmetric_algo}")
                    if hasattr(message, 'signature_algo') and message.signature_algo:
                        self._add_system_message(f"Peer signature: {message.signature_algo}")
                    
                    # Update the crypto settings display
                    self._update_crypto_display()
                
            except Exception as e:
                logger.error(f"Error displaying system message: {e}")
            return
        
        # Regular message handling
        self._add_message(message, is_outgoing=False)
        
        # Update peer crypto settings from message metadata if available
        if hasattr(message, 'key_exchange_algo') or hasattr(message, 'symmetric_algo') or hasattr(message, 'signature_algo'):
            if self.current_peer not in self.secure_messaging.peer_crypto_settings:
                self.secure_messaging.peer_crypto_settings[self.current_peer] = {}
                
            if hasattr(message, 'key_exchange_algo') and message.key_exchange_algo:
                self.secure_messaging.peer_crypto_settings[self.current_peer]["key_exchange"] = message.key_exchange_algo
                
            if hasattr(message, 'symmetric_algo') and message.symmetric_algo:
                self.secure_messaging.peer_crypto_settings[self.current_peer]["symmetric"] = message.symmetric_algo
                
            if hasattr(message, 'signature_algo') and message.signature_algo:
                self.secure_messaging.peer_crypto_settings[self.current_peer]["signature"] = message.signature_algo
                
            # Update the display
            self._update_crypto_display()
