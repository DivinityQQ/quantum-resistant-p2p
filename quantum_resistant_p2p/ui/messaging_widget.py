"""
Widget for messaging functionality.
"""

import logging
import asyncio
import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, 
    QPushButton, QLabel, QFileDialog, QProgressBar, QSplitter
)
from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QFont

from ..app import SecureMessaging, Message

logger = logging.getLogger(__name__)


class MessagingWidget(QWidget):
    """Widget for securely messaging with peers."""
    
    # Signal for running async tasks
    async_task = pyqtSignal(object)
    
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
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Header with peer info
        self.peer_label = QLabel("No peer selected")
        self.peer_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.peer_label)
        
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
    
    def set_current_peer(self, peer_id: str):
        """Set the current peer for messaging.
        
        Args:
            peer_id: The ID of the peer
        """
        self.current_peer = peer_id
        self.peer_label.setText(f"Chatting with: {peer_id[:8]}...")
        
        # Clear the chat area
        self.chat_area.clear()
        
        # Add a system message
        self._add_system_message(f"Started chat with {peer_id[:8]}...")
        
        # Check connection status
        connected_peers = self.secure_messaging.node.get_peers()
        if peer_id in connected_peers:
            self._add_system_message("Connected to peer")
            self._enable_messaging()
        else:
            self._add_system_message("Not connected to peer. Use the Connect button in the peer list.")
            self._disable_messaging()
        
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
    
    def _add_system_message(self, message: str):
        """Add a system message to the chat area.
        
        Args:
            message: The message to add
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_area.append(f"[{timestamp}] * {message} *")
        
        # Scroll to the bottom
        self.chat_area.verticalScrollBar().setValue(
            self.chat_area.verticalScrollBar().maximum()
        )
    
    def _on_send_clicked(self):
        """Handle clicking the send button."""
        if not self.current_peer:
            logger.warning("No peer selected, cannot send message")
            return
        
        # Check if connected
        if self.current_peer not in self.secure_messaging.node.get_peers():
            self._add_system_message("Not connected to peer. Connect first.")
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
            self._add_system_message("Not connected to peer. Connect first.")
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
                self._add_system_message(f"Failed to send file: {file_name}")
                logger.error(f"Failed to send file: {file_name}")
            
        except Exception as e:
            self.progress_bar.setVisible(False)
            self._add_system_message(f"Error sending file: {str(e)}")
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
        # Add the message to the chat area
        self._add_message(message, is_outgoing=False)
