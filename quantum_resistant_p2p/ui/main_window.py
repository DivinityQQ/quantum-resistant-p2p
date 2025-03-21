"""
Main window for the post-quantum P2P application.
"""

import logging
import asyncio
import sys
import os
import subprocess
from pathlib import Path
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, 
    QTabWidget, QLabel, QStatusBar, QAction, QFileDialog, QMessageBox,
    QInputDialog
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon

from .peer_list import PeerListWidget
from .messaging_widget import MessagingWidget
from .settings_dialog import SettingsDialog
from .security_metrics_dialog import SecurityMetricsDialog
from .log_viewer_dialog import LogViewerDialog
from .oqs_status_widget import OQSStatusWidget
from .login_dialog import LoginDialog
from ..app import SecureMessaging, SecureLogger, MessageStore
from ..crypto import KeyStorage
from ..networking import P2PNode, NodeDiscovery

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main window for the application."""
    
    # Signal for running async tasks
    async_task = pyqtSignal(object)
    
    def __init__(self):
        """Initialize the main window."""
        super().__init__()

        # Initialize components
        self.key_storage = KeyStorage()
        # Secure logger will be initialized after login when we have the master key
        self.secure_logger = None

        # Network components will be initialized after login
        self.node = None
        self.node_discovery = None
        self.secure_messaging = None

        # Track if message handler has been registered to prevent duplicates
        self._message_handler_registered = False

        # UI initialization
        self.setWindowTitle("Quantum Resistant P2P")
        self.setMinimumSize(800, 600)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout(self.central_widget)
        layout.addWidget(QLabel("Logging in..."))

        # Connect async signal
        self.async_task.connect(self._run_async_task)

        # Show login dialog first
        QTimer.singleShot(100, self._show_login_dialog)
    
    def _show_login_dialog(self):
        """Show the login dialog to unlock key storage."""
        dialog = LoginDialog(self.key_storage, self)
        dialog.login_successful.connect(self._init_after_login)
        
        # If dialog is rejected, exit the application
        if dialog.exec_() == LoginDialog.Rejected:
            sys.exit(0)
    
    def _init_after_login(self):
        """Initialize components after successful login."""
        # Get the master key from key storage
        master_key = self.key_storage.get_master_key()
        
        # Initialize secure logger with the master key
        self.secure_logger = SecureLogger(encryption_key=master_key)
        
        # Then initialize the rest of the system
        self._init_network()
        
        # Create the message store and set the current node ID
        self.message_store = MessageStore()
        self.message_store.set_current_node_id(self.node.node_id)
        
        self._init_ui()
    
        # Register message handler BEFORE starting the network
        if self.secure_messaging and not self._message_handler_registered:
            self.secure_messaging.register_global_message_handler(self._on_secure_message_received)
            # Register for crypto settings changes
            self.secure_messaging.register_settings_change_listener(self._update_crypto_status)
            self._message_handler_registered = True
            logger.debug("Registered global message handler")
    
        self._start_network()
    
    def _init_network(self):
        """Initialize network components."""
        # Create the P2P node
        self.node = P2PNode(key_storage=self.key_storage)
        
        # Create node discovery
        self.node_discovery = NodeDiscovery(self.node.node_id, port=self.node.port)
        
        # Set the reference to node_discovery in the node
        self.node.node_discovery = self.node_discovery
        
        # Create secure messaging
        self.secure_messaging = SecureMessaging(
            node=self.node,
            key_storage=self.key_storage,
            logger=self.secure_logger
        )
        
        logger.info("Network components initialized")
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Create central widget
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)

        # Create splitter for main layout
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)

        # Left panel - peer list
        self.peer_list = PeerListWidget(self.node, self.node_discovery, self.secure_messaging, message_store=self.message_store)
        splitter.addWidget(self.peer_list)

        # Right panel - messaging
        self.messaging = MessagingWidget(self.secure_messaging, message_store=self.message_store)
        splitter.addWidget(self.messaging)

        # Set initial splitter sizes
        splitter.setSizes([200, 600])

        # Set up the status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Status indicators
        self.connection_status = QLabel("Not connected")
        self.encryption_status = QLabel("No encryption")
        self.status_bar.addPermanentWidget(self.connection_status)
        self.status_bar.addPermanentWidget(self.encryption_status)
        self.oqs_status = OQSStatusWidget()
        self.status_bar.addPermanentWidget(self.oqs_status)

        # Initial status message
        self.status_bar.showMessage("Welcome to Quantum P2P")

        # Set up menu bar
        self._setup_menu()

        # Set central widget
        self.setCentralWidget(central_widget)

        # Connect signals
        self.peer_list.peer_selected.connect(self.messaging.set_current_peer)
        self.peer_list.connection_started.connect(self.messaging.initiate_connection)
        self.peer_list.async_task.connect(self._run_async_task)
        self.messaging.open_settings_dialog.connect(self._show_crypto_settings)
        self.peer_list.add_peer_requested.connect(self._show_connect_dialog)

        # Register for crypto settings changes
        self.secure_messaging.register_settings_change_listener(self._update_crypto_status)

        logger.info("User interface initialized")
    
    def _setup_menu(self):
        """Set up the menu bar."""
        menu_bar = self.menuBar()
        
        # File menu
        file_menu = menu_bar.addMenu("File")
        
        # Connect to peer action
        connect_action = QAction("Connect to Peer...", self)
        connect_action.triggered.connect(self._show_connect_dialog)
        file_menu.addAction(connect_action)
        
        # Send file action
        send_file_action = QAction("Send File...", self)
        send_file_action.triggered.connect(self._show_send_file_dialog)
        file_menu.addAction(send_file_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Settings menu
        settings_menu = menu_bar.addMenu("Settings")
        
        # Crypto settings action
        crypto_settings_action = QAction("Cryptography Settings...", self)
        crypto_settings_action.triggered.connect(self._show_crypto_settings)
        settings_menu.addAction(crypto_settings_action)
        
        # Security metrics action
        metrics_action = QAction("Security Metrics...", self)
        metrics_action.triggered.connect(self._show_security_metrics)
        settings_menu.addAction(metrics_action)
        
        # View logs action
        logs_action = QAction("View Logs...", self)
        logs_action.triggered.connect(self._show_logs)
        settings_menu.addAction(logs_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("Help")
        
        # About action
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about_dialog)
        help_menu.addAction(about_action)
    
    def _start_network(self):
        """Start the network components."""
        # Start the network components asynchronously
        asyncio.create_task(self._async_start_network())

    def _update_crypto_status(self):
        """Update the cryptography status display in the UI."""
        if hasattr(self, 'encryption_status') and self.encryption_status and hasattr(self, 'secure_messaging') and self.secure_messaging:
            self.encryption_status.setText(
                f"Crypto: {self.secure_messaging.key_exchange.display_name.split()[0]}, "
                f"{self.secure_messaging.symmetric.name}, "
                f"{self.secure_messaging.signature.display_name.split()[0]}"
            )
            self.status_bar.showMessage("Cryptography settings updated", 3000)
            logger.debug("Updated cryptography status in UI")

    async def _async_start_network(self):
        """Asynchronously start the network components."""
        try:
            # Start node discovery
            await self.node_discovery.start()
            
            # Start P2P node
            asyncio.create_task(self.node.start())
            
            # Update UI
            self.connection_status.setText(f"Node ID: {self.node.node_id[:8]}...")
            self.encryption_status.setText(
                f"Crypto: {self.secure_messaging.key_exchange.display_name.split()[0]}, "
                f"{self.secure_messaging.symmetric.name}, "
                f"{self.secure_messaging.signature.display_name.split()[0]}"
            )
            
            self.status_bar.showMessage("Network started", 3000)
            
            # Start periodic update of peer list
            asyncio.create_task(self._periodic_peer_update())
            
            logger.info("Network components started")
            
        except Exception as e:
            logger.error(f"Failed to start network: {e}")
            self.status_bar.showMessage(f"Error starting network: {e}", 5000)
    
    async def _periodic_peer_update(self):
        """Periodically update the peer list."""
        while True:
            try:
                # Get discovered nodes
                discovered = self.node_discovery.get_discovered_nodes()
                # Get connected peers
                connected = self.node.get_peers()

                # Update the UI
                self.peer_list.update_peers(discovered, connected)

                # Wait before next update
                await asyncio.sleep(10)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error updating peer list: {e}")
                await asyncio.sleep(10)
    
    def _on_secure_message_received(self, message):
        """Primary handler for all secure messages.

        This is the ONLY place that should process incoming secure messages
        for display in the UI.

        Args:
            message: The decrypted message object
        """
        logger.debug(f"MainWindow received message {message.message_id} from {message.sender_id}")

        # Special handling for system messages
        if message.is_system:
            # Show system message in the status bar
            try:
                content = message.content.decode("utf-8")
                self.status_bar.showMessage(content, 5000)
                logger.info(f"System message: {content}")
            except Exception as e:
                logger.error(f"Error displaying system message: {e}")
            return

        # Add the message to the message store, mark as read only if it's from the current peer
        # and the messaging widget is visible
        mark_as_read = (hasattr(self, 'messaging') and 
                       self.messaging.current_peer == message.sender_id and
                       self.messaging.isVisible())

        self.message_store.add_message(message, mark_as_read=mark_as_read)

        # Check if message is from the currently selected peer
        if hasattr(self, 'messaging') and self.messaging.current_peer == message.sender_id:
            # Pass to messaging widget for display
            self.messaging.handle_message(message)
        else:
            # Show notification for messages from non-selected peers
            sender_id = message.sender_id[:8] + "..." if len(message.sender_id) > 8 else message.sender_id
            if message.is_file:
                filename = message.filename or "unknown file"
                self.status_bar.showMessage(f"Received file '{filename}' from {sender_id}", 5000)
            else:
                self.status_bar.showMessage(f"New message from {sender_id}", 5000)

        # Update the peer list to show unread indicators
        if hasattr(self, 'peer_list'):
            self.peer_list.update_peers(
                self.node_discovery.get_discovered_nodes(), 
                self.node.get_peers()
            )
    
    async def _connect_to_peer(self, host: str, port: int):
        """Connect to a peer.
        
        Args:
            host: The peer's host address
            port: The peer's port
        """
        try:
            # Attempt to connect
            success = await self.node.connect_to_peer(host, port)
            
            if success:
                self.status_bar.showMessage(f"Connected to {host}:{port}", 3000)
                logger.info(f"Connected to peer at {host}:{port}")
                return True
            else:
                self.status_bar.showMessage(f"Failed to connect to {host}:{port}", 3000)
                logger.error(f"Failed to connect to peer at {host}:{port}")
                return False
                
        except Exception as e:
            self.status_bar.showMessage(f"Error connecting to peer: {e}", 3000)
            logger.error(f"Error connecting to peer at {host}:{port}: {e}")
            return False
    
    @pyqtSlot(object)
    def _run_async_task(self, coro):
        """Run an asynchronous task in the event loop.
        
        Args:
            coro: The coroutine to run
        """
        asyncio.create_task(coro)
    
    def _show_connect_dialog(self):
        """Show the dialog to connect to a specific peer."""
        host, ok = QInputDialog.getText(self, "Connect to Peer", "Enter the peer's host address:")
        if not ok or not host:
            return
            
        port, ok = QInputDialog.getInt(self, "Connect to Peer", "Enter the peer's port:", 8000, 1, 65535)
        if not ok:
            return
            
        # Connect to the peer
        self.status_bar.showMessage(f"Connecting to {host}:{port}...", 3000)
        self.async_task.emit(self._connect_to_peer(host, port))
    
    def _show_send_file_dialog(self):
        """Show the dialog to send a file to a peer."""
        if not hasattr(self, 'messaging') or not self.messaging.current_peer:
            QMessageBox.warning(self, "Error", "Please select a peer first.")
            return
        
        # Show file dialog
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Send", str(Path.home())
        )
        
        if file_path:
            # Send the file asynchronously
            self.async_task.emit(
                self.secure_messaging.send_file(self.messaging.current_peer, file_path)
            )
    
    def _show_crypto_settings(self):
        """Show the cryptography settings dialog."""
        dialog = SettingsDialog(self.secure_messaging, self)
        dialog.exec_()
    
    def _show_security_metrics(self):
        """Show the security metrics dialog."""
        dialog = SecurityMetricsDialog(self.secure_messaging, self.secure_logger, self)
        dialog.exec_()
    
    def _show_logs(self):
        """Show the logs view."""
        dialog = LogViewerDialog(self.secure_logger, self)
        dialog.exec_()
    
    def _show_about_dialog(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About Quantum Resistant P2P",
            "<h2>Quantum Resistant P2P</h2>"
            "<p>A secure peer-to-peer application using post-quantum cryptography.</p>"
            "<p>Version: 0.2.0</p>"
            "<p>© 2025 DivinityQQ</p>"
        )
    
    def closeEvent(self, event):
        """Handle the window close event.

        Args:
            event: The close event
        """
        # If we have a messaging widget, make sure to clean it up
        if hasattr(self, 'messaging') and self.messaging:
            # This will trigger the destroyed signal and _cleanup_resources
            self.messaging.deleteLater()

        # Stop the network components asynchronously
        asyncio.create_task(self._async_stop_network())
        event.accept()
    
    async def _async_stop_network(self):
        """Asynchronously stop the network components."""
        try:
            # Stop node discovery
            if self.node_discovery:
                await self.node_discovery.stop()
            
            # Stop P2P node
            if self.node:
                await self.node.stop()
            
            logger.info("Network components stopped")
            
        except Exception as e:
            logger.error(f"Error stopping network: {e}")
