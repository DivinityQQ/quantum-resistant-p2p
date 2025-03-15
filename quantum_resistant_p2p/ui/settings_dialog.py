"""
Dialog for application and cryptography settings.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QPushButton, QGroupBox, QFormLayout, QDialogButtonBox, QSpinBox,
    QMessageBox, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt

from ..app import SecureMessaging
from ..crypto import (
    KyberKeyExchange, NTRUKeyExchange,
    AES256GCM, ChaCha20Poly1305,
    DilithiumSignature, SPHINCSSignature,
    LIBOQS_AVAILABLE, LIBOQS_VERSION
)

logger = logging.getLogger(__name__)


class SettingsDialog(QDialog):
    """Dialog for configuring application settings."""
    
    def __init__(self, secure_messaging: SecureMessaging, parent=None):
        """Initialize the settings dialog.
        
        Args:
            secure_messaging: The secure messaging service
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.secure_messaging = secure_messaging
        
        self.setWindowTitle("Cryptography Settings")
        self.setMinimumWidth(550)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()

        # Add OQS status indicator
        if LIBOQS_AVAILABLE:
            oqs_label = QLabel(f"OQS Library: Available (version {LIBOQS_VERSION})")
            oqs_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            oqs_label = QLabel("OQS Library: Not Available (using mock implementations)")
            oqs_label.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(oqs_label)
        
        # Peer synchronization group
        sync_group = QGroupBox("Peer Settings Synchronization")
        sync_layout = QVBoxLayout()
        
        # Description
        sync_description = QLabel(
            "You can adopt the cryptography settings of a connected peer to ensure compatibility.\n"
            "This will automatically restart key exchanges with all connected peers."
        )
        sync_description.setWordWrap(True)
        sync_layout.addWidget(sync_description)
        
        # Peer list
        self.peer_list = QListWidget()
        self.peer_list.setMaximumHeight(120)
        sync_layout.addWidget(self.peer_list)
        
        # Populate peer list
        connected_peers = self.secure_messaging.node.get_peers()
        for peer_id in connected_peers:
            item = QListWidgetItem(f"{peer_id[:8]}... ({peer_id})")
            item.setData(Qt.UserRole, peer_id)
            settings = self.secure_messaging.get_peer_crypto_settings(peer_id)
            if settings:
                key_exchange = settings.get("key_exchange", "Unknown")
                symmetric = settings.get("symmetric", "Unknown")
                signature = settings.get("signature", "Unknown")
                item.setToolTip(
                    f"Key Exchange: {key_exchange}\n"
                    f"Symmetric: {symmetric}\n"
                    f"Signature: {signature}"
                )
            else:
                item.setToolTip("Settings unknown")
            self.peer_list.addItem(item)
        
        # Sync button
        self.sync_button = QPushButton("Adopt Selected Peer's Settings")
        self.sync_button.setEnabled(False)
        self.sync_button.clicked.connect(self._on_sync_clicked)
        sync_layout.addWidget(self.sync_button)
        
        # Connect peer list selection
        self.peer_list.itemSelectionChanged.connect(self._on_peer_selection_changed)
        
        sync_group.setLayout(sync_layout)
        layout.addWidget(sync_group)
        
        # Local cryptography settings
        crypto_group = QGroupBox("Local Cryptography Settings")
        crypto_layout = QFormLayout()
        
        # Key exchange algorithm
        self.key_exchange_combo = QComboBox()
        self.key_exchange_combo.addItem("CRYSTALS-Kyber (Level 1)", 1)
        self.key_exchange_combo.addItem("CRYSTALS-Kyber (Level 3)", 3)
        self.key_exchange_combo.addItem("CRYSTALS-Kyber (Level 5)", 5)
        self.key_exchange_combo.addItem("NTRU (Level 1)", 1)
        self.key_exchange_combo.addItem("NTRU (Level 3)", 3)
        self.key_exchange_combo.addItem("NTRU (Level 5)", 5)
        
        # Set current key exchange algorithm
        current_algo = self.secure_messaging.key_exchange
        if isinstance(current_algo, KyberKeyExchange):
            index = 0 + (current_algo.security_level // 2)  # Map 1,3,5 to 0,1,2
            self.key_exchange_combo.setCurrentIndex(index)
        elif isinstance(current_algo, NTRUKeyExchange):
            index = 3 + (current_algo.security_level // 2)  # Map 1,3,5 to 3,4,5
            self.key_exchange_combo.setCurrentIndex(index)
        
        crypto_layout.addRow("Key Exchange:", self.key_exchange_combo)
        
        # Symmetric algorithm
        self.symmetric_combo = QComboBox()
        self.symmetric_combo.addItem("AES-256-GCM")
        self.symmetric_combo.addItem("ChaCha20-Poly1305")
        
        # Set current symmetric algorithm
        current_algo = self.secure_messaging.symmetric
        if isinstance(current_algo, AES256GCM):
            self.symmetric_combo.setCurrentIndex(0)
        elif isinstance(current_algo, ChaCha20Poly1305):
            self.symmetric_combo.setCurrentIndex(1)
        
        crypto_layout.addRow("Symmetric Encryption:", self.symmetric_combo)
        
        # Signature algorithm
        self.signature_combo = QComboBox()
        self.signature_combo.addItem("CRYSTALS-Dilithium (Level 2)", 2)
        self.signature_combo.addItem("CRYSTALS-Dilithium (Level 3)", 3)
        self.signature_combo.addItem("CRYSTALS-Dilithium (Level 5)", 5)
        self.signature_combo.addItem("SPHINCS+ (Level 1)", 1)
        self.signature_combo.addItem("SPHINCS+ (Level 3)", 3)
        self.signature_combo.addItem("SPHINCS+ (Level 5)", 5)
        
        # Set current signature algorithm
        current_algo = self.secure_messaging.signature
        if isinstance(current_algo, DilithiumSignature):
            index = 0 + ((current_algo.security_level - 2) // 1)  # Map 2,3,5 to 0,1,2
            self.signature_combo.setCurrentIndex(index)
        elif isinstance(current_algo, SPHINCSSignature):
            index = 3 + (current_algo.security_level // 2)  # Map 1,3,5 to 3,4,5
            self.signature_combo.setCurrentIndex(index)
        
        crypto_layout.addRow("Digital Signature:", self.signature_combo)
        
        crypto_group.setLayout(crypto_layout)
        layout.addWidget(crypto_group)
        
        # Warning message
        warning_label = QLabel("Warning: Changing cryptography settings will require re-establishing connections with peers.")
        warning_label.setStyleSheet("color: red;")
        warning_label.setWordWrap(True)
        layout.addWidget(warning_label)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        
        logger.debug("Settings dialog initialized")
    
    def _on_peer_selection_changed(self):
        """Handle peer selection change in the list."""
        self.sync_button.setEnabled(len(self.peer_list.selectedItems()) > 0)
    
    def _on_sync_clicked(self):
        """Handle sync button click."""
        selected_items = self.peer_list.selectedItems()
        if not selected_items:
            return
            
        peer_id = selected_items[0].data(Qt.UserRole)
        
        # Confirm adoption
        reply = QMessageBox.question(
            self,
            "Adopt Peer Settings",
            f"Do you want to adopt the cryptography settings of peer {peer_id[:8]}...?\n\n"
            "This will restart key exchanges with all connected peers.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Adopt the peer's settings
            success = self.secure_messaging.adopt_peer_settings(peer_id)
            
            if success:
                # Update the UI to reflect the changes
                current_algo = self.secure_messaging.key_exchange
                if isinstance(current_algo, KyberKeyExchange):
                    index = 0 + (current_algo.security_level // 2)
                    self.key_exchange_combo.setCurrentIndex(index)
                elif isinstance(current_algo, NTRUKeyExchange):
                    index = 3 + (current_algo.security_level // 2)
                    self.key_exchange_combo.setCurrentIndex(index)
                
                current_algo = self.secure_messaging.symmetric
                if isinstance(current_algo, AES256GCM):
                    self.symmetric_combo.setCurrentIndex(0)
                elif isinstance(current_algo, ChaCha20Poly1305):
                    self.symmetric_combo.setCurrentIndex(1)
                
                current_algo = self.secure_messaging.signature
                if isinstance(current_algo, DilithiumSignature):
                    index = 0 + ((current_algo.security_level - 2) // 1)
                    self.signature_combo.setCurrentIndex(index)
                elif isinstance(current_algo, SPHINCSSignature):
                    index = 3 + (current_algo.security_level // 2)
                    self.signature_combo.setCurrentIndex(index)
                
                QMessageBox.information(
                    self,
                    "Settings Adopted",
                    f"Successfully adopted settings from peer {peer_id[:8]}..."
                )
            else:
                QMessageBox.warning(
                    self,
                    "Settings Adoption Failed",
                    f"Failed to adopt settings from peer {peer_id[:8]}..."
                )
    
    def _on_accept(self):
        """Handle accepting the dialog."""
        try:
            # Get selected key exchange algorithm
            key_exchange_idx = self.key_exchange_combo.currentIndex()
            key_exchange_level = self.key_exchange_combo.currentData()
            
            if key_exchange_idx < 3:  # Kyber
                new_key_exchange = KyberKeyExchange(security_level=key_exchange_level)
            else:  # NTRU
                new_key_exchange = NTRUKeyExchange(security_level=key_exchange_level)
            
            # Get selected symmetric algorithm
            symmetric_idx = self.symmetric_combo.currentIndex()
            
            if symmetric_idx == 0:  # AES-256-GCM
                new_symmetric = AES256GCM()
            else:  # ChaCha20-Poly1305
                new_symmetric = ChaCha20Poly1305()
            
            # Get selected signature algorithm
            signature_idx = self.signature_combo.currentIndex()
            signature_level = self.signature_combo.currentData()
            
            if signature_idx < 3:  # Dilithium
                new_signature = DilithiumSignature(security_level=signature_level)
            else:  # SPHINCS+
                new_signature = SPHINCSSignature(security_level=signature_level)
            
            # Check if anything has changed
            settings_changed = (
                new_key_exchange.name != self.secure_messaging.key_exchange.name or
                new_symmetric.name != self.secure_messaging.symmetric.name or
                new_signature.name != self.secure_messaging.signature.name
            )
            
            if settings_changed:
                # Ask for confirmation if settings have changed
                response = QMessageBox.question(
                    self,
                    "Confirm Settings Change",
                    "Changing cryptography settings will require re-establishing connections with peers. Continue?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if response != QMessageBox.Yes:
                    return
                
                # Update the secure messaging service
                self.secure_messaging.set_key_exchange_algorithm(new_key_exchange)
                self.secure_messaging.set_symmetric_algorithm(new_symmetric)
                self.secure_messaging.set_signature_algorithm(new_signature)
                
                # Show notification
                QMessageBox.information(
                    self,
                    "Settings Updated",
                    "Cryptography settings have been updated. New key exchanges will be performed with connected peers."
                )
                
                logger.info("Updated cryptography settings")
            
            # Accept the dialog
            self.accept()
            
        except Exception as e:
            logger.error(f"Error updating settings: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while updating settings: {str(e)}"
            )
            self.reject()