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
    MLKEMKeyExchange, HQCKeyExchange, FrodoKEMKeyExchange, NTRUKeyExchange,
    AES256GCM, ChaCha20Poly1305,
    MLDSASignature, SPHINCSSignature,
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
        
        # ML-KEM (formerly Kyber) options
        self.key_exchange_combo.addItem("ML-KEM (Level 1)", {"class": MLKEMKeyExchange, "level": 1})
        self.key_exchange_combo.addItem("ML-KEM (Level 3)", {"class": MLKEMKeyExchange, "level": 3})
        self.key_exchange_combo.addItem("ML-KEM (Level 5)", {"class": MLKEMKeyExchange, "level": 5})
        
        # HQC options
        self.key_exchange_combo.addItem("HQC (Level 1)", {"class": HQCKeyExchange, "level": 1})
        self.key_exchange_combo.addItem("HQC (Level 3)", {"class": HQCKeyExchange, "level": 3})
        self.key_exchange_combo.addItem("HQC (Level 5)", {"class": HQCKeyExchange, "level": 5})
        
        # FrodoKEM options
        self.key_exchange_combo.addItem("FrodoKEM (Level 1, AES)", 
                                   {"class": FrodoKEMKeyExchange, "level": 1, "use_aes": True})
        self.key_exchange_combo.addItem("FrodoKEM (Level 3, AES)", 
                                   {"class": FrodoKEMKeyExchange, "level": 3, "use_aes": True})
        self.key_exchange_combo.addItem("FrodoKEM (Level 5, AES)", 
                                   {"class": FrodoKEMKeyExchange, "level": 5, "use_aes": True})
        
        # NTRU option (mock-only, for backward compatibility)
        self.key_exchange_combo.addItem("NTRU (Level 3, Mock Only)", {"class": NTRUKeyExchange, "level": 3})
        
        # Set current key exchange algorithm
        current_algo = self.secure_messaging.key_exchange
        current_level = getattr(current_algo, "security_level", 3)
        
        # Find the matching algorithm in the combo box
        for i in range(self.key_exchange_combo.count()):
            item_data = self.key_exchange_combo.itemData(i)
            if (isinstance(current_algo, item_data["class"]) and 
                current_level == item_data["level"]):
                # Also check use_aes for FrodoKEM
                if (isinstance(current_algo, FrodoKEMKeyExchange) and 
                    hasattr(current_algo, "use_aes") and 
                    "use_aes" in item_data):
                    if current_algo.use_aes == item_data["use_aes"]:
                        self.key_exchange_combo.setCurrentIndex(i)
                        break
                else:
                    self.key_exchange_combo.setCurrentIndex(i)
                    break
        
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
        
        # ML-DSA (formerly Dilithium) options
        self.signature_combo.addItem("ML-DSA (Level 2)", {"class": MLDSASignature, "level": 2})
        self.signature_combo.addItem("ML-DSA (Level 3)", {"class": MLDSASignature, "level": 3})
        self.signature_combo.addItem("ML-DSA (Level 5)", {"class": MLDSASignature, "level": 5})
        
        # SPHINCS+ options
        self.signature_combo.addItem("SPHINCS+ (Level 1)", {"class": SPHINCSSignature, "level": 1})
        self.signature_combo.addItem("SPHINCS+ (Level 3)", {"class": SPHINCSSignature, "level": 3})
        self.signature_combo.addItem("SPHINCS+ (Level 5)", {"class": SPHINCSSignature, "level": 5})
        
        # Set current signature algorithm
        current_algo = self.secure_messaging.signature
        current_level = getattr(current_algo, "security_level", 3)
        
        # Find the matching algorithm in the combo box
        for i in range(self.signature_combo.count()):
            item_data = self.signature_combo.itemData(i)
            if (isinstance(current_algo, item_data["class"]) and 
                current_level == item_data["level"]):
                self.signature_combo.setCurrentIndex(i)
                break
        
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
                # After this, current algorithms should have changed
                # We need to update the combo boxes to reflect these changes
                
                # Update Key Exchange ComboBox
                current_algo = self.secure_messaging.key_exchange
                current_level = getattr(current_algo, "security_level", 3)
                
                for i in range(self.key_exchange_combo.count()):
                    item_data = self.key_exchange_combo.itemData(i)
                    if (isinstance(current_algo, item_data["class"]) and 
                        current_level == item_data["level"]):
                        # Also check use_aes for FrodoKEM
                        if (isinstance(current_algo, FrodoKEMKeyExchange) and 
                            hasattr(current_algo, "use_aes") and 
                            "use_aes" in item_data):
                            if current_algo.use_aes == item_data["use_aes"]:
                                self.key_exchange_combo.setCurrentIndex(i)
                                break
                        else:
                            self.key_exchange_combo.setCurrentIndex(i)
                            break
                
                # Update Symmetric ComboBox
                current_algo = self.secure_messaging.symmetric
                if isinstance(current_algo, AES256GCM):
                    self.symmetric_combo.setCurrentIndex(0)
                elif isinstance(current_algo, ChaCha20Poly1305):
                    self.symmetric_combo.setCurrentIndex(1)
                
                # Update Signature ComboBox
                current_algo = self.secure_messaging.signature
                current_level = getattr(current_algo, "security_level", 3)
                
                for i in range(self.signature_combo.count()):
                    item_data = self.signature_combo.itemData(i)
                    if (isinstance(current_algo, item_data["class"]) and 
                        current_level == item_data["level"]):
                        self.signature_combo.setCurrentIndex(i)
                        break
                
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
            key_exchange_data = self.key_exchange_combo.itemData(key_exchange_idx)
            
            # Create new algorithm instance
            cls = key_exchange_data["class"]
            level = key_exchange_data["level"]
            
            if cls == FrodoKEMKeyExchange:
                use_aes = key_exchange_data.get("use_aes", True)
                new_key_exchange = cls(security_level=level, use_aes=use_aes)
            else:
                new_key_exchange = cls(security_level=level)
            
            # Get selected symmetric algorithm
            symmetric_idx = self.symmetric_combo.currentIndex()
            
            if symmetric_idx == 0:  # AES-256-GCM
                new_symmetric = AES256GCM()
            else:  # ChaCha20-Poly1305
                new_symmetric = ChaCha20Poly1305()
            
            # Get selected signature algorithm
            signature_idx = self.signature_combo.currentIndex()
            signature_data = self.signature_combo.itemData(signature_idx)
            
            # Create new algorithm instance
            cls = signature_data["class"]
            level = signature_data["level"]
            new_signature = cls(security_level=level)
            
            # Check if anything has changed
            settings_changed = (
                new_key_exchange.display_name != self.secure_messaging.key_exchange.display_name or
                new_symmetric.name != self.secure_messaging.symmetric.name or
                new_signature.display_name != self.secure_messaging.signature.display_name
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
