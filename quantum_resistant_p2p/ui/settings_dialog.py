"""
Dialog for application and cryptography settings.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
    QPushButton, QGroupBox, QFormLayout, QDialogButtonBox, QSpinBox
)
from PyQt5.QtCore import Qt

from ..app import SecureMessaging
from ..crypto import (
    KyberKeyExchange, NTRUKeyExchange,
    AES256GCM, ChaCha20Poly1305,
    DilithiumSignature, SPHINCSSignature
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
        
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Cryptography settings
        crypto_group = QGroupBox("Cryptography Settings")
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
        
        # Network settings
        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()
        
        # Node discovery interval
        self.discovery_interval = QSpinBox()
        self.discovery_interval.setRange(5, 600)
        self.discovery_interval.setValue(60)
        self.discovery_interval.setSuffix(" seconds")
        network_layout.addRow("Discovery Interval:", self.discovery_interval)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
        
        logger.debug("Settings dialog initialized")
    
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
            
            # Update the secure messaging service
            self.secure_messaging.set_key_exchange_algorithm(new_key_exchange)
            self.secure_messaging.set_symmetric_algorithm(new_symmetric)
            self.secure_messaging.set_signature_algorithm(new_signature)
            
            logger.info("Updated cryptography settings")
            
            # Accept the dialog
            self.accept()
            
        except Exception as e:
            logger.error(f"Error updating settings: {e}")
            self.reject()
