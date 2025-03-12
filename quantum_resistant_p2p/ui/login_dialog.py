"""
Login dialog for unlocking key storage.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal

from ..crypto import KeyStorage

logger = logging.getLogger(__name__)


class LoginDialog(QDialog):
    """Dialog for unlocking the key storage with a password."""
    
    # Signal emitted when login is successful
    login_successful = pyqtSignal()
    
    def __init__(self, key_storage: KeyStorage, parent=None):
        """Initialize the login dialog.
        
        Args:
            key_storage: The key storage to unlock
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.key_storage = key_storage
        
        self.setWindowTitle("Unlock Key Storage")
        self.setMinimumWidth(350)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Information label
        info_label = QLabel(
            "Please enter your password to unlock the key storage.\n"
            "If this is your first time using the application, this\n"
            "password will be used to secure your keys."
        )
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Password input
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Confirm password (for first time use)
        confirm_layout = QHBoxLayout()
        confirm_label = QLabel("Confirm:")
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        confirm_layout.addWidget(confirm_label)
        confirm_layout.addWidget(self.confirm_input)
        layout.addLayout(confirm_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.login_button = QPushButton("Unlock")
        self.login_button.clicked.connect(self.try_unlock)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Set focus to password input
        self.password_input.setFocus()
        
        # Connect enter key in password input to login button
        self.password_input.returnPressed.connect(self.login_button.click)
        self.confirm_input.returnPressed.connect(self.login_button.click)
    
    def try_unlock(self):
        """Try to unlock the key storage with the entered password."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password.")
            return
        
        # Check if passwords match
        if self.confirm_input.isVisible() and password != confirm:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return
        
        # Try to unlock the key storage
        success = self.key_storage.unlock(password)
        
        if success:
            logger.info("Key storage unlocked successfully")
            self.login_successful.emit()
            self.accept()
        else:
            QMessageBox.warning(self, "Error", "Failed to unlock key storage. Incorrect password?")
            self.password_input.clear()
            self.confirm_input.clear()
            self.password_input.setFocus()
