"""
Dialog for changing the key storage password.
"""

import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
    QPushButton, QMessageBox, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal

from ..crypto import KeyStorage

logger = logging.getLogger(__name__)


class ChangePasswordDialog(QDialog):
    """Dialog for changing the key storage password."""
    
    # Signal emitted when password change is successful
    password_changed = pyqtSignal()
    
    def __init__(self, key_storage: KeyStorage, require_old_password: bool = True, parent=None):
        """Initialize the change password dialog.
        
        Args:
            key_storage: The key storage to change password for
            require_old_password: Whether to require the old password (True for normal changes,
                                 False for when we know the user just entered it)
            parent: The parent widget
        """
        super().__init__(parent)
        
        self.key_storage = key_storage
        self.require_old_password = require_old_password
        
        self.setWindowTitle("Change Password")
        self.setMinimumWidth(400)
        
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Information label
        info_label = QLabel(
            "Please set a new password for your secure key storage.\n"
            "This password protects all your cryptographic keys."
        )
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)
        
        # Form layout for password fields
        form_layout = QFormLayout()
        
        # Old password field (only if required)
        if self.require_old_password:
            self.old_password_input = QLineEdit()
            self.old_password_input.setEchoMode(QLineEdit.Password)
            self.old_password_input.setPlaceholderText("Enter your current password")
            form_layout.addRow("Current Password:", self.old_password_input)
        
        # New password field
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input.setPlaceholderText("Enter a strong password")
        form_layout.addRow("New Password:", self.new_password_input)
        
        # Confirm new password field
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm your new password")
        form_layout.addRow("Confirm Password:", self.confirm_password_input)
        
        layout.addLayout(form_layout)
        
        # Password strength guidelines
        strength_label = QLabel(
            "Strong password tips:\n"
            "• At least 12 characters long\n"
            "• Mix of uppercase, lowercase, numbers, and symbols\n"
            "• Avoid easily guessable information"
        )
        strength_label.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(strength_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.change_button = QPushButton("Change Password")
        self.change_button.clicked.connect(self._on_change_clicked)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.change_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect enter key to change button
        if hasattr(self, 'old_password_input'):
            self.old_password_input.returnPressed.connect(self.change_button.click)
        self.new_password_input.returnPressed.connect(self.change_button.click)
        self.confirm_password_input.returnPressed.connect(self.change_button.click)
        
        # Set focus to the appropriate field
        if hasattr(self, 'old_password_input'):
            self.old_password_input.setFocus()
        else:
            self.new_password_input.setFocus()
    
    def _on_change_clicked(self):
        """Handle clicking the change password button."""
        # Get the passwords
        old_password = self.old_password_input.text() if hasattr(self, 'old_password_input') else ""
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        # Validate inputs
        if self.require_old_password and not old_password:
            QMessageBox.warning(self, "Error", "Please enter your current password.")
            return
        
        if not new_password:
            QMessageBox.warning(self, "Error", "Please enter a new password.")
            return
            
        if new_password != confirm_password:
            QMessageBox.warning(self, "Error", "New passwords do not match.")
            self.new_password_input.clear()
            self.confirm_password_input.clear()
            self.new_password_input.setFocus()
            return
            
        # Check password strength
        if len(new_password) < 8:
            response = QMessageBox.question(
                self,
                "Weak Password",
                "Your password is quite short. Are you sure you want to use it?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if response == QMessageBox.No:
                return
        
        # Change the password
        try:
            if self.require_old_password:
                success = self.key_storage.change_password(old_password, new_password)
            else:
                # For the case where we've just verified the old password (e.g., in login dialog)
                current_master_key = self.key_storage.master_key
                success = self.key_storage.change_password("", new_password)
                
            if success:
                QMessageBox.information(
                    self, "Success", 
                    "Password changed successfully. Please remember your new password."
                )
                logger.info("Password changed successfully")
                self.password_changed.emit()
                self.accept()
            else:
                if self.require_old_password:
                    QMessageBox.warning(
                        self, "Error", 
                        "Failed to change password. Please check your current password."
                    )
                    self.old_password_input.clear()
                    self.old_password_input.setFocus()
                else:
                    QMessageBox.warning(
                        self, "Error", 
                        "Failed to change password due to an internal error."
                    )
                logger.error("Password change failed")
        except Exception as e:
            QMessageBox.critical(
                self, "Error", 
                f"An error occurred while changing the password: {str(e)}"
            )
            logger.error(f"Exception during password change: {e}")